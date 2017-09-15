/*
 * Copyright 217 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>

#include <avsystem/commons/stream/net.h>

#include "../body_receivers.h"
#include "../log.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const avs_stream_v_table_t * const vtable;
    avs_stream_abstract_t *backend;
    const avs_http_buffer_sizes_t *buffer_sizes;
    size_t chunk_left;
    bool finished;
} chunked_receiver_t;

typedef int (*read_chunk_size_getline_func_t)(void *state,
                                              char *buffer,
                                              size_t buffer_length);

static int read_chunk_size(const avs_http_buffer_sizes_t *buffer_sizes,
                           read_chunk_size_getline_func_t getline_func,
                           void *getline_func_state, size_t *out_value) {
    char line_buf[buffer_sizes->header_line];
    unsigned long value = 0;
    int result;
    LOG(TRACE, "read_chunk_size");
    while (1) {
        char *endptr = NULL;
        result = getline_func(getline_func_state, line_buf, sizeof(line_buf));
        if (result) { /* this also handles buffer too small problem */
            LOG(ERROR, "error reading chunk headline");
            break;
        }
        LOG(TRACE, "chunk headline: %s", line_buf);
        if (!line_buf[0]) { /* empty string */
            continue;
        }
        errno = 0;
        value = strtoul(line_buf, &endptr, 16);
        if (errno) {
            result = errno;
            LOG(ERROR, "invalid chunk headline");
            break;
        }
        if (*endptr == '\0' || *endptr == ';') { /* entire line read */
            break;
        }
    }
    *out_value = (size_t) value;
    if (result == 0 && *out_value == 0) {
        /* zero length chunk got, ignore the possible trailers and empty line */
        while (1) {
            result = getline_func(getline_func_state,
                                  line_buf, sizeof(line_buf));
            if (result || !line_buf[0]) {
                break;
            }
            LOG(TRACE, "ignoring trailer: %s", line_buf);
        }
    }
    LOG(TRACE, "result == %d", result);
    return result;
}

static int read_chunk_size_getline_reader(void *state,
                                          char *buffer, size_t buffer_length) {
    return avs_stream_getline((avs_stream_abstract_t *) state, NULL, NULL,
                              buffer, buffer_length);
}

static int chunked_read(avs_stream_abstract_t *stream_,
                        size_t *out_bytes_read,
                        char *out_message_finished,
                        void *buffer,
                        size_t buffer_length) {
    chunked_receiver_t *stream = (chunked_receiver_t *) stream_;
    size_t bytes_read = 0;
    char backend_message_finished;
    int result = 0;
    if (!out_bytes_read) {
        out_bytes_read = &bytes_read;
    }
    if (stream->chunk_left == 0) {
        *out_bytes_read = 0;
        if (!stream->finished
                && !(result = read_chunk_size(stream->buffer_sizes,
                                              read_chunk_size_getline_reader,
                                              stream->backend,
                                              &stream->chunk_left))
                && stream->chunk_left == 0) {
            stream->finished = true;
        }
        if (out_message_finished) {
            *out_message_finished = stream->finished;
        }
        if (result || stream->finished
                || avs_stream_nonblock_read_ready(stream->backend) <= 0) {
            goto finish;
        }
    }
    result = avs_stream_read(stream->backend, out_bytes_read,
                             &backend_message_finished, buffer,
                             AVS_MIN(buffer_length, stream->chunk_left));
    stream->chunk_left -= *out_bytes_read;
    if (!result && backend_message_finished) {
        LOG(ERROR, "unexpected end of stream");
        result = -1;
    }
    if (out_message_finished) {
        // Note that this means that the final read will always be zero-length
        *out_message_finished = 0;
    }
finish:
    if (result) {
        LOG(ERROR, "chunked_read: result == %d", result);
    }
    return result;
}

static int chunked_nonblock_read_ready(avs_stream_abstract_t *stream_) {
    chunked_receiver_t *stream = (chunked_receiver_t *) stream_;
    // This is somewhat inaccurate. If there is a packet boundary somewhere
    // *within* the chunk header, then the next read operation might indeed
    // block. But I don't think there's a good solution to this problem that
    // would not be overkill.
    return avs_stream_nonblock_read_ready(stream->backend);
}

typedef struct {
    avs_stream_abstract_t *stream;
    size_t offset;
} read_chunk_size_getline_peeker_state_t;

static int read_chunk_size_getline_peeker(void *state_,
                                          char *buffer, size_t buffer_length) {
    read_chunk_size_getline_peeker_state_t *state =
            (read_chunk_size_getline_peeker_state_t *) state_;
    return avs_stream_peekline(state->stream, state->offset, NULL,
                               &state->offset, buffer, buffer_length);
}

static int chunked_peek(avs_stream_abstract_t *stream_, size_t offset) {
    chunked_receiver_t *stream =
            (chunked_receiver_t *) stream_;
    if (stream->finished) {
        return EOF;
    }
    read_chunk_size_getline_peeker_state_t state;
    size_t chunk_left = stream->chunk_left;
    int result;
    state.stream = stream->backend;
    state.offset = 0;
    while (offset >= chunk_left) {
        offset -= chunk_left;
        state.offset += chunk_left;
        result = read_chunk_size(stream->buffer_sizes,
                                 read_chunk_size_getline_peeker, &state,
                                 &chunk_left);
        if (result || chunk_left == 0) {
            return EOF;
        }
    }
    offset += state.offset;
    result = avs_stream_peek(stream->backend, offset);
    if (result == EOF) {
        LOG(DEBUG, "chunked_peek: EOF");
    }
    return result;
}

static int chunked_close(avs_stream_abstract_t *stream_) {
    chunked_receiver_t *stream = (chunked_receiver_t *) stream_;
    avs_stream_net_setsock(stream->backend, NULL); /* don't close the socket */
    avs_stream_cleanup(&stream->backend);
    return 0;
}

static int chunked_errno(avs_stream_abstract_t *stream) {
    return avs_stream_errno(((chunked_receiver_t *) stream)->backend);
}

static int unimplemented() {
    LOG(ERROR, "Vtable method unimplemented");
    return -1;
}

static const avs_stream_v_table_t chunked_receiver_vtable = {
    (avs_stream_write_some_t) unimplemented,
    (avs_stream_finish_message_t) unimplemented,
    chunked_read,
    chunked_peek,
    (avs_stream_reset_t) unimplemented,
    chunked_close,
    chunked_errno,
    &(avs_stream_v_table_extension_t[]) {
        {
            AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
            &(avs_stream_v_table_extension_nonblock_t[]) {
                {
                    chunked_nonblock_read_ready,
                    (avs_stream_nonblock_write_ready_t) unimplemented
                }
            }[0]
        },
        AVS_STREAM_V_TABLE_EXTENSION_NULL
    }[0]
};

avs_stream_abstract_t *_avs_http_body_receiver_chunked_create(
        avs_stream_abstract_t *backend,
        const avs_http_buffer_sizes_t *buffer_sizes) {
    chunked_receiver_t *retval =
            (chunked_receiver_t *) calloc(1, sizeof(*retval));
    LOG(TRACE, "create_content_length_receiver");
    if (retval) {
        *(const avs_stream_v_table_t **) (intptr_t) &retval->vtable =
                &chunked_receiver_vtable;
        retval->backend = backend;
        retval->buffer_sizes = buffer_sizes;
    }
    return (avs_stream_abstract_t *) retval;
}
