/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_HTTP

#    include <errno.h>

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_errno_map.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_net.h>

#    include "../avs_body_receivers.h"

#    include "../avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const avs_stream_v_table_t *const vtable;
    avs_stream_t *backend;
    const avs_http_buffer_sizes_t *buffer_sizes;
    size_t chunk_left;
    bool finished;
} chunked_receiver_t;

typedef avs_error_t (*read_chunk_size_getline_func_t)(void *state,
                                                      char *buffer,
                                                      size_t buffer_length);

static avs_error_t read_chunk_size(const avs_http_buffer_sizes_t *buffer_sizes,
                                   read_chunk_size_getline_func_t getline_func,
                                   void *getline_func_state,
                                   size_t *out_value) {
    char *line_buf = (char *) avs_malloc(buffer_sizes->header_line);
    if (!line_buf) {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }
    unsigned long value = 0;
    avs_error_t err;
    LOG(TRACE, _("read_chunk_size"));
    while (true) {
        char *endptr = NULL;
        err = getline_func(getline_func_state, line_buf,
                           buffer_sizes->header_line);
        if (avs_is_err(err)) {
            if (avs_is_eof(err)) {
                LOG(ERROR, _("unexpected end of stream"));
                err = avs_errno(AVS_EPROTO);
            } else {
                LOG(ERROR, _("error reading chunk headline"));
            }
            break;
        }
        LOG(TRACE, _("chunk headline: ") "%s", line_buf);
        if (!line_buf[0]) { /* empty string */
            continue;
        }
        errno = 0;
        value = strtoul(line_buf, &endptr, 16);
        if (errno) {
            err = avs_errno(avs_map_errno(errno));
            LOG(ERROR, _("invalid chunk headline"));
            break;
        }
        if (*endptr == '\0' || *endptr == ';') { /* entire line read */
            break;
        }
    }
    *out_value = (size_t) value;
    if (avs_is_ok(err) && *out_value == 0) {
        /* got zero-length chunk, ignore the possible trailers and empty line */
        while (true) {
            err = getline_func(getline_func_state, line_buf,
                               buffer_sizes->header_line);
            if (avs_is_err(err) || !line_buf[0]) {
                break;
            }
            LOG(TRACE, _("ignoring trailer: ") "%s", line_buf);
        }
    }
    avs_free(line_buf);
    return err;
}

static avs_error_t read_chunk_size_getline_reader(void *state,
                                                  char *buffer,
                                                  size_t buffer_length) {
    return avs_stream_getline((avs_stream_t *) state, NULL, NULL, buffer,
                              buffer_length);
}

static avs_error_t chunked_read(avs_stream_t *stream_,
                                size_t *out_bytes_read,
                                bool *out_message_finished,
                                void *buffer,
                                size_t buffer_length) {
    chunked_receiver_t *stream = (chunked_receiver_t *) stream_;
    size_t bytes_read = 0;
    bool backend_message_finished;
    avs_error_t err = AVS_OK;
    if (!out_bytes_read) {
        out_bytes_read = &bytes_read;
    }
    if (stream->chunk_left == 0) {
        *out_bytes_read = 0;
        if (!stream->finished
                && avs_is_ok((
                           err = read_chunk_size(stream->buffer_sizes,
                                                 read_chunk_size_getline_reader,
                                                 stream->backend,
                                                 &stream->chunk_left)))
                && stream->chunk_left == 0) {
            stream->finished = true;
        }
        if (out_message_finished) {
            *out_message_finished = stream->finished;
        }
        if (avs_is_err(err) || stream->finished
                || avs_stream_nonblock_read_ready(stream->backend) <= 0) {
            return err;
        }
    }
    err = avs_stream_read(stream->backend, out_bytes_read,
                          &backend_message_finished, buffer,
                          AVS_MIN(buffer_length, stream->chunk_left));
    stream->chunk_left -= *out_bytes_read;
    if (avs_is_ok(err) && backend_message_finished) {
        LOG(ERROR, _("unexpected end of stream"));
        return avs_errno(AVS_EIO);
    }
    if (out_message_finished) {
        // Note that this means that the final read will always be zero-length
        *out_message_finished = 0;
    }
    return AVS_OK;
}

static bool chunked_nonblock_read_ready(avs_stream_t *stream) {
    // This is somewhat inaccurate. If there is a packet boundary somewhere
    // *within* the chunk header, then the next read operation might indeed
    // block. But I don't think there's a good solution to this problem that
    // would not be overkill.
    return avs_stream_nonblock_read_ready(
            ((chunked_receiver_t *) stream)->backend);
}

typedef struct {
    avs_stream_t *stream;
    size_t offset;
} read_chunk_size_getline_peeker_state_t;

static avs_error_t read_chunk_size_getline_peeker(void *state_,
                                                  char *buffer,
                                                  size_t buffer_length) {
    read_chunk_size_getline_peeker_state_t *state =
            (read_chunk_size_getline_peeker_state_t *) state_;
    return avs_stream_peekline(state->stream, state->offset, NULL,
                               &state->offset, buffer, buffer_length);
}

static avs_error_t
chunked_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    chunked_receiver_t *stream = (chunked_receiver_t *) stream_;
    if (stream->finished) {
        return AVS_EOF;
    }
    read_chunk_size_getline_peeker_state_t state;
    size_t chunk_left = stream->chunk_left;
    avs_error_t err;
    state.stream = stream->backend;
    state.offset = 0;
    while (offset >= chunk_left) {
        offset -= chunk_left;
        state.offset += chunk_left;
        err = read_chunk_size(stream->buffer_sizes,
                              read_chunk_size_getline_peeker, &state,
                              &chunk_left);
        if (avs_is_err(err)) {
            return err;
        } else if (chunk_left == 0) {
            return AVS_EOF;
        }
    }
    offset += state.offset;
    return avs_stream_peek(stream->backend, offset, out_value);
}

static avs_error_t chunked_close(avs_stream_t *stream_) {
    chunked_receiver_t *stream = (chunked_receiver_t *) stream_;
    avs_stream_net_setsock(stream->backend, NULL); /* don't close the socket */
    return avs_stream_cleanup(&stream->backend);
}

static const avs_stream_v_table_t chunked_receiver_vtable = {
    .read = chunked_read,
    .peek = chunked_peek,
    .close = chunked_close,
    &(avs_stream_v_table_extension_t[]){
            { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
              &(avs_stream_v_table_extension_nonblock_t[])
                      {
                          {
                              .read_ready = chunked_nonblock_read_ready
                          }
                      }[0] },
            AVS_STREAM_V_TABLE_EXTENSION_NULL }[0]
};

avs_stream_t *_avs_http_body_receiver_chunked_create(
        avs_stream_t *backend, const avs_http_buffer_sizes_t *buffer_sizes) {
    chunked_receiver_t *retval =
            (chunked_receiver_t *) avs_calloc(1, sizeof(*retval));
    LOG(TRACE, _("create_content_length_receiver"));
    if (retval) {
        *(const avs_stream_v_table_t **) (intptr_t) &retval->vtable =
                &chunked_receiver_vtable;
        retval->backend = backend;
        retval->buffer_sizes = buffer_sizes;
    }
    return (avs_stream_t *) retval;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
