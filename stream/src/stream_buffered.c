/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_config.h>

#include <avsystem/commons/stream/stream_buffered.h>

#include <assert.h>
#include <string.h>
#include <stdint.h>

#include <avsystem/commons/buffer.h>
#include <avsystem/commons/errno.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/stream_v_table.h>

#define MODULE_NAME stream_buffered
#include <x_log_config.h>

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const void *const vtable;
    avs_stream_abstract_t *underlying_stream;
    avs_buffer_t *in_buffer;
    avs_buffer_t *out_buffer;
    char message_finished;
    int errno_;
} buffered_stream_t;

static ssize_t flush_data(buffered_stream_t *stream) {
    stream->errno_ = 0;

    size_t bytes_to_write = avs_buffer_data_size(stream->out_buffer);
    if (!bytes_to_write) {
        return 0;
    }

    int retval = avs_stream_write_some(stream->underlying_stream,
                                       avs_buffer_data(stream->out_buffer),
                                       &bytes_to_write);
    if (retval) {
        return (ssize_t) retval;
    }

    avs_buffer_consume_bytes(stream->out_buffer, bytes_to_write);
    return (ssize_t) bytes_to_write;
}

static ssize_t fetch_data(buffered_stream_t *stream) {
    stream->errno_ = 0;

    char *insert_ptr = avs_buffer_raw_insert_ptr(stream->in_buffer);
    size_t bytes_to_read = avs_buffer_space_left(stream->in_buffer);
    size_t bytes_read = 0;

    int retval = avs_stream_read(stream->underlying_stream, &bytes_read,
                                 &stream->message_finished, insert_ptr,
                                 bytes_to_read);
    if (retval) {
        return (ssize_t) retval;
    }

    assert(bytes_read <= avs_buffer_capacity(stream->in_buffer));
    avs_buffer_advance_ptr(stream->in_buffer, bytes_read);
    return (ssize_t) bytes_read;
}

static int stream_buffered_write_some(avs_stream_abstract_t *stream_,
                                      const void *buffer,
                                      size_t *inout_data_length) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    stream->errno_ = 0;

    if (!inout_data_length) {
        stream->errno_ = EINVAL;
        return -1;
    }
    if (*inout_data_length == 0) {
        return 0;
    }
    if (!buffer) {
        stream->errno_ = EINVAL;
        return -1;
    }
    if (!stream->out_buffer) {
        return avs_stream_write_some(stream->underlying_stream, buffer,
                                     inout_data_length);
    }

    size_t total_written = 0;
    while (total_written < *inout_data_length) {
        size_t bytes_to_write =
                AVS_MIN(avs_buffer_space_left(stream->out_buffer),
                        *inout_data_length - total_written);
        avs_buffer_append_bytes(stream->out_buffer,
                                (const uint8_t *) buffer + total_written,
                                bytes_to_write);
        total_written += bytes_to_write;
        if (avs_buffer_space_left(stream->out_buffer) == 0) {
            ssize_t bytes_flushed = flush_data(stream);
            if (bytes_flushed < 0) {
                return -1;
            } else if (bytes_flushed == 0) {
                break;
            }
        }
    }

    *inout_data_length = total_written;
    return 0;
}

static int stream_buffered_read(avs_stream_abstract_t *stream_,
                                size_t *out_bytes_read,
                                char *out_message_finished,
                                void *buffer,
                                size_t buffer_length) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    stream->errno_ = 0;

    size_t bytes_read = 0;
    int retval = 0;

    if (buffer_length == 0) {
        goto finish;
    }
    if (!buffer) {
        stream->errno_ = EINVAL;
        return -1;
    }

    if (!stream->in_buffer) {
        if ((retval = avs_stream_read(stream->underlying_stream, &bytes_read,
                                      &stream->message_finished, buffer,
                                      buffer_length))) {
            return retval;
        }
        goto finish;
    }

    if (avs_buffer_data_size(stream->in_buffer) == 0) {
        retval = (int) fetch_data(stream);
        if (retval < 0) {
            return retval;
        }
    }

    bytes_read = AVS_MIN(avs_buffer_data_size(stream->in_buffer),
                         buffer_length);
    if (bytes_read) {
        memcpy(buffer, avs_buffer_data(stream->in_buffer), bytes_read);
        avs_buffer_consume_bytes(stream->in_buffer, bytes_read);
    }

finish:
    if (out_bytes_read) {
        *out_bytes_read = bytes_read;
    }
    if (out_message_finished) {
        *out_message_finished = stream->message_finished;
    }
    return 0;
}

static int finish_message(buffered_stream_t *stream) {
    assert(stream->out_buffer);
    ssize_t data_size = (ssize_t) avs_buffer_data_size(stream->out_buffer);
    return (flush_data(stream) < data_size) ? -1 : 0;
}

static int stream_buffered_finish_message(avs_stream_abstract_t *stream_) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    stream->errno_ = 0;
    int retval = 0;
    if (stream->out_buffer) {
        retval = finish_message(stream);
    }

    int backend_retval = avs_stream_finish_message(stream->underlying_stream);

    return retval ? retval : backend_retval;
}

static int stream_buffered_peek(avs_stream_abstract_t *stream_, size_t offset) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    stream->errno_ = 0;
    if (!stream->in_buffer) {
        return avs_stream_peek(stream->underlying_stream, offset);
    }

    if (offset < avs_buffer_capacity(stream->in_buffer)) {
        while (offset >= avs_buffer_data_size(stream->in_buffer)) {
            ssize_t bytes_read = fetch_data(stream);
            if (bytes_read < 0) {
                LOG(ERROR, "cannot peek - read error");
                return EOF;
            } else if (bytes_read == 0) {
                LOG(ERROR, "cannot peek - 0 bytes read");
                return EOF;
            }
        }
        return (unsigned char) avs_buffer_data(stream->in_buffer)[offset];
    }

    int retval =
            avs_stream_peek(stream->underlying_stream,
                            offset - avs_buffer_data_size(stream->in_buffer));
    if (retval < 0) {
        LOG(ERROR, "cannot peek - buffer is too small and underlying stream's "
                   "peek failed");
        if (!avs_stream_errno(stream->underlying_stream)) {
            stream->errno_ = EINVAL;
        }
    }
    return retval;
}

static int stream_buffered_close(avs_stream_abstract_t *stream_) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    int retval = 0;
    if (stream->out_buffer) {
        retval = finish_message(stream);
        avs_buffer_free(&stream->out_buffer);
    }
    if (stream->in_buffer) {
        avs_buffer_free(&stream->in_buffer);
    }

    int backend_retval = avs_stream_cleanup(&stream->underlying_stream);

    return retval ? retval : backend_retval;
}

static int stream_buffered_reset(avs_stream_abstract_t *stream_) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    stream->errno_ = 0;
    if (stream->in_buffer) {
        avs_buffer_reset(stream->in_buffer);
    }
    if (stream->out_buffer) {
        avs_buffer_reset(stream->out_buffer);
    }
    return avs_stream_reset(stream->underlying_stream);
}

static int stream_buffered_errno(avs_stream_abstract_t *stream_) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    if (stream->errno_) {
        return stream->errno_;
    }
    return avs_stream_errno(stream->underlying_stream);
}

static const avs_stream_v_table_t buffered_stream_vtable = {
    .write_some = stream_buffered_write_some,
    .finish_message = stream_buffered_finish_message,
    .read = stream_buffered_read,
    .peek = stream_buffered_peek,
    .reset = stream_buffered_reset,
    .close = stream_buffered_close,
    .get_errno = stream_buffered_errno
};

int avs_stream_buffered_create(avs_stream_abstract_t **inout_stream,
                               size_t in_buffer_size,
                               size_t out_buffer_size) {
    if (!inout_stream || !*inout_stream) {
        LOG(ERROR, "No underlying stream provided!");
        return -1;
    }
    if (!in_buffer_size && !out_buffer_size) {
        LOG(ERROR, "At least one buffer has to be non-zero sized");
        return -1;
    }
    if (in_buffer_size > SIZE_MAX / 2 || out_buffer_size > SIZE_MAX / 2) {
        LOG(ERROR, "Buffer size is too big");
        return -1;
    }

    buffered_stream_t *stream =
            (buffered_stream_t *) avs_calloc(1, sizeof(buffered_stream_t));
    if (!stream) {
        return -1;
    }

    if ((in_buffer_size > 0
                    && avs_buffer_create(&stream->in_buffer, in_buffer_size))
            || (out_buffer_size > 0
                    && avs_buffer_create(&stream->out_buffer,
                                         out_buffer_size))) {
        avs_buffer_free(&stream->in_buffer);
        avs_buffer_free(&stream->out_buffer);
        avs_stream_cleanup((avs_stream_abstract_t **) &stream);
        return -1;
    }

    const void *vtable = &buffered_stream_vtable;
    memcpy((void *) (intptr_t) &stream->vtable, &vtable, sizeof(void *));
    stream->underlying_stream = *inout_stream;
    *inout_stream = (avs_stream_abstract_t *) stream;

    return 0;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_stream_buffered.c"
#endif
