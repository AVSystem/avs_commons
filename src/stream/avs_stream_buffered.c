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

#ifdef AVS_COMMONS_WITH_AVS_STREAM

#    include <avsystem/commons/avs_stream_buffered.h>

#    include <assert.h>
#    include <stdint.h>
#    include <string.h>
/*
 * Added for SIZE_MAX definition on Android ARM NDK, which for some reason does
 * not define it in stdint.h like POSIX says it should
 */
#    include <limits.h>

#    include <avsystem/commons/avs_buffer.h>
#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    define MODULE_NAME stream_buffered
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const void *const vtable;
    avs_stream_t *underlying_stream;
    avs_buffer_t *in_buffer;
    avs_buffer_t *out_buffer;
    bool message_finished;
} buffered_stream_t;

static avs_error_t flush_data(buffered_stream_t *stream,
                              size_t *out_bytes_written) {
    if (!(*out_bytes_written = avs_buffer_data_size(stream->out_buffer))) {
        return AVS_OK;
    }

    avs_error_t err = avs_stream_write_some(stream->underlying_stream,
                                            avs_buffer_data(stream->out_buffer),
                                            out_bytes_written);
    if (avs_is_err(err)) {
        return err;
    }

    avs_buffer_consume_bytes(stream->out_buffer, *out_bytes_written);
    return AVS_OK;
}

static avs_error_t fetch_data(buffered_stream_t *stream,
                              size_t *out_bytes_read) {
    char *insert_ptr = avs_buffer_raw_insert_ptr(stream->in_buffer);
    size_t bytes_to_read = avs_buffer_space_left(stream->in_buffer);

    avs_error_t err = avs_stream_read(stream->underlying_stream, out_bytes_read,
                                      &stream->message_finished, insert_ptr,
                                      bytes_to_read);
    if (avs_is_err(err)) {
        return err;
    }

    assert(*out_bytes_read <= avs_buffer_capacity(stream->in_buffer));
    avs_buffer_advance_ptr(stream->in_buffer, *out_bytes_read);
    return AVS_OK;
}

static avs_error_t stream_buffered_write_some(avs_stream_t *stream_,
                                              const void *buffer,
                                              size_t *inout_data_length) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    if (!inout_data_length) {
        return avs_errno(AVS_EINVAL);
    }
    if (*inout_data_length == 0) {
        return AVS_OK;
    }
    if (!buffer) {
        return avs_errno(AVS_EINVAL);
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
            size_t bytes_flushed;
            avs_error_t err = flush_data(stream, &bytes_flushed);
            if (avs_is_err(err)) {
                return err;
            } else if (bytes_flushed == 0) {
                break;
            }
        }
    }

    *inout_data_length = total_written;
    return AVS_OK;
}

static avs_error_t stream_buffered_read(avs_stream_t *stream_,
                                        size_t *out_bytes_read,
                                        bool *out_message_finished,
                                        void *buffer,
                                        size_t buffer_length) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    size_t bytes_read = 0;

    if (buffer_length == 0) {
        goto finish;
    }
    if (!buffer) {
        return avs_errno(AVS_EINVAL);
    }

    if (!stream->in_buffer) {
        avs_error_t err =
                avs_stream_read(stream->underlying_stream, &bytes_read,
                                &stream->message_finished, buffer,
                                buffer_length);
        if (avs_is_err(err)) {
            return err;
        }
        goto finish;
    }

    if (avs_buffer_data_size(stream->in_buffer) == 0) {
        avs_error_t err = fetch_data(stream, &(size_t) { 0 });
        if (avs_is_err(err)) {
            return err;
        }
    }

    bytes_read =
            AVS_MIN(avs_buffer_data_size(stream->in_buffer), buffer_length);
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
    return AVS_OK;
}

static avs_error_t finish_message(buffered_stream_t *stream) {
    assert(stream->out_buffer);
    size_t data_size = avs_buffer_data_size(stream->out_buffer);
    size_t bytes_flushed;
    avs_error_t err = flush_data(stream, &bytes_flushed);
    if (avs_is_ok(err) && bytes_flushed < data_size) {
        return avs_errno(AVS_EMSGSIZE);
    }
    return err;
}

static avs_error_t stream_buffered_finish_message(avs_stream_t *stream_) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    avs_error_t err = AVS_OK;
    if (stream->out_buffer) {
        err = finish_message(stream);
    }

    avs_error_t backend_err =
            avs_stream_finish_message(stream->underlying_stream);

    return avs_is_ok(err) ? backend_err : err;
}

static avs_error_t
stream_buffered_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    if (!stream->in_buffer) {
        return avs_stream_peek(stream->underlying_stream, offset, out_value);
    }

    if (offset < avs_buffer_capacity(stream->in_buffer)) {
        while (offset >= avs_buffer_data_size(stream->in_buffer)) {
            size_t bytes_read;
            avs_error_t err = fetch_data(stream, &bytes_read);
            if (avs_is_err(err)) {
                LOG(ERROR, _("cannot peek - read error"));
                return err;
            } else if (bytes_read == 0) {
                LOG(ERROR, _("cannot peek - 0 bytes read"));
                return stream->message_finished ? AVS_EOF
                                                : avs_errno(AVS_ENOBUFS);
            }
        }
        *out_value = avs_buffer_data(stream->in_buffer)[offset];
        return AVS_OK;
    }

    avs_error_t err =
            avs_stream_peek(stream->underlying_stream,
                            offset - avs_buffer_data_size(stream->in_buffer),
                            out_value);
    if (avs_is_err(err)) {
        LOG(ERROR,
            _("cannot peek - buffer is too small and underlying stream's ")
                    _("peek failed"));
        if (err.category == AVS_ERRNO_CATEGORY && err.code == AVS_ENOTSUP) {
            // underlying stream does not support peeking - map it to ENOBUFS
            return avs_errno(AVS_ENOBUFS);
        }
    }
    return err;
}

static avs_error_t stream_buffered_close(avs_stream_t *stream_) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    avs_error_t err = AVS_OK;
    if (stream->out_buffer) {
        err = finish_message(stream);
        avs_buffer_free(&stream->out_buffer);
    }
    if (stream->in_buffer) {
        avs_buffer_free(&stream->in_buffer);
    }

    avs_error_t backend_err = avs_stream_cleanup(&stream->underlying_stream);

    return avs_is_ok(err) ? backend_err : err;
}

static avs_error_t stream_buffered_reset(avs_stream_t *stream_) {
    buffered_stream_t *stream = (buffered_stream_t *) stream_;
    if (stream->in_buffer) {
        avs_buffer_reset(stream->in_buffer);
    }
    if (stream->out_buffer) {
        avs_buffer_reset(stream->out_buffer);
    }
    return avs_stream_reset(stream->underlying_stream);
}

static const avs_stream_v_table_t buffered_stream_vtable = {
    .write_some = stream_buffered_write_some,
    .finish_message = stream_buffered_finish_message,
    .read = stream_buffered_read,
    .peek = stream_buffered_peek,
    .reset = stream_buffered_reset,
    .close = stream_buffered_close
};

int avs_stream_buffered_create(avs_stream_t **inout_stream,
                               size_t in_buffer_size,
                               size_t out_buffer_size) {
    if (!inout_stream || !*inout_stream) {
        LOG(ERROR, _("No underlying stream provided!"));
        return -1;
    }
    if (!in_buffer_size && !out_buffer_size) {
        LOG(ERROR, _("At least one buffer has to be non-zero sized"));
        return -1;
    }
    if (in_buffer_size > SIZE_MAX / 2 || out_buffer_size > SIZE_MAX / 2) {
        LOG(ERROR, _("Buffer size is too big"));
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
                && avs_buffer_create(&stream->out_buffer, out_buffer_size))) {
        avs_buffer_free(&stream->in_buffer);
        avs_buffer_free(&stream->out_buffer);
        avs_stream_cleanup((avs_stream_t **) &stream);
        return -1;
    }

    const void *vtable = &buffered_stream_vtable;
    memcpy((void *) (intptr_t) &stream->vtable, &vtable, sizeof(void *));
    stream->underlying_stream = *inout_stream;
    *inout_stream = (avs_stream_t *) stream;

    return 0;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/stream/test_stream_buffered.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_STREAM
