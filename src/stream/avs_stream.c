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

#    include <assert.h>
#    include <stdarg.h>
#    include <stdbool.h>
#    include <stdlib.h>
#    include <string.h>

#    include <limits.h>

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    define MODULE_NAME avs_stream
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#    define AVS_STREAM_STACK_BUFFER_SIZE 512

struct avs_stream_struct {
    const avs_stream_v_table_t *const vtable;
};

avs_error_t avs_stream_write_some(avs_stream_t *stream,
                                  const void *buffer,
                                  size_t *inout_data_length) {
    if (!stream->vtable->write_some) {
        return avs_errno(AVS_ENOTSUP);
    }
    return stream->vtable->write_some(stream, buffer, inout_data_length);
}

avs_error_t avs_stream_write(avs_stream_t *stream,
                             const void *buffer,
                             size_t buffer_length) {
    size_t data_length = buffer_length;
    avs_error_t err = avs_stream_write_some(stream, buffer, &data_length);
    if (avs_is_ok(err) && data_length != buffer_length) {
        return avs_errno(AVS_EMSGSIZE);
    }
    return err;
}

avs_error_t avs_stream_finish_message(avs_stream_t *stream) {
    if (!stream->vtable->finish_message) {
        return avs_errno(AVS_ENOTSUP);
    }
    return stream->vtable->finish_message(stream);
}

avs_error_t avs_stream_read(avs_stream_t *stream,
                            size_t *out_bytes_read,
                            bool *out_message_finished,
                            void *buffer,
                            size_t buffer_length) {
    if (!stream->vtable->read) {
        return avs_errno(AVS_ENOTSUP);
    }
    return stream->vtable->read(stream, out_bytes_read, out_message_finished,
                                buffer, buffer_length);
}

avs_error_t
avs_stream_peek(avs_stream_t *stream, size_t offset, char *out_value) {
    if (!stream->vtable->peek) {
        return avs_errno(AVS_ENOTSUP);
    }
    return stream->vtable->peek(stream, offset, out_value);
}

avs_error_t avs_stream_reset(avs_stream_t *stream) {
    if (!stream->vtable->reset) {
        return avs_errno(AVS_ENOTSUP);
    }
    return stream->vtable->reset(stream);
}

avs_error_t avs_stream_cleanup(avs_stream_t **stream) {
    avs_error_t err = AVS_OK;
    if (*stream) {
        if ((*stream)->vtable->close) {
            err = (*stream)->vtable->close(*stream);
        }
        avs_free(*stream);
        *stream = NULL;
    }
    return err;
}

avs_error_t avs_stream_write_f(avs_stream_t *stream, const char *msg, ...) {
    avs_error_t err;
    va_list args;
    va_start(args, msg);
    err = avs_stream_write_fv(stream, msg, args);
    va_end(args);
    return err;
}

static avs_error_t try_write_fv(avs_stream_t *stream,
                                const char *msg,
                                va_list args,
                                char *buf,
                                size_t *inout_buf_size) {
    int retval = vsnprintf(buf, *inout_buf_size, msg, args);
    if (retval < 0) {
        return avs_errno(AVS_EIO);
    } else if ((size_t) retval >= *inout_buf_size) {
        *inout_buf_size = (size_t) retval + 1;
        return avs_errno(AVS_ENOBUFS);
    }
    return avs_stream_write(stream, buf, (size_t) retval);
}

static avs_error_t try_stack_write_fv(avs_stream_t *stream,
                                      const char *msg,
                                      va_list args,
                                      size_t *out_required_size) {
    char buf[AVS_STREAM_STACK_BUFFER_SIZE];
    *out_required_size = sizeof(buf);
    return try_write_fv(stream, msg, args, buf, out_required_size);
}

static avs_error_t try_heap_write_fv(avs_stream_t *stream,
                                     const char *msg,
                                     va_list args,
                                     size_t *inout_size) {
    char *buf = (char *) avs_malloc(*inout_size);
    if (!buf) {
        return avs_errno(AVS_ENOMEM);
    }
    avs_error_t err = try_write_fv(stream, msg, args, buf, inout_size);
    avs_free(buf);
    return err;
}

#    ifndef va_copy
#        define va_copy(dest, src) ((dest) = (src))
#    endif

avs_error_t
avs_stream_write_fv(avs_stream_t *stream, const char *msg, va_list args) {
    avs_error_t err;
    size_t previous_buffer_size = 0;
    size_t buffer_size;
    va_list copy;
    va_copy(copy, args);
    err = try_stack_write_fv(stream, msg, copy, &buffer_size);
    va_end(copy);
    while (err.category == AVS_ERRNO_CATEGORY && err.code == AVS_ENOBUFS
           && buffer_size > previous_buffer_size) {
        previous_buffer_size = buffer_size;
        va_copy(copy, args);
        err = try_heap_write_fv(stream, msg, copy, &buffer_size);
        va_end(copy);
    }
    return err;
}

avs_error_t avs_stream_read_reliably(avs_stream_t *stream,
                                     void *buffer,
                                     size_t buffer_length) {
    size_t bytes_read = 0;
    bool message_finished = false;
    while (bytes_read < buffer_length && !message_finished) {
        size_t current_read = 0;
        message_finished = 0;
        avs_error_t err =
                avs_stream_read(stream, &current_read, &message_finished,
                                ((char *) buffer) + bytes_read,
                                buffer_length - bytes_read);
        if (avs_is_err(err)) {
            return err;
        }
        bytes_read += current_read;
    }
    return (bytes_read == buffer_length) ? AVS_OK : AVS_EOF;
}

avs_error_t avs_stream_ignore_to_end(avs_stream_t *stream) {
    char tmp_char;
    avs_error_t err;
    do {
        err = avs_stream_getch(stream, &tmp_char, NULL);
    } while (avs_is_ok(err));
    if (avs_is_eof(err)) {
        return AVS_OK;
    }
    return err;
}

avs_error_t avs_stream_getch(avs_stream_t *stream,
                             char *out_value,
                             bool *out_message_finished) {
    size_t bytes_read;
    avs_error_t err = avs_stream_read(stream, &bytes_read, out_message_finished,
                                      out_value, 1);
    if (avs_is_ok(err) && bytes_read < 1) {
        return AVS_EOF;
    }
    return err;
}

typedef struct getline_provider_struct {
    avs_error_t (*getch)(struct getline_provider_struct *self,
                         char *out_value,
                         bool *out_message_finished);
    avs_error_t (*peek)(struct getline_provider_struct *self,
                        size_t offset,
                        char *out_value);
} getline_provider_t;

static avs_error_t validate_line_finished(getline_provider_t *provider,
                                          char last_read_char) {
    if (last_read_char == '\n') {
        // read the EOL already
        return AVS_OK;
    }
    avs_error_t err = provider->peek(provider, 0, &last_read_char);
    if (avs_is_err(err) || last_read_char == '\n') {
        // EOL right after the last read character
        return err;
    }
    if (last_read_char == '\r') {
        // special handling for \r\n
        // if the next character is \n, it's still EOL
        err = provider->peek(provider, 1, &last_read_char);
        if (avs_is_err(err) || last_read_char == '\n') {
            return err;
        }
    }
    // no EOL, so it means the line has been truncated
    return avs_errno(AVS_ENOBUFS);
}

static avs_error_t consume_line_terminator(getline_provider_t *provider,
                                           char last_consumed_char,
                                           bool *out_message_finished) {
    if (last_consumed_char == '\n') {
        return AVS_OK;
    }
    avs_error_t err = provider->getch(provider, &last_consumed_char,
                                      out_message_finished);
    if (avs_is_ok(err) && last_consumed_char == '\r') {
        err = provider->getch(provider, &last_consumed_char,
                              out_message_finished);
    }
    assert(last_consumed_char == '\n' || avs_is_err(err));
    return err;
}

static avs_error_t getline_helper(getline_provider_t *provider,
                                  size_t *out_bytes_read,
                                  bool *out_message_finished,
                                  char *buffer,
                                  size_t buffer_length) {
    *out_bytes_read = 0;
    assert(buffer_length > 0);
    char tmp_char = '\0';
    char next_char;
    avs_error_t err = AVS_OK;
    *out_message_finished = false;
    while (avs_is_ok(err) && *out_bytes_read < buffer_length - 1) {
        err = provider->getch(provider, &tmp_char, out_message_finished);
        if (avs_is_err(err)) {
            break;
        } else if (tmp_char == '\0') {
            err = avs_errno(AVS_EIO);
            break;
        } else if (tmp_char == '\n') {
            break;
        } else if (tmp_char == '\r') {
            err = provider->peek(provider, 0, &next_char);
            if (avs_is_err(err) || next_char == '\n') {
                // ignore '\r's that are before '\n's
                continue;
            }
        }
        buffer[(*out_bytes_read)++] = (char) (unsigned char) tmp_char;
    }
    if (avs_is_ok(err)
            && avs_is_ok((err = validate_line_finished(provider, tmp_char)))) {
        err = consume_line_terminator(provider, tmp_char, out_message_finished);
    }
    buffer[*out_bytes_read] = '\0';
    return err;
}

typedef struct {
    getline_provider_t vtable;
    avs_stream_t *stream;
} getline_reader_provider_t;

static avs_error_t getline_reader_getch_func(getline_provider_t *self_,
                                             char *out_value,
                                             bool *out_message_finished) {
    getline_reader_provider_t *self =
            AVS_CONTAINER_OF(self_, getline_reader_provider_t, vtable);
    return avs_stream_getch(self->stream, out_value, out_message_finished);
}

static avs_error_t getline_reader_peek_func(getline_provider_t *self_,
                                            size_t offset,
                                            char *out_value) {
    getline_reader_provider_t *self =
            AVS_CONTAINER_OF(self_, getline_reader_provider_t, vtable);
    return avs_stream_peek(self->stream, offset, out_value);
}

avs_error_t avs_stream_getline(avs_stream_t *stream,
                               size_t *out_bytes_read,
                               bool *out_message_finished,
                               char *buffer,
                               size_t buffer_length) {
    if (buffer_length == 0 || !buffer) {
        return avs_errno(AVS_EINVAL);
    }
    size_t bytes_read;
    bool message_finished;
    getline_reader_provider_t provider = {
        .vtable = {
            .getch = getline_reader_getch_func,
            .peek = getline_reader_peek_func
        },
        .stream = stream
    };
    return getline_helper(
            &provider.vtable, out_bytes_read ? out_bytes_read : &bytes_read,
            out_message_finished ? out_message_finished : &message_finished,
            buffer, buffer_length);
}

typedef struct {
    getline_provider_t vtable;
    avs_stream_t *stream;
    size_t offset;
} getline_peeker_provider_t;

static avs_error_t getline_peeker_getch_func(getline_provider_t *self_,
                                             char *out_value,
                                             bool *out_message_finished) {
    (void) out_message_finished;
    getline_peeker_provider_t *self =
            AVS_CONTAINER_OF(self_, getline_peeker_provider_t, vtable);

    avs_error_t err = avs_stream_peek(self->stream, self->offset, out_value);
    if (avs_is_ok(err)) {
        ++self->offset;
    }
    return err;
}

static avs_error_t getline_peeker_peek_func(getline_provider_t *self_,
                                            size_t offset,
                                            char *out_value) {
    getline_peeker_provider_t *self =
            AVS_CONTAINER_OF(self_, getline_peeker_provider_t, vtable);
    return avs_stream_peek(self->stream, self->offset + offset, out_value);
}

avs_error_t avs_stream_peekline(avs_stream_t *stream,
                                size_t offset,
                                size_t *out_bytes_peeked,
                                size_t *out_next_offset,
                                char *buffer,
                                size_t buffer_length) {
    if (buffer_length == 0 || !buffer) {
        return avs_errno(AVS_EINVAL);
    }
    size_t bytes_peeked;
    getline_peeker_provider_t provider = {
        .vtable = {
            .getch = getline_peeker_getch_func,
            .peek = getline_peeker_peek_func
        },
        .stream = stream,
        .offset = offset
    };
    avs_error_t err =
            getline_helper(&provider.vtable,
                           out_bytes_peeked ? out_bytes_peeked : &bytes_peeked,
                           &(bool) { false }, buffer, buffer_length);
    if (out_next_offset) {
        *out_next_offset = provider.offset;
    }
    return err;
}

avs_error_t avs_stream_copy(avs_stream_t *output_stream,
                            avs_stream_t *input_stream) {
    char buf[AVS_STREAM_STACK_BUFFER_SIZE];
    size_t bytes_read;
    bool message_finished = false;
    while (!message_finished) {
        avs_error_t err;
        if (avs_is_err((err = avs_stream_read(input_stream, &bytes_read,
                                              &message_finished, buf,
                                              sizeof(buf))))
                || (bytes_read
                    && avs_is_err((err = avs_stream_write(output_stream, buf,
                                                          bytes_read))))) {
            return err;
        }
        if (!bytes_read && !message_finished) {
            return avs_errno(AVS_EINVAL);
        }
    }
    return AVS_OK;
}

const void *avs_stream_v_table_find_extension(avs_stream_t *stream,
                                              uint32_t id) {
    const avs_stream_v_table_extension_t *ext;
    if (!stream) {
        return NULL;
    }
    for (ext = stream->vtable->extension_list; ext && ext->id; ++ext) {
        if (ext->id == id) {
            return ext->data;
        }
    }
    return NULL;
}

bool avs_stream_nonblock_read_ready(avs_stream_t *stream) {
    const avs_stream_v_table_extension_nonblock_t *nonblock =
            (const avs_stream_v_table_extension_nonblock_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK);
    if (nonblock && nonblock->read_ready) {
        return nonblock->read_ready(stream);
    } else {
        return false;
    }
}

size_t avs_stream_nonblock_write_ready(avs_stream_t *stream) {
    const avs_stream_v_table_extension_nonblock_t *nonblock =
            (const avs_stream_v_table_extension_nonblock_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK);
    if (nonblock && nonblock->write_ready) {
        return nonblock->write_ready(stream);
    } else {
        return 0;
    }
}

avs_error_t avs_stream_offset(avs_stream_t *stream, avs_off_t *out_offset) {
    const avs_stream_v_table_extension_offset_t *ext =
            (const avs_stream_v_table_extension_offset_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_OFFSET);
    if (ext) {
        return ext->offset(stream, out_offset);
    }
    return avs_errno(AVS_ENOTSUP);
}

#endif // AVS_COMMONS_WITH_AVS_STREAM
