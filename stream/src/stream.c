/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>

#include <avsystem/commons/stream.h>
#include <avsystem/commons/stream_v_table.h>

#define MODULE_NAME avs_stream
#include <x_log_config.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

struct avs_stream_abstract_struct {
    const avs_stream_v_table_t * const vtable;
};

int avs_stream_write_some(avs_stream_abstract_t *stream,
                          const void *buffer,
                          size_t *inout_data_length) {
    if (!stream->vtable->write_some) {
        return -1;
    }
    return stream->vtable->write_some(stream, buffer, inout_data_length);
}

int avs_stream_write(avs_stream_abstract_t *stream,
                     const void *buffer,
                     size_t buffer_length) {
    size_t data_length = buffer_length;
    int result = avs_stream_write_some(stream, buffer, &data_length);
    if (!result && data_length != buffer_length) {
        result = -1;
    }
    return result;
}

int avs_stream_finish_message(avs_stream_abstract_t *stream) {
    if (!stream->vtable->finish_message) {
        return -1;
    }
    return stream->vtable->finish_message(stream);
}

int avs_stream_read(avs_stream_abstract_t *stream,
                    size_t *out_bytes_read,
                    char *out_message_finished,
                    void *buffer,
                    size_t buffer_length) {
    if (!stream->vtable->read) {
        return -1;
    }
    return stream->vtable->read(stream, out_bytes_read,
                                out_message_finished,
                                buffer, buffer_length);
}

int avs_stream_peek(avs_stream_abstract_t *stream,
                    size_t offset) {
    if (!stream->vtable->peek) {
        return -1;
    }
    return stream->vtable->peek(stream, offset);
}

int avs_stream_reset(avs_stream_abstract_t *stream) {
    if (!stream->vtable->reset) {
        return -1;
    }
    return stream->vtable->reset(stream);
}

void avs_stream_cleanup(avs_stream_abstract_t **stream) {
    if (*stream) {
        (*stream)->vtable->close(*stream);
        free(*stream);
        *stream = NULL;
    }
}

int avs_stream_errno(avs_stream_abstract_t *stream) {
    if (!stream->vtable->get_errno) {
        return -1;
    }
    return stream->vtable->get_errno(stream);
}

int avs_stream_write_f(avs_stream_abstract_t *stream, const char* msg, ...) {
    int result = 0;
    va_list args;
    va_start(args, msg);
    result = avs_stream_write_fv(stream, msg, args);
    va_end(args);
    return result;
}

static int try_write_fv(avs_stream_abstract_t *stream,
                        const char *msg, va_list args,
                        char *buf, size_t buf_size) {
    int retval = vsnprintf(buf, buf_size, msg, args);
    if (retval < 0) {
        size_t new_size = buf_size * 2;
        retval = (int) new_size;
        if (retval < 0 || (size_t) retval != new_size) {
            return -1;
        }
        return retval;
    } else if ((size_t) retval >= buf_size) {
        return retval + 1;
    }
    return avs_stream_write(stream, buf, (size_t) retval);
}

static int try_stack_write_fv(avs_stream_abstract_t *stream,
                              const char *msg, va_list args) {
    char buf[512];
    return try_write_fv(stream, msg, args, buf, sizeof(buf));
}

static int try_heap_write_fv(avs_stream_abstract_t *stream,
                             const char *msg, va_list args, size_t size) {
    char *buf = (char *) malloc(size);
    int retval = -1;
    if (buf) {
        retval = try_write_fv(stream, msg, args, buf, size);
        free(buf);
    }
    return retval;
}

#ifndef va_copy
#define va_copy(dest, src) ((dest) = (src))
#endif

int avs_stream_write_fv(avs_stream_abstract_t *stream,
                        const char* msg, va_list args) {
    int retval;
    va_list copy;
    va_copy(copy, args);
    retval = try_stack_write_fv(stream, msg, copy);
    va_end(copy);
    while (retval > 0) {
        va_copy(copy, args);
        retval = try_heap_write_fv(stream, msg, copy, (size_t) retval);
        va_end(copy);
    }
    return retval;
}

int avs_stream_read_reliably(avs_stream_abstract_t *stream,
                             void *buffer,
                             size_t buffer_length) {
    size_t bytes_read = 0;
    char message_finished = 0;
    while (bytes_read < buffer_length && !message_finished) {
        size_t current_read = 0;
        message_finished = 0;
        if (avs_stream_read(stream, &current_read, &message_finished,
                              ((char *) buffer) + bytes_read,
                              buffer_length - bytes_read)) {
            return -1;
        }
        bytes_read += current_read;
    }
    return (bytes_read == buffer_length) ? 0 : -1;
}

int avs_stream_ignore_to_end(avs_stream_abstract_t *stream) {
    char message_finished = 0;
    int count = 0;
    while (avs_stream_getch(stream, &message_finished) != EOF) {
        ++count;
    }
    return message_finished ? count : -1;
}

int avs_stream_getch(avs_stream_abstract_t *stream, char *message_finished) {
    char buf;
    size_t bytes_read;
    if (avs_stream_read(stream, &bytes_read, message_finished, &buf, 1) < 0
            || bytes_read < 1) {
        return EOF;
    }
    return buf;
}

typedef struct getline_provider_struct {
    int (*getch)(struct getline_provider_struct *self);
    int (*peek)(struct getline_provider_struct *self, size_t offset);
} getline_provider_t;

static bool line_finished(getline_provider_t *provider,
                          int last_read_char) {
    if (last_read_char == '\n') {
        return true;
    }
    int next_char = provider->peek(provider, 0);
    return (next_char == '\n'
            || (next_char == '\r' && provider->peek(provider, 1) == '\n'));
}

static void consume_line_terminator(getline_provider_t *provider,
                                    int last_consumed_char) {
    if (last_consumed_char != '\n') {
        last_consumed_char = provider->getch(provider);
        if (last_consumed_char == '\r') {
            last_consumed_char = provider->getch(provider);
        }
    }
    assert(last_consumed_char == '\n');
}

static int getline_helper(getline_provider_t *provider,
                          size_t *out_bytes_read,
                          char *buffer,
                          size_t buffer_length) {
    *out_bytes_read = 0;
    assert(buffer_length > 0);
    int tmp_char = EOF;
    int result = 0;
    while (*out_bytes_read < buffer_length - 1) {
        tmp_char = provider->getch(provider);
        if (tmp_char <= 0) {
            result = -1;
            break;
        } else if (tmp_char == '\n') {
            break;
        } else if (tmp_char != '\r' || provider->peek(provider, 0) != '\n') {
            /* ignore '\r's that are before '\n's */
            buffer[(*out_bytes_read)++] = (char) (unsigned char) tmp_char;
        }
    }
    if (!result) {
        if (line_finished(provider, tmp_char)) {
            consume_line_terminator(provider, tmp_char);
        } else {
            result = 1;
        }
    }
    buffer[*out_bytes_read] = '\0';
    return result;
}

typedef struct {
    getline_provider_t vtable;
    avs_stream_abstract_t *stream;
    char *out_message_finished;
} getline_reader_provider_t;

static int getline_reader_getch_func(getline_provider_t *self_) {
    getline_reader_provider_t *self =
            AVS_CONTAINER_OF(self_, getline_reader_provider_t, vtable);
    if (*self->out_message_finished) {
        return EOF;
    }
    return avs_stream_getch(self->stream, self->out_message_finished);
}

static int getline_reader_peek_func(getline_provider_t *self_,
                                    size_t offset) {
    getline_reader_provider_t *self =
            AVS_CONTAINER_OF(self_, getline_reader_provider_t, vtable);
    if (*self->out_message_finished) {
        return EOF;
    }
    return avs_stream_peek(self->stream, offset);
}

int avs_stream_getline(avs_stream_abstract_t *stream,
                       size_t *out_bytes_read,
                       char *out_message_finished,
                       char *buffer,
                       size_t buffer_length) {
    if (buffer_length == 0 || !buffer) {
        return -1;
    }
    size_t bytes_read;
    char message_finished;
    getline_reader_provider_t provider = {
        .vtable = {
            .getch = getline_reader_getch_func,
            .peek = getline_reader_peek_func
        },
        .stream = stream,
        .out_message_finished =
                out_message_finished ? out_message_finished : &message_finished
    };
    *provider.out_message_finished = 0;
    return getline_helper(&provider.vtable,
                          out_bytes_read ? out_bytes_read : &bytes_read,
                          buffer, buffer_length);
}

typedef struct {
    getline_provider_t vtable;
    avs_stream_abstract_t *stream;
    size_t offset;
} getline_peeker_provider_t;

static int getline_peeker_getch_func(getline_provider_t *self_) {
    getline_peeker_provider_t *self =
            AVS_CONTAINER_OF(self_, getline_peeker_provider_t, vtable);
    int retval = avs_stream_peek(self->stream, self->offset);
    if (retval >= 0) {
        ++self->offset;
    }
    return retval;
}

static int getline_peeker_peek_func(getline_provider_t *self_,
                                    size_t offset) {
    getline_peeker_provider_t *self =
            AVS_CONTAINER_OF(self_, getline_peeker_provider_t, vtable);
    return avs_stream_peek(self->stream, self->offset + offset);
}

int avs_stream_peekline(avs_stream_abstract_t *stream,
                        size_t offset,
                        size_t *out_bytes_peeked,
                        size_t *out_next_offset,
                        char *buffer,
                        size_t buffer_length) {
    if (buffer_length == 0 || !buffer) {
        return -1;
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
    int retval =
            getline_helper(&provider.vtable,
                           out_bytes_peeked ? out_bytes_peeked : &bytes_peeked,
                           buffer, buffer_length);
    if (out_next_offset) {
        *out_next_offset = provider.offset;
    }
    return retval;
}

const void *avs_stream_v_table_find_extension(avs_stream_abstract_t *stream,
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
