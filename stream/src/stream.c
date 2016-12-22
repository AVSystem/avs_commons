/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifdef __STRICT_ANSI__
#undef __STRICT_ANSI__ /* for va_copy() */
#endif

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
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

int avs_stream_write(avs_stream_abstract_t *stream,
                     const void *buffer,
                     size_t buffer_length) {
    if (!stream->vtable->write) {
        return -1;
    }
    return stream->vtable->write(stream, buffer, buffer_length);
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

typedef int (*getline_getch_func_t)(void *state, char peek);

static int getline_helper(getline_getch_func_t getch_func,
                          void *getch_func_state,
                          size_t *out_bytes_read,
                          char *buffer,
                          size_t buffer_length) {
    char line_finished = 0;
    *out_bytes_read = 0;
    while (*out_bytes_read < buffer_length) {
        int tmp_char = getch_func(getch_func_state, 0);
        if (tmp_char < 0) {
            return tmp_char;
        } else if (tmp_char == '\n') {
            line_finished = 1;
            break;
        } else if (tmp_char == '\0') {
            break;
        } else if (tmp_char != '\r'
                || getch_func(getch_func_state, 1) != '\n') {
            /* ignore '\r's that are before '\n's */
            buffer[(*out_bytes_read)++] = (char) (unsigned char) tmp_char;
        }
    }
    return line_finished ? 0 : 1;
}

typedef struct {
    avs_stream_abstract_t *stream;
    char *out_message_finished;
} getline_reader_getch_func_state_t;

static int getline_reader_getch_func(void *state_, char peek) {
    getline_reader_getch_func_state_t *state =
            (getline_reader_getch_func_state_t *) state_;
    if (*state->out_message_finished) {
        return EOF;
    }
    if (peek) {
        return avs_stream_peek(state->stream, 0);
    } else {
        return avs_stream_getch(state->stream, state->out_message_finished);
    }
}

/**
 * Simple code for manual testing:
 *
 *   http_client_t *http = _cwmp_http_new();
 *   cwmp_abstract_stream_t *stream =
 *           _cwmp_http_open_stream(http, HTTP_GET, "http://www.google.com/",
 *                                  NULL, NULL);
 *   char message_finished = 0;
 *   _cwmp_stream_write(stream, 1, NULL, 0);
 *   while (!message_finished) {
 *       char buf[81];
 *       int val;
 *       buf[80] = '\0';
 *       val = _cwmp_stream_getline(stream, NULL, &message_finished, buf, 80);
 *       if (val < 0) {
 *           break;
 *       }
 *       printf("%s: %s\n", val ? "   v" : "LINE", buf);
 *   }
 */
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
    getline_reader_getch_func_state_t state;
    state.stream = stream;
    state.out_message_finished =
            out_message_finished ? out_message_finished : &message_finished;
    *state.out_message_finished = 0;
    int retval = getline_helper(getline_reader_getch_func, &state,
                                &bytes_read,
                                buffer, buffer_length - 1);
    if (retval >= 0) {
        if (out_bytes_read) {
            *out_bytes_read = bytes_read;
        }
        buffer[bytes_read] = '\0';
    }
    return retval;
}

typedef struct {
    avs_stream_abstract_t *stream;
    size_t offset;
} getline_peeker_getch_func_state_t;

static int getline_peeker_getch_func(void *state_, char peek) {
    getline_peeker_getch_func_state_t *state =
            (getline_peeker_getch_func_state_t *) state_;
    int retval = avs_stream_peek(state->stream, state->offset);
    if (retval >= 0 && !peek) {
        ++state->offset;
    }
    return retval;
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
    getline_peeker_getch_func_state_t state;
    state.stream = stream;
    state.offset = offset;
    int retval = getline_helper(getline_peeker_getch_func, &state,
                                &bytes_peeked, buffer, buffer_length - 1);
    if (out_next_offset) {
        *out_next_offset = state.offset;
    }
    if (retval >= 0) {
        if (out_bytes_peeked) {
            *out_bytes_peeked = bytes_peeked;
        }
        buffer[bytes_peeked] = '\0';
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
