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
#include <posix-config.h>

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <limits.h>

#include <avsystem/commons/stream/stream_membuf.h>
#include <avsystem/commons/stream_v_table.h>

#define MODULE_NAME avs_stream
#include <x_log_config.h>

VISIBILITY_SOURCE_BEGIN

struct avs_stream_membuf_struct {
    const void *const vtable;
    char *buffer;
    size_t buffer_size;
    size_t index_write;
    size_t index_read;
    int error_code;
};

int avs_stream_membuf_fit(avs_stream_abstract_t *stream) {
    const avs_stream_v_table_extension_membuf_t *ext =
        (const avs_stream_v_table_extension_membuf_t *)
        avs_stream_v_table_find_extension(stream,
                                          AVS_STREAM_V_TABLE_EXTENSION_MEMBUF);
    if (ext) {
        return ext->fit(stream);
    }
    return -1;
}

static int stream_membuf_write_some(avs_stream_abstract_t *stream_,
                                    const void *buffer,
                                    size_t *inout_data_length) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    stream->error_code = 0;
    if (*inout_data_length == 0) {
        return 0;
    }
    if (stream->buffer_size < stream->index_write + *inout_data_length) {
        size_t new_size = 2 * stream->buffer_size + *inout_data_length;
        char *new_buffer = (char *) realloc(stream->buffer, new_size);
        if (!new_buffer) {
            *inout_data_length = stream->buffer_size - stream->index_write;
        } else {
            stream->buffer = new_buffer;
            stream->buffer_size = new_size;
        }
    }
    memcpy(stream->buffer + stream->index_write, buffer, *inout_data_length);
    stream->index_write += *inout_data_length;
    return 0;
}

static int stream_membuf_read(avs_stream_abstract_t *stream_,
                              size_t *out_bytes_read,
                              char *out_message_finished,
                              void *buffer,
                              size_t buffer_length) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    size_t bytes_left = stream->index_write - stream->index_read;
    size_t bytes_read = bytes_left < buffer_length
                            ? bytes_left
                            : buffer_length;
    stream->error_code = 0;
    assert(stream->index_read <= stream->index_write);
    if (!buffer) {
        stream->error_code = EINVAL;
        return -1;
    }
    *out_bytes_read = bytes_read;
    if (out_message_finished) {
        *out_message_finished = (bytes_read == bytes_left);
    }
    memcpy(buffer, stream->buffer + stream->index_read, bytes_read);
    stream->index_read += bytes_read;
    return 0;
}

static int stream_membuf_peek(avs_stream_abstract_t *stream_,
                              size_t offset) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    stream->error_code = 0;
    if (stream->index_read + offset >= stream->index_write) {
        return EOF;
    }
    return (unsigned char) stream->buffer[stream->index_read + offset];
}

static int stream_membuf_errno(avs_stream_abstract_t *stream_) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    return stream->error_code;
}

static int stream_membuf_reset(avs_stream_abstract_t *stream_) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    stream->error_code = 0;
    stream->index_read = 0;
    stream->index_write = 0;
    return 0;
}

static int stream_membuf_close(avs_stream_abstract_t *stream_) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    free(stream->buffer);
    stream->buffer = NULL;
    stream->buffer_size = 0;
    stream->index_read = 0;
    stream->index_write = 0;
    return 0;
}

static int stream_membuf_fit(avs_stream_abstract_t *stream_) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    size_t max_index = stream->index_write;
    if (stream->buffer_size > max_index) {
        void *new_buffer = realloc(stream->buffer, max_index);
        if (new_buffer || max_index == 0) {
            stream->buffer = (char *) new_buffer;
            stream->buffer_size = max_index;
        }
    }
    return 0;
}

static int unimplemented() {
    return -1;
}

static const avs_stream_v_table_extension_membuf_t stream_membuf_ext_vtable = {
    stream_membuf_fit
};

static const avs_stream_v_table_extension_t stream_membuf_extensions[] = {
    { AVS_STREAM_V_TABLE_EXTENSION_MEMBUF, &stream_membuf_ext_vtable },
    AVS_STREAM_V_TABLE_EXTENSION_NULL
};

static const avs_stream_v_table_t membuf_stream_vtable = {
    stream_membuf_write_some,
    (avs_stream_finish_message_t) unimplemented,
    stream_membuf_read,
    stream_membuf_peek,
    stream_membuf_reset,
    stream_membuf_close,
    stream_membuf_errno,
    stream_membuf_extensions
};

avs_stream_abstract_t *
avs_stream_membuf_create() {
    avs_stream_membuf_t *membuf =
        (avs_stream_membuf_t *) calloc(1, sizeof(avs_stream_membuf_t));
    const void *vtable = &membuf_stream_vtable;
    if (!membuf) {
        return NULL;
    }
    memcpy((void *) (intptr_t) &membuf->vtable, &vtable, sizeof(void *));
    return (avs_stream_abstract_t *) membuf;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_stream_membuf.c"
#endif
