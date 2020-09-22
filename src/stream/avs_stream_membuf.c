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
#    include <string.h>

#    include <limits.h>

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_membuf.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    define MODULE_NAME avs_stream
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

struct avs_stream_membuf_struct {
    const void *const vtable;
    char *buffer;
    size_t buffer_size;
    size_t index_write;
    size_t index_read;
};

avs_error_t avs_stream_membuf_ensure_free_bytes(avs_stream_t *stream,
                                                size_t additional_size) {
    const avs_stream_v_table_extension_membuf_t *ext =
            (const avs_stream_v_table_extension_membuf_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_MEMBUF);
    if (ext) {
        return ext->ensure_free_bytes(stream, additional_size);
    }
    return avs_errno(AVS_ENOTSUP);
}

avs_error_t avs_stream_membuf_fit(avs_stream_t *stream) {
    const avs_stream_v_table_extension_membuf_t *ext =
            (const avs_stream_v_table_extension_membuf_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_MEMBUF);
    if (ext) {
        return ext->fit(stream);
    }
    return avs_errno(AVS_ENOTSUP);
}

avs_error_t avs_stream_membuf_take_ownership(avs_stream_t *stream,
                                             void **out_ptr,
                                             size_t *out_size) {
    const avs_stream_v_table_extension_membuf_t *ext =
            (const avs_stream_v_table_extension_membuf_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_MEMBUF);
    if (ext) {
        return ext->take_ownership(stream, out_ptr, out_size);
    }
    return avs_errno(AVS_ENOTSUP);
}

static void defragment_membuf(avs_stream_membuf_t *stream) {
    if (stream->index_read) {
        size_t used = stream->index_write - stream->index_read;
        memmove(stream->buffer, &stream->buffer[stream->index_read], used);
        stream->index_write = used;
        stream->index_read = 0;
    }
}

static avs_error_t realloc_membuf(avs_stream_membuf_t *stream,
                                  size_t new_size) {
    assert(stream->index_read == 0);         // stream is defragmented
    assert(stream->index_write <= new_size); // we're not losing data
    char *new_buffer = (char *) avs_realloc(stream->buffer, new_size);
    if (!new_buffer && new_size) {
        return avs_errno(AVS_ENOMEM);
    }
    stream->buffer = new_buffer;
    stream->buffer_size = new_size;
    return AVS_OK;
}

static avs_error_t stream_membuf_write_some(avs_stream_t *stream_,
                                            const void *buffer,
                                            size_t *inout_data_length) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    if (*inout_data_length == 0) {
        return AVS_OK;
    }
    if (stream->buffer_size < stream->index_write + *inout_data_length) {
        defragment_membuf(stream);
    }
    if (stream->buffer_size < stream->index_write + *inout_data_length) {
        avs_error_t err =
                realloc_membuf(stream,
                               2 * stream->buffer_size + *inout_data_length);
        if (avs_is_err(err)) {
            *inout_data_length = stream->buffer_size - stream->index_write;
            if (*inout_data_length == 0) {
                return err;
            }
        }
        assert(stream->buffer);
    }
    memcpy(stream->buffer + stream->index_write, buffer, *inout_data_length);
    stream->index_write += *inout_data_length;
    return AVS_OK;
}

static avs_error_t stream_membuf_read(avs_stream_t *stream_,
                                      size_t *out_bytes_read,
                                      bool *out_message_finished,
                                      void *buffer,
                                      size_t buffer_length) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    size_t bytes_left = stream->index_write - stream->index_read;
    size_t bytes_read = bytes_left < buffer_length ? bytes_left : buffer_length;
    assert(stream->index_read <= stream->index_write);
    if (!buffer && buffer_length) {
        return avs_errno(AVS_EINVAL);
    }
    if (out_bytes_read) {
        *out_bytes_read = bytes_read;
    }
    if (out_message_finished) {
        *out_message_finished = (bytes_read == bytes_left);
    }
    if (bytes_read) {
        assert(buffer);
        memcpy(buffer, stream->buffer + stream->index_read, bytes_read);
        stream->index_read += bytes_read;
        if (stream->index_read == stream->index_write) {
            stream->index_read = 0;
            stream->index_write = 0;
        }
    }
    return AVS_OK;
}

static avs_error_t
stream_membuf_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    if (stream->index_read + offset >= stream->index_write) {
        return AVS_EOF;
    }
    *out_value = stream->buffer[stream->index_read + offset];
    return AVS_OK;
}

static avs_error_t stream_membuf_reset(avs_stream_t *stream_) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    stream->index_read = 0;
    stream->index_write = 0;
    return AVS_OK;
}

static avs_error_t stream_membuf_close(avs_stream_t *stream_) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    avs_free(stream->buffer);
    stream->buffer = NULL;
    stream->buffer_size = 0;
    stream->index_read = 0;
    stream->index_write = 0;
    return AVS_OK;
}

static avs_error_t stream_membuf_offset(avs_stream_t *stream_,
                                        avs_off_t *out_offset) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    assert(stream->index_read <= stream->index_write);
    size_t offset = stream->index_write - stream->index_read;
    if (offset > LONG_MAX) {
        return avs_errno(AVS_E2BIG);
    }
    *out_offset = (avs_off_t) offset;
    return AVS_OK;
}

static avs_error_t stream_membuf_ensure_free_bytes(avs_stream_t *stream_,
                                                   size_t additional_size) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    defragment_membuf(stream);
    if (additional_size > SIZE_MAX - stream->index_write) {
        return avs_errno(AVS_ENOMEM);
    }
    if (stream->buffer_size < stream->index_write + additional_size) {
        return realloc_membuf(stream, stream->index_write + additional_size);
    }
    return AVS_OK;
}

static avs_error_t stream_membuf_fit(avs_stream_t *stream_) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    defragment_membuf(stream);
    size_t max_index = stream->index_write;
    if (stream->buffer_size > max_index) {
        return realloc_membuf(stream, max_index);
    }
    return AVS_OK;
}

static avs_error_t stream_membuf_take_ownership(avs_stream_t *stream_,
                                                void **out_ptr,
                                                size_t *out_size) {
    avs_stream_membuf_t *stream = (avs_stream_membuf_t *) stream_;
    stream_membuf_fit(stream_);
    *out_ptr = (void *) stream->buffer;
    if (out_size) {
        *out_size = stream->buffer_size;
    }
    stream->buffer = NULL;
    stream->buffer_size = 0;
    stream_membuf_reset(stream_);
    return AVS_OK;
}

static const avs_stream_v_table_t membuf_stream_vtable = {
    .write_some = stream_membuf_write_some,
    .read = stream_membuf_read,
    .peek = stream_membuf_peek,
    .reset = stream_membuf_reset,
    .close = stream_membuf_close,
    .extension_list =
            (const avs_stream_v_table_extension_t[]) {
                    { AVS_STREAM_V_TABLE_EXTENSION_OFFSET,
                      &(const avs_stream_v_table_extension_offset_t) {
                              stream_membuf_offset } },
                    { AVS_STREAM_V_TABLE_EXTENSION_MEMBUF,
                      &(const avs_stream_v_table_extension_membuf_t) {
                              stream_membuf_ensure_free_bytes,
                              stream_membuf_fit,
                              stream_membuf_take_ownership } },
                    AVS_STREAM_V_TABLE_EXTENSION_NULL }
};

avs_stream_t *avs_stream_membuf_create(void) {
    avs_stream_membuf_t *membuf =
            (avs_stream_membuf_t *) avs_calloc(1, sizeof(avs_stream_membuf_t));
    const void *vtable = &membuf_stream_vtable;
    if (!membuf) {
        return NULL;
    }
    memcpy((void *) (intptr_t) &membuf->vtable, &vtable, sizeof(void *));
    return (avs_stream_t *) membuf;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/stream/test_stream_membuf.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_STREAM
