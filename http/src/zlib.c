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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include <avsystem/commons/errno.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/stream_v_table.h>

#include "http_log.h"
#include "zlib.h"

VISIBILITY_SOURCE_BEGIN

#define GET_INPUT_BUFFER(stream) ((stream)->data)
#define GET_OUTPUT_BUFFER(stream) ((stream)->data + (stream)->input_buffer_size)

typedef struct {
    const avs_stream_v_table_t * const vtable;
    z_stream zlib;
    int error;
    int flush;
    size_t input_buffer_size;
    size_t output_buffer_size;
    uint8_t data[];
} zlib_stream_t;

/* we don't use opaque field in zlib for allocation data,
 * so we can reuse it for flush function pointer */
#define FLUSH_FUNC(stream) \
        (((zlib_flush_func_holder_t *) (stream)->zlib.opaque)->flush_func)

typedef struct {
    int (*flush_func)(zlib_stream_t *);
} zlib_flush_func_holder_t;

#define zlib_stream_flush(stream) FLUSH_FUNC(stream)(stream)

static const char *get_zlib_msg(const zlib_stream_t *stream) {
    return stream->zlib.msg ? stream->zlib.msg : "(no message)";
}

static int compressor_flush(zlib_stream_t *stream) {
    stream->error = deflate(&stream->zlib, stream->flush);
    if (stream->error == Z_BUF_ERROR) {
        /* nothing happened, ignore */
        stream->error = Z_OK;
        return 0;
    }
    if (stream->error != Z_OK && stream->error != Z_STREAM_END) {
        LOG(ERROR, "Compression error (%d): %s",
            stream->error, get_zlib_msg(stream));
        return -1;
    }
    memmove(GET_INPUT_BUFFER(stream),
            stream->zlib.next_in, stream->zlib.avail_in);
    stream->zlib.next_in = GET_INPUT_BUFFER(stream);
    return 0;
}

static zlib_flush_func_holder_t compressor_flush_holder = { compressor_flush };

static int decompressor_flush(zlib_stream_t *stream) {
    if (stream->error == Z_STREAM_END) {
        return 0;
    }
    stream->error = inflate(&stream->zlib, stream->flush);
    if (stream->error == Z_BUF_ERROR) {
        /* nothing happened, ignore */
        stream->error = Z_OK;
        return 0;
    }
    if (stream->error != Z_OK && stream->error != Z_STREAM_END) {
        LOG(ERROR, "Decompression error (%d): %s",
            stream->error, get_zlib_msg(stream));
        return -1;
    }
    memmove(GET_INPUT_BUFFER(stream),
            stream->zlib.next_in, stream->zlib.avail_in);
    stream->zlib.next_in = GET_INPUT_BUFFER(stream);
    return 0;
}

static zlib_flush_func_holder_t decompressor_flush_holder
        = { decompressor_flush };

static int zlib_stream_write_some(avs_stream_abstract_t *stream_,
                                  const void *data,
                                  size_t *inout_data_length) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (stream->error == Z_STREAM_END || stream->flush != Z_NO_FLUSH) {
        LOG(ERROR, "Stream finished");
        return -1;
    }
    if (*inout_data_length
            > stream->input_buffer_size - stream->zlib.avail_in) {
        if (zlib_stream_flush(stream)) {
            return -1;
        }
    }
    if (*inout_data_length
            > stream->input_buffer_size - stream->zlib.avail_in) {
        *inout_data_length = stream->input_buffer_size - stream->zlib.avail_in;
    }
    memcpy(stream->zlib.next_in + stream->zlib.avail_in,
           data, *inout_data_length);
    stream->zlib.avail_in += (unsigned) *inout_data_length;
    return zlib_stream_flush(stream);
}

static int zlib_stream_nonblock_write_ready(avs_stream_abstract_t *stream_,
                                            size_t *out_ready_capacity_bytes) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (stream->zlib.avail_in > 0 && zlib_stream_flush(stream)) {
        return -1;
    }
    *out_ready_capacity_bytes =
            stream->input_buffer_size - stream->zlib.avail_in;
    return 0;
}

static int zlib_stream_finish_message(avs_stream_abstract_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    stream->flush = Z_FINISH;
    return zlib_stream_flush(stream);
}

static int zlib_stream_read(avs_stream_abstract_t *stream_,
                            size_t *out_bytes_read,
                            char *out_message_finished,
                            void *buffer,
                            size_t buffer_length) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    size_t ready_bytes =
            AVS_MIN(buffer_length,
                    stream->output_buffer_size - stream->zlib.avail_out);
    *out_bytes_read = 0;
    *out_message_finished = 0;
    if (ready_bytes) {
        memcpy(buffer, GET_OUTPUT_BUFFER(stream), ready_bytes);
        memmove(GET_OUTPUT_BUFFER(stream),
                GET_OUTPUT_BUFFER(stream) + ready_bytes,
                (stream->output_buffer_size - stream->zlib.avail_out)
                - ready_bytes);
        stream->zlib.avail_out += (unsigned) ready_bytes;
        *out_bytes_read += ready_bytes;
    }
    if (*out_bytes_read < buffer_length && stream->error != Z_STREAM_END) {
        unsigned avail_out_orig = stream->zlib.avail_out;
        stream->zlib.next_out = ((uint8_t *) buffer) + *out_bytes_read;
        stream->zlib.avail_out = (unsigned) (buffer_length - *out_bytes_read);
        zlib_stream_flush(stream);
        *out_bytes_read = buffer_length - stream->zlib.avail_out;
        stream->zlib.avail_out = avail_out_orig;
    }
    stream->zlib.next_out = GET_OUTPUT_BUFFER(stream)
            + (stream->output_buffer_size - stream->zlib.avail_out);
    if (stream->error == Z_STREAM_END) {
        if (stream->zlib.avail_out >= stream->output_buffer_size) {
            *out_message_finished = 1;
        }
    } else if (stream->error != Z_OK) {
        LOG(ERROR, "zlib operation error (%d): %s",
            stream->error, get_zlib_msg(stream));
        return -1;
    }
    return 0;
}

static int zlib_stream_nonblock_read_ready(avs_stream_abstract_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (stream->zlib.avail_out < stream->output_buffer_size) {
        return 1;
    }
    if (zlib_stream_flush(stream)) {
        return -1;
    }
    return stream->zlib.avail_out < stream->output_buffer_size;
}

static int zlib_stream_peek(avs_stream_abstract_t *stream_,
                            size_t offset) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (offset > stream->output_buffer_size) {
        LOG(ERROR, "cannot peek - buffer is too small");
        return EOF;
    }
    if (stream->zlib.avail_out + offset >= stream->output_buffer_size) {
        if (zlib_stream_flush(stream)) {
            return EOF;
        }
    }
    if (stream->zlib.avail_out + offset < stream->output_buffer_size) {
        return GET_OUTPUT_BUFFER(stream)[offset];
    } else {
        return EOF;
    }
}

static void reset_fields(zlib_stream_t *stream) {
    stream->zlib.avail_in = 0;
    stream->zlib.avail_out = (unsigned int) stream->output_buffer_size;
    stream->zlib.next_in = GET_INPUT_BUFFER(stream);
    stream->zlib.next_out = GET_OUTPUT_BUFFER(stream);
    stream->flush = 0;
    stream->error = Z_OK;
}

static int zlib_stream_error(avs_stream_abstract_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (stream->error == Z_OK || stream->error == Z_STREAM_END) {
        return 0;
    } else if (stream->error != Z_ERRNO) {
        return stream->error;
    } else {
        return errno;
    }
    return 0;
}

static void *zlib_stream_alloc(void *opaque, unsigned n, unsigned size) {
    (void) opaque;
    return avs_calloc(n, size);
}

static void zlib_stream_free(void *opaque, void *ptr) {
    (void) opaque;
    avs_free(ptr);
}

static zlib_stream_t *zlib_stream_init(const avs_stream_v_table_t *vtable,
                                       size_t input_buffer_size,
                                       size_t output_buffer_size) {
    if (input_buffer_size <= 0 || output_buffer_size <= 0) {
        LOG(ERROR, "buffers cannot be zero-length");
        return NULL;
    }
    zlib_stream_t *stream = (zlib_stream_t *)
            avs_calloc(1, sizeof(zlib_stream_t)
                         + input_buffer_size + output_buffer_size);
    if (!stream) {
        LOG(ERROR, "cannot allocate memory");
        return NULL;
    }
    *(const avs_stream_v_table_t **) (intptr_t) &stream->vtable = vtable;
    stream->input_buffer_size = input_buffer_size;
    stream->output_buffer_size = output_buffer_size;
    stream->zlib.zalloc = zlib_stream_alloc;
    stream->zlib.zfree = zlib_stream_free;
    return stream;
}

static int compressor_reset(avs_stream_abstract_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    reset_fields(stream);
    stream->error = deflateReset(&stream->zlib);
    return stream->error == Z_OK ? 0 : -1;
}

static int compressor_close(avs_stream_abstract_t *stream) {
    return deflateEnd(&((zlib_stream_t *) stream)->zlib) == Z_OK ? 0 : -1;
}

static const avs_stream_v_table_extension_t zlib_vtable_extensions[] = {
    {
        AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
        &(avs_stream_v_table_extension_nonblock_t[]) {
            {
                zlib_stream_nonblock_read_ready,
                zlib_stream_nonblock_write_ready
            }
        }[0]
    },
    AVS_STREAM_V_TABLE_EXTENSION_NULL
};

static const avs_stream_v_table_t compressor_vtable = {
    zlib_stream_write_some,
    zlib_stream_finish_message,
    zlib_stream_read,
    zlib_stream_peek,
    compressor_reset,
    compressor_close,
    zlib_stream_error,
    zlib_vtable_extensions
};

avs_stream_abstract_t *
_avs_http_create_compressor(http_compression_format_t format,
                            int level,
                            int window_bits,
                            int mem_level,
                            size_t input_buffer_size,
                            size_t output_buffer_size) {
    int result;
    zlib_stream_t *stream = zlib_stream_init(&compressor_vtable,
                                             input_buffer_size,
                                             output_buffer_size);
    if (!stream) {
        return NULL;
    }
    stream->zlib.opaque = &compressor_flush_holder;
    result = deflateInit2(
            &stream->zlib, level, Z_DEFLATED,
            window_bits + (format == HTTP_COMPRESSION_GZIP ? 16 : 0),
            mem_level, Z_DEFAULT_STRATEGY);
    if (result != Z_OK) {
        LOG(ERROR, "could not initialize zlib (%d): %s",
            result, get_zlib_msg(stream));
        avs_free(stream);
        return NULL;
    }
    reset_fields(stream);
    return (avs_stream_abstract_t *) stream;
}

static int decompressor_reset(avs_stream_abstract_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    reset_fields(stream);
    stream->error = inflateReset(&stream->zlib);
    return stream->error == Z_OK ? 0 : -1;
}

static int decompressor_close(avs_stream_abstract_t *stream) {
    return inflateEnd(&((zlib_stream_t *) stream)->zlib) == Z_OK ? 0 : -1;
}

static const avs_stream_v_table_t decompressor_vtable = {
    zlib_stream_write_some,
    zlib_stream_finish_message,
    zlib_stream_read,
    zlib_stream_peek,
    decompressor_reset,
    decompressor_close,
    zlib_stream_error,
    zlib_vtable_extensions
};

avs_stream_abstract_t *
_avs_http_create_decompressor(http_compression_format_t format,
                              int window_bits,
                              size_t input_buffer_size,
                              size_t output_buffer_size) {
    int result;
    zlib_stream_t *stream = zlib_stream_init(&decompressor_vtable,
                                             input_buffer_size,
                                             output_buffer_size);
    if (!stream) {
        return NULL;
    }
    stream->zlib.opaque = &decompressor_flush_holder;
    result = inflateInit2(
            &stream->zlib,
            window_bits + (format == HTTP_COMPRESSION_GZIP ? 16 : 0));
    if (result != Z_OK) {
        LOG(ERROR, "could not initialize zlib (%d): %s",
            result, get_zlib_msg(stream));
        avs_free(stream);
        return NULL;
    }
    reset_fields(stream);
    return (avs_stream_abstract_t *) stream;
}
