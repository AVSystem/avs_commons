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

// NOTE: zlib headers sometimes (depending on a version) contain some of the
// symbols poisoned via inclusion of avs_commons_init.h. Therefore they must
// be included before poison.
#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_HTTP) && defined(AVS_COMMONS_HTTP_WITH_ZLIB)

#    include <zlib.h>

#    include <avs_commons_poison.h>

#    include <errno.h>
#    include <stdint.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_errno_map.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    include "avs_compression.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

#    define GET_INPUT_BUFFER(stream) ((stream)->data)
#    define GET_OUTPUT_BUFFER(stream) \
        ((stream)->data + (stream)->input_buffer_size)

typedef struct {
    const avs_stream_v_table_t *const vtable;
    z_stream zlib;
    int error;
    int flush;
    size_t input_buffer_size;
    size_t output_buffer_size;
    uint8_t data[];
} zlib_stream_t;

/* we don't use opaque field in zlib for allocation data,
 * so we can reuse it for flush function pointer */
#    define FLUSH_FUNC(stream) \
        (((zlib_flush_func_holder_t *) (stream)->zlib.opaque)->flush_func)

typedef struct {
    avs_error_t (*flush_func)(zlib_stream_t *);
} zlib_flush_func_holder_t;

#    define zlib_stream_flush(stream) FLUSH_FUNC(stream)(stream)

static const char *get_zlib_msg(const zlib_stream_t *stream) {
    return stream->zlib.msg ? stream->zlib.msg : "(no message)";
}

static avs_error_t map_zlib_error(int zlib_error) {
    if (zlib_error == Z_ERRNO) {
        return avs_errno(avs_map_errno(errno));
    } else {
        return avs_errno(AVS_EIO);
    }
}

static avs_error_t compressor_flush(zlib_stream_t *stream) {
    stream->error = deflate(&stream->zlib, stream->flush);
    if (stream->error == Z_BUF_ERROR) {
        /* nothing happened, ignore */
        stream->error = Z_OK;
        return AVS_OK;
    }
    if (stream->error != Z_OK && stream->error != Z_STREAM_END) {
        avs_error_t err = map_zlib_error(stream->error);
        LOG(ERROR, _("Compression error (") "%d" _("): ") "%s", stream->error,
            get_zlib_msg(stream));
        return err;
    }
    memmove(GET_INPUT_BUFFER(stream), stream->zlib.next_in,
            stream->zlib.avail_in);
    stream->zlib.next_in = GET_INPUT_BUFFER(stream);
    return AVS_OK;
}

static zlib_flush_func_holder_t compressor_flush_holder = { compressor_flush };

static avs_error_t decompressor_flush(zlib_stream_t *stream) {
    if (stream->error == Z_STREAM_END) {
        return AVS_OK;
    }
    stream->error = inflate(&stream->zlib, stream->flush);
    if (stream->error == Z_BUF_ERROR) {
        /* nothing happened, ignore */
        stream->error = Z_OK;
        return AVS_OK;
    }
    if (stream->error != Z_OK && stream->error != Z_STREAM_END) {
        avs_error_t err = map_zlib_error(stream->error);
        LOG(ERROR, _("Decompression error (") "%d" _("): ") "%s", stream->error,
            get_zlib_msg(stream));
        return err;
    }
    memmove(GET_INPUT_BUFFER(stream), stream->zlib.next_in,
            stream->zlib.avail_in);
    stream->zlib.next_in = GET_INPUT_BUFFER(stream);
    return AVS_OK;
}

static zlib_flush_func_holder_t decompressor_flush_holder = {
    decompressor_flush
};

static avs_error_t zlib_stream_write_some(avs_stream_t *stream_,
                                          const void *data,
                                          size_t *inout_data_length) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (stream->error == Z_STREAM_END || stream->flush != Z_NO_FLUSH) {
        LOG(ERROR, _("Stream finished"));
        return avs_errno(AVS_EBADF);
    }
    if (*inout_data_length
            > stream->input_buffer_size - stream->zlib.avail_in) {
        avs_error_t err = zlib_stream_flush(stream);
        if (avs_is_err(err)) {
            return err;
        }
    }
    if (*inout_data_length
            > stream->input_buffer_size - stream->zlib.avail_in) {
        *inout_data_length = stream->input_buffer_size - stream->zlib.avail_in;
    }
    memcpy(stream->zlib.next_in + stream->zlib.avail_in, data,
           *inout_data_length);
    stream->zlib.avail_in += (unsigned) *inout_data_length;
    return zlib_stream_flush(stream);
}

static size_t zlib_stream_nonblock_write_ready(avs_stream_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (stream->zlib.avail_in > 0 && avs_is_err(zlib_stream_flush(stream))) {
        return 0;
    }
    return stream->input_buffer_size - stream->zlib.avail_in;
}

static avs_error_t zlib_stream_finish_message(avs_stream_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    stream->flush = Z_FINISH;
    return zlib_stream_flush(stream);
}

static avs_error_t zlib_stream_read(avs_stream_t *stream_,
                                    size_t *out_bytes_read,
                                    bool *out_message_finished,
                                    void *buffer,
                                    size_t buffer_length) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    size_t ready_bytes =
            AVS_MIN(buffer_length,
                    stream->output_buffer_size - stream->zlib.avail_out);
    *out_bytes_read = 0;
    *out_message_finished = false;
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
    stream->zlib.next_out =
            GET_OUTPUT_BUFFER(stream)
            + (stream->output_buffer_size - stream->zlib.avail_out);
    if (stream->error == Z_STREAM_END) {
        if (stream->zlib.avail_out >= stream->output_buffer_size) {
            *out_message_finished = true;
        }
    } else if (stream->error != Z_OK) {
        avs_error_t err = map_zlib_error(stream->error);
        LOG(ERROR, _("zlib operation error (") "%d" _("): ") "%s",
            stream->error, get_zlib_msg(stream));
        return err;
    }
    return AVS_OK;
}

static bool zlib_stream_nonblock_read_ready(avs_stream_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (stream->zlib.avail_out < stream->output_buffer_size) {
        return true;
    }
    if (avs_is_err(zlib_stream_flush(stream))) {
        return false;
    }
    return stream->zlib.avail_out < stream->output_buffer_size;
}

static avs_error_t
zlib_stream_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    if (offset > stream->output_buffer_size) {
        LOG(ERROR, _("cannot peek - buffer is too small"));
        return avs_errno(AVS_ENOBUFS);
    }
    if (stream->zlib.avail_out + offset >= stream->output_buffer_size) {
        avs_error_t err = zlib_stream_flush(stream);
        if (avs_is_err(err)) {
            return err;
        }
    }
    if (stream->zlib.avail_out + offset < stream->output_buffer_size) {
        *out_value = ((char *) GET_OUTPUT_BUFFER(stream))[offset];
        return AVS_OK;
    } else {
        return AVS_EOF;
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
        LOG(ERROR, _("buffers cannot be zero-length"));
        return NULL;
    }
    zlib_stream_t *stream = (zlib_stream_t *) avs_calloc(
            1, sizeof(zlib_stream_t) + input_buffer_size + output_buffer_size);
    if (!stream) {
        LOG(ERROR, _("cannot allocate memory"));
        return NULL;
    }
    *(const avs_stream_v_table_t **) (intptr_t) &stream->vtable = vtable;
    stream->input_buffer_size = input_buffer_size;
    stream->output_buffer_size = output_buffer_size;
    stream->zlib.zalloc = zlib_stream_alloc;
    stream->zlib.zfree = zlib_stream_free;
    return stream;
}

static avs_error_t compressor_reset(avs_stream_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    reset_fields(stream);
    stream->error = deflateReset(&stream->zlib);
    if (stream->error != Z_OK) {
        return map_zlib_error(stream->error);
    }
    return AVS_OK;
}

static avs_error_t compressor_close(avs_stream_t *stream) {
    int err = deflateEnd(&((zlib_stream_t *) stream)->zlib);
    if (err != Z_OK) {
        return map_zlib_error(err);
    }
    return AVS_OK;
}

static const avs_stream_v_table_extension_t zlib_vtable_extensions[] = {
    { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
      &(avs_stream_v_table_extension_nonblock_t[]){
              { zlib_stream_nonblock_read_ready,
                zlib_stream_nonblock_write_ready } }[0] },
    AVS_STREAM_V_TABLE_EXTENSION_NULL
};

static const avs_stream_v_table_t compressor_vtable = {
    zlib_stream_write_some, zlib_stream_finish_message, zlib_stream_read,
    zlib_stream_peek,       compressor_reset,           compressor_close,
    zlib_vtable_extensions
};

avs_stream_t *_avs_http_create_compressor(http_compression_format_t format,
                                          int level,
                                          int window_bits,
                                          int mem_level,
                                          size_t input_buffer_size,
                                          size_t output_buffer_size) {
    int result;
    zlib_stream_t *stream =
            zlib_stream_init(&compressor_vtable, input_buffer_size,
                             output_buffer_size);
    if (!stream) {
        return NULL;
    }
    stream->zlib.opaque = &compressor_flush_holder;
    result = deflateInit2(&stream->zlib, level, Z_DEFLATED,
                          window_bits
                                  + (format == HTTP_COMPRESSION_GZIP ? 16 : 0),
                          mem_level, Z_DEFAULT_STRATEGY);
    if (result != Z_OK) {
        LOG(ERROR, _("could not initialize zlib (") "%d" _("): ") "%s", result,
            get_zlib_msg(stream));
        avs_free(stream);
        return NULL;
    }
    reset_fields(stream);
    return (avs_stream_t *) stream;
}

static avs_error_t decompressor_reset(avs_stream_t *stream_) {
    zlib_stream_t *stream = (zlib_stream_t *) stream_;
    reset_fields(stream);
    stream->error = inflateReset(&stream->zlib);
    if (stream->error != Z_OK) {
        return map_zlib_error(stream->error);
    }
    return AVS_OK;
}

static avs_error_t decompressor_close(avs_stream_t *stream) {
    int err = inflateEnd(&((zlib_stream_t *) stream)->zlib);
    if (err != Z_OK) {
        return map_zlib_error(err);
    }
    return AVS_OK;
}

static const avs_stream_v_table_t decompressor_vtable = {
    zlib_stream_write_some, zlib_stream_finish_message, zlib_stream_read,
    zlib_stream_peek,       decompressor_reset,         decompressor_close,
    zlib_vtable_extensions
};

avs_stream_t *_avs_http_create_decompressor(http_compression_format_t format,
                                            int window_bits,
                                            size_t input_buffer_size,
                                            size_t output_buffer_size) {
    int result;
    zlib_stream_t *stream =
            zlib_stream_init(&decompressor_vtable, input_buffer_size,
                             output_buffer_size);
    if (!stream) {
        return NULL;
    }
    stream->zlib.opaque = &decompressor_flush_holder;
    result = inflateInit2(&stream->zlib,
                          window_bits
                                  + (format == HTTP_COMPRESSION_GZIP ? 16 : 0));
    if (result != Z_OK) {
        LOG(ERROR, _("could not initialize zlib (") "%d" _("): ") "%s", result,
            get_zlib_msg(stream));
        avs_free(stream);
        return NULL;
    }
    reset_fields(stream);
    return (avs_stream_t *) stream;
}

#endif // defined(AVS_COMMONS_WITH_AVS_HTTP) &&
       // defined(AVS_COMMONS_HTTP_WITH_ZLIB)
