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

#include <avsystem/commons/memory.h>
#include <avsystem/commons/stream_v_table.h>

#include "zlib.h"

#include "client.h"
#include "content_encoding.h"
#include "http_log.h"

VISIBILITY_SOURCE_BEGIN

#define HTTP_CONTENT_CODING_OUT_BUF_FACTOR 1.2
#define HTTP_CONTENT_CODING_OUT_BUF_SIZE(BufferSizes) \
    ((size_t) (HTTP_CONTENT_CODING_OUT_BUF_FACTOR     \
               * (double) (BufferSizes)->content_coding_input))

typedef struct {
    const avs_stream_v_table_t *const vtable;
    avs_stream_abstract_t *backend;
    avs_stream_abstract_t *decoder;
    const avs_http_buffer_sizes_t *buffer_sizes;
    avs_errno_t error;
} decoding_stream_t;

static int decode_more_data_with_buffer(decoding_stream_t *stream,
                                        void *buffer,
                                        size_t buffer_length,
                                        char *out_no_more_data) {
    size_t bytes_read;
    stream->error = AVS_NO_ERROR;
    if (avs_stream_read(stream->backend, &bytes_read, out_no_more_data, buffer,
                        buffer_length)) {
        stream->error = AVS_EIO;
        return -1;
    }
    if ((bytes_read > 0
         && avs_stream_write(stream->decoder, buffer, bytes_read))
            || (*out_no_more_data
                && avs_stream_finish_message(stream->decoder))) {
        stream->error = AVS_EIO;
        return -1;
    }
    return 0;
}

static int decode_more_data(decoding_stream_t *stream,
                            void *temporary_buffer,
                            size_t buffer_length,
                            char *out_no_more_data) {
    if (buffer_length >= stream->buffer_sizes->content_coding_min_input) {
        return decode_more_data_with_buffer(stream, temporary_buffer,
                                            buffer_length, out_no_more_data);
    } else {
        char *internal_buffer = (char *) avs_malloc(
                stream->buffer_sizes->content_coding_min_input);
        if (!internal_buffer) {
            return -1;
        }
        int result = decode_more_data_with_buffer(
                stream, internal_buffer,
                stream->buffer_sizes->content_coding_min_input,
                out_no_more_data);
        avs_free(internal_buffer);
        return result;
    }
}

static int decoding_read(avs_stream_abstract_t *stream_,
                         size_t *out_bytes_read,
                         char *out_message_finished,
                         void *buffer,
                         size_t buffer_length) {
    decoding_stream_t *stream = (decoding_stream_t *) stream_;
    char no_more_data = 0;
    while (1) {
        stream->error = AVS_NO_ERROR;
        /* try reading remaining data from decoder */
        int result =
                avs_stream_read(stream->decoder, out_bytes_read,
                                out_message_finished, buffer, buffer_length);
        if (result || *out_bytes_read > 0 || *out_message_finished) {
            if (result) {
                stream->error = AVS_EIO;
            }
            return result;
        }
        /* read and decode */
        /* buffer is used here only as temporary storage;
         * stored data is not used after return from decode_more_data() */
        if (no_more_data
                || decode_more_data(stream, buffer, buffer_length,
                                    &no_more_data)) {
            return -1;
        }
    }
}

static int decoding_nonblock_read_ready(avs_stream_abstract_t *stream_) {
    decoding_stream_t *stream = (decoding_stream_t *) stream_;
    char no_more_data = 0;
    while (avs_stream_peek(stream->decoder, 0) == EOF) {
        int result = avs_stream_nonblock_read_ready(stream->backend);
        if (result <= 0) {
            return result;
        }
        // this will allocate a temporary buffer inside
        if ((result = decode_more_data(stream, NULL, 0, &no_more_data))) {
            return result < 0 ? result : -1;
        }
        if (no_more_data) {
            return 1;
        }
    }
    return 1;
}

static int decoding_peek(avs_stream_abstract_t *stream_, size_t offset) {
    decoding_stream_t *stream = (decoding_stream_t *) stream_;
    char no_more_data = 0;
    int result = avs_stream_peek(stream->decoder, offset);
    while (result == EOF && !no_more_data) {
        // this will allocate a temporary buffer inside
        if (decode_more_data(stream, NULL, 0, &no_more_data)) {
            return EOF;
        }
        result = avs_stream_peek(stream->decoder, offset);
    }
    stream->error = AVS_NO_ERROR;
    return result;
}

static int decoding_close(avs_stream_abstract_t *stream_) {
    decoding_stream_t *stream = (decoding_stream_t *) stream_;
    int retval = 0;
    if (avs_stream_cleanup(&stream->decoder)) {
        LOG(ERROR, "failed to close decoder stream");
        retval = -1;
    }
    if (avs_stream_cleanup(&stream->backend)) {
        LOG(ERROR, "failed to close backend stream");
        retval = -1;
    }
    return retval;
}

static avs_errno_t decoding_error(avs_stream_abstract_t *stream) {
    return ((decoding_stream_t *) stream)->error;
}

static int unimplemented() {
    LOG(ERROR, "Vtable method unimplemented");
    return -1;
}

static const avs_stream_v_table_t decoding_vtable = {
    (avs_stream_write_some_t) unimplemented,
    (avs_stream_finish_message_t) unimplemented,
    decoding_read,
    decoding_peek,
    (avs_stream_reset_t) unimplemented,
    decoding_close,
    decoding_error,
    &(avs_stream_v_table_extension_t[]){
            { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
              &(avs_stream_v_table_extension_nonblock_t[]){
                      { decoding_nonblock_read_ready,
                        (avs_stream_nonblock_write_ready_t)
                                unimplemented } }[0] },
            AVS_STREAM_V_TABLE_EXTENSION_NULL }[0]
};

avs_stream_abstract_t *
_avs_http_decoding_stream_create(avs_stream_abstract_t *backend,
                                 avs_stream_abstract_t *decoder,
                                 const avs_http_buffer_sizes_t *buffer_sizes) {
    decoding_stream_t *retval =
            (decoding_stream_t *) avs_malloc(sizeof(*retval));
    LOG(TRACE, "create_decoding_stream");
    if (retval) {
        *(const avs_stream_v_table_t **) (intptr_t) &retval->vtable =
                &decoding_vtable;
        retval->backend = backend;
        retval->decoder = decoder;
        retval->buffer_sizes = buffer_sizes;
    }
    return (avs_stream_abstract_t *) retval;
}

int _avs_http_content_decoder_create(
        avs_stream_abstract_t **out_decoder,
        avs_http_content_encoding_t content_encoding,
        const avs_http_buffer_sizes_t *buffer_sizes) {
    (void) buffer_sizes;
    *out_decoder = NULL;
    switch (content_encoding) {
    case AVS_HTTP_CONTENT_IDENTITY:
        return 0;

    case AVS_HTTP_CONTENT_GZIP:
        *out_decoder = _avs_http_create_decompressor(
                HTTP_COMPRESSION_GZIP, HTTP_DECOMPRESSOR_WINDOW_BITS_DEFAULT,
                buffer_sizes->content_coding_input,
                HTTP_CONTENT_CODING_OUT_BUF_SIZE(buffer_sizes));
        return *out_decoder ? 0 : -1;

    case AVS_HTTP_CONTENT_COMPRESS:
        LOG(ERROR, "'compress' content encoding is not supported");
        return -1;

    case AVS_HTTP_CONTENT_DEFLATE:
        *out_decoder = _avs_http_create_decompressor(
                HTTP_COMPRESSION_ZLIB, HTTP_DECOMPRESSOR_WINDOW_BITS_DEFAULT,
                buffer_sizes->content_coding_input,
                HTTP_CONTENT_CODING_OUT_BUF_SIZE(buffer_sizes));
        return *out_decoder ? 0 : -1;

    default:
        LOG(ERROR, "Unknown content encoding");
        return -1;
    }
}

int _avs_http_encoding_init(http_stream_t *stream) {
    if (stream->encoding == AVS_HTTP_CONTENT_IDENTITY) {
        /* no encoding */
        return 0;
    }
    stream->encoder = _avs_http_create_compressor(
            stream->encoding == AVS_HTTP_CONTENT_GZIP ? HTTP_COMPRESSION_GZIP
                                                      : HTTP_COMPRESSION_ZLIB,
            HTTP_COMPRESSOR_LEVEL_DEFAULT, HTTP_COMPRESSOR_WINDOW_BITS_DEFAULT,
            HTTP_COMPRESSOR_MEM_LEVEL_DEFAULT,
            stream->http->buffer_sizes.content_coding_input,
            HTTP_CONTENT_CODING_OUT_BUF_SIZE(&stream->http->buffer_sizes));
    return stream->encoder ? 0 : -1;
}
