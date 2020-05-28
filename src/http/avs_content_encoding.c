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

#ifdef AVS_COMMONS_WITH_AVS_HTTP

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    include "avs_client.h"
#    include "avs_compression.h"
#    include "avs_content_encoding.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

#    define HTTP_CONTENT_CODING_OUT_BUF_FACTOR 1.2
#    define HTTP_CONTENT_CODING_OUT_BUF_SIZE(BufferSizes) \
        ((size_t) (HTTP_CONTENT_CODING_OUT_BUF_FACTOR     \
                   * (double) (BufferSizes)->content_coding_input))

typedef struct {
    const avs_stream_v_table_t *const vtable;
    avs_stream_t *backend;
    avs_stream_t *decoder;
    const avs_http_buffer_sizes_t *buffer_sizes;
} decoding_stream_t;

static avs_error_t decode_more_data_with_buffer(decoding_stream_t *stream,
                                                void *buffer,
                                                size_t buffer_length,
                                                bool *out_no_more_data) {
    size_t bytes_read;
    avs_error_t err = avs_stream_read(stream->backend, &bytes_read,
                                      out_no_more_data, buffer, buffer_length);
    if (avs_is_err(err)) {
        return err;
    }
    if ((bytes_read > 0
         && avs_is_err((err = avs_stream_write(stream->decoder, buffer,
                                               bytes_read))))
            || (*out_no_more_data
                && avs_is_err((err = avs_stream_finish_message(
                                       stream->decoder))))) {
        return err;
    }
    return AVS_OK;
}

static avs_error_t decode_more_data(decoding_stream_t *stream,
                                    void *temporary_buffer,
                                    size_t buffer_length,
                                    bool *out_no_more_data) {
    if (buffer_length >= stream->buffer_sizes->content_coding_min_input) {
        return decode_more_data_with_buffer(stream, temporary_buffer,
                                            buffer_length, out_no_more_data);
    } else {
        char *internal_buffer = (char *) avs_malloc(
                stream->buffer_sizes->content_coding_min_input);
        if (!internal_buffer) {
            return avs_errno(AVS_ENOMEM);
        }
        avs_error_t err = decode_more_data_with_buffer(
                stream, internal_buffer,
                stream->buffer_sizes->content_coding_min_input,
                out_no_more_data);
        avs_free(internal_buffer);
        return err;
    }
}

static avs_error_t decoding_read(avs_stream_t *stream_,
                                 size_t *out_bytes_read,
                                 bool *out_message_finished,
                                 void *buffer,
                                 size_t buffer_length) {
    decoding_stream_t *stream = (decoding_stream_t *) stream_;
    bool no_more_data = false;
    while (true) {
        /* try reading remaining data from decoder */
        avs_error_t err =
                avs_stream_read(stream->decoder, out_bytes_read,
                                out_message_finished, buffer, buffer_length);
        if (avs_is_err(err)) {
            return err;
        } else if (*out_bytes_read > 0 || *out_message_finished) {
            return AVS_OK;
        }
        // no_more_data signifies that the underlying stream with *encoded*
        // (compressed) data has been read to the end - but not necessarily
        // decoded; i.e. we have received all the data from the network,
        // buffered it, but not all the data resulting from decompression has
        // been read yet. In that case, the avs_stream_read() above shall be
        // enough for reading everything. If we reach here, it means that there
        // is an error in the decoder implementation.
        assert(!no_more_data);
        // read and decode
        // buffer is used here only as temporary storage;
        // stored data is not used after return from decode_more_data()
        err = decode_more_data(stream, buffer, buffer_length, &no_more_data);
        if (avs_is_err(err)) {
            return err;
        }
    }
}

static bool decoding_nonblock_read_ready(avs_stream_t *stream_) {
    decoding_stream_t *stream = (decoding_stream_t *) stream_;
    bool no_more_data = false;
    avs_error_t err;
    while (avs_is_eof(
            (err = avs_stream_peek(stream->decoder, 0, &(char) { 0 })))) {
        if (!avs_stream_nonblock_read_ready(stream->backend)) {
            return false;
        }
        // this will allocate a temporary buffer inside
        if (avs_is_err(decode_more_data(stream, NULL, 0, &no_more_data))) {
            return false;
        }
        if (no_more_data) {
            return true;
        }
    }
    return avs_is_ok(err);
}

static avs_error_t
decoding_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    decoding_stream_t *stream = (decoding_stream_t *) stream_;
    bool no_more_data = false;
    avs_error_t err;
    while (avs_is_eof(
                   (err = avs_stream_peek(stream->decoder, offset, out_value)))
           && !no_more_data) {
        // this will allocate a temporary buffer inside
        if (avs_is_err(
                    (err = decode_more_data(stream, NULL, 0, &no_more_data)))) {
            break;
        }
    }
    return err;
}

static avs_error_t decoding_close(avs_stream_t *stream_) {
    decoding_stream_t *stream = (decoding_stream_t *) stream_;
    avs_error_t decoder_err, backend_err;
    if (avs_is_err((decoder_err = avs_stream_cleanup(&stream->decoder)))) {
        LOG(ERROR, _("failed to close decoder stream"));
    }
    if (avs_is_err((backend_err = avs_stream_cleanup(&stream->backend)))) {
        LOG(ERROR, _("failed to close backend stream"));
    }
    return avs_is_ok(decoder_err) ? backend_err : decoder_err;
}

static const avs_stream_v_table_t decoding_vtable = {
    .read = decoding_read,
    .peek = decoding_peek,
    .close = decoding_close,
    &(avs_stream_v_table_extension_t[]){
            { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
              &(avs_stream_v_table_extension_nonblock_t[])
                      {
                          {
                              .read_ready = decoding_nonblock_read_ready
                          }
                      }[0] },
            AVS_STREAM_V_TABLE_EXTENSION_NULL }[0]
};

avs_stream_t *
_avs_http_decoding_stream_create(avs_stream_t *backend,
                                 avs_stream_t *decoder,
                                 const avs_http_buffer_sizes_t *buffer_sizes) {
    decoding_stream_t *retval =
            (decoding_stream_t *) avs_malloc(sizeof(*retval));
    LOG(TRACE, _("create_decoding_stream"));
    if (retval) {
        *(const avs_stream_v_table_t **) (intptr_t) &retval->vtable =
                &decoding_vtable;
        retval->backend = backend;
        retval->decoder = decoder;
        retval->buffer_sizes = buffer_sizes;
    }
    return (avs_stream_t *) retval;
}

int _avs_http_content_decoder_create(
        avs_stream_t **out_decoder,
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
        LOG(ERROR, _("'compress' content encoding is not supported"));
        return -1;

    case AVS_HTTP_CONTENT_DEFLATE:
        *out_decoder = _avs_http_create_decompressor(
                HTTP_COMPRESSION_ZLIB, HTTP_DECOMPRESSOR_WINDOW_BITS_DEFAULT,
                buffer_sizes->content_coding_input,
                HTTP_CONTENT_CODING_OUT_BUF_SIZE(buffer_sizes));
        return *out_decoder ? 0 : -1;

    default:
        LOG(ERROR, _("Unknown content encoding"));
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

#endif // AVS_COMMONS_WITH_AVS_HTTP
