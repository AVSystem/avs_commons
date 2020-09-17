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

#ifndef AVS_COMMONS_HTTP_COMPRESSION_H
#define AVS_COMMONS_HTTP_COMPRESSION_H

#include <avsystem/commons/avs_stream.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef enum {
    HTTP_COMPRESSION_ZLIB,
    HTTP_COMPRESSION_GZIP
} http_compression_format_t;

#define HTTP_COMPRESSOR_LEVEL_MIN 0
#define HTTP_COMPRESSOR_LEVEL_MAX 9
#define HTTP_COMPRESSOR_LEVEL_DEFAULT 6

#define HTTP_COMPRESSOR_WINDOW_BITS_MIN 8
#define HTTP_COMPRESSOR_WINDOW_BITS_MAX 15
#define HTTP_COMPRESSOR_WINDOW_BITS_DEFAULT 15

#define HTTP_COMPRESSOR_MEM_LEVEL_MIN 1
#define HTTP_COMPRESSOR_MEM_LEVEL_MAX 9
#define HTTP_COMPRESSOR_MEM_LEVEL_DEFAULT 8

#define HTTP_DECOMPRESSOR_WINDOW_BITS_MIN HTTP_COMPRESSOR_WINDOW_BITS_MIN
#define HTTP_DECOMPRESSOR_WINDOW_BITS_MAX HTTP_COMPRESSOR_WINDOW_BITS_MAX
#define HTTP_DECOMPRESSOR_WINDOW_BITS_DEFAULT \
    HTTP_COMPRESSOR_WINDOW_BITS_DEFAULT

#ifdef AVS_COMMONS_HTTP_WITH_ZLIB

/**
 * Creates a zlib-based compressor stream.
 *
 * This is <strong>NOT</strong> a decorator. The basic semantics of this stream
 * are that the user will write uncompressed data to it, which will then make
 * equivalent compressed data available to read.
 *
 * <c>avs_stream_t</c> methods are implemented as follows:
 *
 * - <c>avs_stream_write</c> - passes some uncompressed data to the compression
 *   engine. It may or may not make some equivalent compressed data available to
 *   retrieve, depending on the compression algorithm's properties. If there is
 *   no compressed data available to retrieve, it means that the compression
 *   algorithm is waiting for more input.
 *
 *   Note that when there is not enough space available in the input buffer for
 *   the data to be written, the call will fail. Amount of space available is
 *   dependent on the compression algorithm and not easily determinable. For
 *   this reason, it is recommended to write data in small chunks.
 *
 *   In particular, attempting to write more data than <c>input_buffer_size</c>
 *   will always result in an error.
 *
 * - <c>avs_stream_finish_message</c> - signifies the end of input data. After
 *   calling it, the final part of the compressed data can be read from the
 *   stream.
 *
 * - <c>avs_stream_read</c> - reads the compressed data equivalent to part or
 *   entirety of the uncompressed data earlier pushed via
 *   <c>avs_stream_write()</c>.
 *
 * - <c>avs_stream_peek</c> - reads a single byte from the compressed data
 *   without consuming it. The possible peek range is limited by
 *   <c>output_buffer_size</c>, but may be less if not enough uncompressed data
 *   was previously written for the compression algorith to produce the desired
 *   amount of compressed data.
 *
 * - <c>avs_stream_reset</c> - clears the buffers and the state of the
 *   compression algorithm, allowing to compress a new stream.
 */
avs_stream_t *_avs_http_create_compressor(http_compression_format_t format,
                                          int level,
                                          int window_bits,
                                          int mem_level,
                                          size_t input_buffer_size,
                                          size_t output_buffer_size);

/**
 * Creates a zlib-based decompressor stream.
 *
 * This is <strong>NOT</strong> a decorator. The basic semantics of this stream
 * are that the user will write compressed data to it, which will then make
 * equivalent uncompressed data available to read.
 *
 * <c>avs_stream_t</c> methods are implemented in the same way as for
 * @ref _avs_http_create_compressor, but with the "compressed" and
 * "uncompressed" kinds of data reversed.
 */
avs_stream_t *_avs_http_create_decompressor(http_compression_format_t format,
                                            int window_bits,
                                            size_t input_buffer_size,
                                            size_t output_buffer_size);

#else

#    define _avs_http_create_compressor(format,             \
                                        level,              \
                                        window_bits,        \
                                        mem_level,          \
                                        input_buffer_size,  \
                                        output_buffer_size) \
        (NULL)

#    define _avs_http_create_decompressor(                              \
            format, window_bits, input_buffer_size, output_buffer_size) \
        (NULL)

#endif

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_HTTP_COMPRESSION_H */
