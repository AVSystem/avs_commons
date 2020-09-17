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

#ifndef AVS_COMMONS_HTTP_CONTENT_ENCODING_H
#define AVS_COMMONS_HTTP_CONTENT_ENCODING_H

#include "avs_http_stream.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

/**
 * Creates a decorator stream that wraps a backend stream and transparently does
 * decoding, using a stream with semantics as described for
 * @ref _avs_http_create_decompressor.
 *
 * <c>avs_stream_t</c> methods are implemented as follows:
 *
 * - <c>avs_stream_read</c> - attempts to read some data from the <c>decoder</c>
 *   stream. If nothing could be read and the stream is not finished, it calls
 *   the "decode more data" procedure. This logic is repeated until there is
 *   data available, the <c>decoder</c> stream reports end of data, or an error
 *   occurs.
 *
 * - <c>avs_stream_peek</c> - calls <c>avs_stream_peek()</c> on the
 *   <c>decoder</c> stream. If it fails, attempts to call the "decode more data"
 *   procedure and retry.
 *
 * The "decode more data" procedure mentioned above attempts to read some data
 * from the <c>backend</c> stream. The read data is then written to the
 * <c>decoder</c> stream, and - if the read on <c>backend</c> reported
 * end-of-data, <c>avs_stream_finish_message()</c> is also called on the
 * <c>decoder</c> stream.
 */
avs_stream_t *
_avs_http_decoding_stream_create(avs_stream_t *backend,
                                 avs_stream_t *decoder,
                                 const avs_http_buffer_sizes_t *buffer_sizes);

/**
 * Calls @ref _avs_http_create_decompressor to create a decompressor stream
 * appropriate for the specified <c>content_encoding</c>.
 */
int _avs_http_content_decoder_create(
        avs_stream_t **out_decoder,
        avs_http_content_encoding_t content_encoding,
        const avs_http_buffer_sizes_t *buffer_sizes);

/**
 * Initializes the <c>encoding</c> field of <c>stream</c>, calling
 * @ref _avs_http_create_compressor if appropriate.
 */
int _avs_http_encoding_init(http_stream_t *stream);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_HTTP_CONTENT_ENCODING_H */
