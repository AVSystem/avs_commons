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

#ifndef AVS_COMMONS_HTTP_BODY_RECEIVERS_H
#define AVS_COMMONS_HTTP_BODY_RECEIVERS_H

#include "avs_headers.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

/**
 * Creates a "dumb" body receiver, appropriate for the "identity" transfer
 * encoding.
 *
 * This body receiver can be read from until the underlying TCP connection is
 * not closed by the remote party.
 *
 * @param backend The netbuf stream wrapping the TCP socket.
 */
avs_stream_t *_avs_http_body_receiver_dumb_create(avs_stream_t *backend);

/**
 * Creates a body receiver appropriate for when a Content-Length has been
 * specified.
 *
 * This body receiver can be read from until <c>content_length</c> bytes have
 * been consumed.
 *
 * @param backend        The netbuf stream wrapping the TCP socket.
 * @param content_length Limit of the number of bytes to consume.
 */
avs_stream_t *
_avs_http_body_receiver_content_length_create(avs_stream_t *backend,
                                              size_t content_length);

/**
 * Creates a body receiver that decodes HTTP chunked encoding.
 *
 * This body receiver keeps tracks of the received chunked headers, and allows
 * reading until a zero-length chunk is received.
 *
 * @param backend        The netbuf stream wrapping the TCP socket.
 * @param buffer_sizes   Pointer to buffer sizes used by this HTTP client.
 *                       The pointer must remain valid for the lifetime of the
 *                       created object.
 */
avs_stream_t *_avs_http_body_receiver_chunked_create(
        avs_stream_t *backend, const avs_http_buffer_sizes_t *buffer_sizes);

/**
 * Puts the HTTP stream in a receiving state, filling the <c>body_receiver</c>
 * field with a newly created body receiver.
 *
 * There are three kinds of body receivers appropriate for three kinds of
 * transfer encoding; see the functions above for details. Also note that if the
 * received status code is 204 or 205, it will behave as if "Content-Length: 0"
 * header is present, even if none has actually been received.
 *
 * If <c>content_encoding</c> is not <c>HTTP_CONTENT_IDENTITY</c>, the created
 * body receiver will also be wrapped in a decompressing decorator. See
 * @ref _avs_http_decoding_stream_create for details on that.
 */
int _avs_http_body_receiver_init(http_stream_t *stream,
                                 http_transfer_encoding_t transfer_encoding,
                                 avs_http_content_encoding_t content_encoding,
                                 size_t content_length);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_HTTP_BODY_RECEIVERS_H */
