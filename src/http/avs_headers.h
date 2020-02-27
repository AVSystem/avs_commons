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

#ifndef AVS_COMMONS_HTTP_HEADERS_H
#define AVS_COMMONS_HTTP_HEADERS_H

#include "avs_http_stream.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef enum {
    TRANSFER_IDENTITY,
    TRANSFER_LENGTH,
    TRANSFER_CHUNKED
} http_transfer_encoding_t;

/* length == (size_t) -1 mean chunked encoding */
avs_error_t _avs_http_send_headers(http_stream_t *stream,
                                   size_t content_length);

avs_error_t _avs_http_receive_headers(http_stream_t *stream);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_HTTP_HEADERS_H */
