/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#include "http_stream.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef enum {
    TRANSFER_IDENTITY,
    TRANSFER_LENGTH,
    TRANSFER_CHUNKED
} http_transfer_encoding_t;

/* length == (size_t) -1 mean chunked encoding */
int _avs_http_send_headers(http_stream_t *stream, size_t content_length);

int _avs_http_receive_headers(http_stream_t *stream);

/**
 * Calculates a number of bytes needed for a decimal string representation of a
 * given unsigned integer type.
 *
 * The number of decimal digits necessary can be calculated as:
 *
 * <pre>
 * D = floor(log10(max(type))) + 1
 * </pre>
 *
 * Also, we know that (for unsigned types):
 *
 * <pre>
 * max(type) == 2^(8*sizeof(type)) - 1
 * </pre>
 *
 * So:
 *
 * <pre>
 * D = floor(log10(2^(8*sizeof(type)) - 1)) + 1
 *   > floor(log10(2^(8*sizeof(type)))) + 1
 *   = floor(log10(2)*8*sizeof(type)) + 1
 *   ~= floor(0.3*8*sizeof(type)) + 1
 *   = floor((12/5)*sizeof(type)) + 1
 * </pre>
 *
 * We add an extra character for terminating null byte.
 */
#define UINT_STR_BUF_SIZE(type) ((12*sizeof(type))/5 + 2)

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_HTTP_HEADERS_H */
