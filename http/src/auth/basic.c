/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#include <config.h>

#include <assert.h>
#include <string.h>

#include <avsystem/commons/base64.h>
#include <avsystem/commons/utils.h>

#include "../auth.h"
#include "../log.h"
#include "../stream.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

int _avs_http_auth_send_header_basic(http_stream_t *stream) {
    size_t bufsize = 1; // terminating nullbyte
    if (stream->auth.credentials.user) {
        bufsize += strlen(stream->auth.credentials.user);
    }
    if (stream->auth.credentials.password) {
        bufsize += strlen(stream->auth.credentials.password) + 1;
    }
    char plaintext[bufsize];
    size_t encoded_size = avs_base64_encoded_size(sizeof(plaintext));
    assert(encoded_size <= 4 * sizeof(plaintext));
    char encoded[encoded_size];

    if (avs_simple_snprintf(plaintext, sizeof(plaintext), "%s%s%s",
                            stream->auth.credentials.user
                                    ? stream->auth.credentials.user : "",
                            stream->auth.credentials.password ? ":" : "",
                            stream->auth.credentials.password
                                    ? stream->auth.credentials.password
                                    : "") < 0) {
        return -1;
    }
    if (avs_base64_encode(encoded, sizeof(encoded), (const uint8_t *) plaintext,
                          strlen(plaintext))) {
        LOG(ERROR, "Cannot encode authorization data");
        return -1;
    }
    LOG(TRACE, "Basic encoded pass: %s", encoded);

    return avs_stream_write_f(stream->backend,
                              "Authorization: Basic %s\r\n", encoded);
}
