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

#include <avs_commons_config.h>

#include <string.h>

#include <avsystem/commons/base64.h>
#include <avsystem/commons/utils.h>

#include "../auth.h"
#include "../http_log.h"
#include "../http_stream.h"

VISIBILITY_SOURCE_BEGIN

int _avs_http_auth_send_header_basic(http_stream_t *stream) {
    size_t bufsize = 1; // terminating nullbyte
    if (stream->auth.credentials.user) {
        bufsize += strlen(stream->auth.credentials.user);
    }
    if (stream->auth.credentials.password) {
        bufsize += strlen(stream->auth.credentials.password) + 1;
    }
    size_t encoded_size = avs_base64_encoded_size(bufsize - 1);
    char *plaintext = (char *) malloc(bufsize + encoded_size);
    if (!plaintext) {
        LOG(ERROR, "Out of memory");
        return -1;
    }
    char *encoded = plaintext + bufsize;

    int result = 0;
    if (avs_simple_snprintf(plaintext, bufsize, "%s%s%s",
                            stream->auth.credentials.user
                                    ? stream->auth.credentials.user : "",
                            stream->auth.credentials.password ? ":" : "",
                            stream->auth.credentials.password
                                    ? stream->auth.credentials.password
                                    : "") < 0) {
        result = -1;
    } else if (avs_base64_encode(encoded, encoded_size,
                                 (const uint8_t *) plaintext,
                                 strlen(plaintext))) {
        LOG(ERROR, "Cannot encode authorization data");
        result = -1;
    } else {
        LOG(TRACE, "Basic encoded pass: %s", encoded);
        result = avs_stream_write_f(stream->backend,
                                    "Authorization: Basic %s\r\n", encoded);
    }

    free(plaintext);
    return result;
}
