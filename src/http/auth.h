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

#ifndef AVS_COMMONS_HTTP_AUTH_H
#define AVS_COMMONS_HTTP_AUTH_H

#include <avsystem/commons/avs_http.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

struct http_stream_struct;

typedef enum {
    HTTP_AUTH_TYPE_NONE,
    HTTP_AUTH_TYPE_BASIC,
    HTTP_AUTH_TYPE_DIGEST
} http_auth_type_t;

typedef struct {
    unsigned type : 2; /* actually http_auth_type_t,
                          but enum bitfields are not supported */
    unsigned retried : 1;
    unsigned use_md5_sess : 1;
    unsigned use_qop_auth : 1;
} http_auth_flags_t;

typedef struct {
    char *user;
    char *password;
} http_auth_credentials_t;

typedef struct {
    http_auth_flags_t flags;
    char *nonce;
    uint32_t nc;
    char *realm;
    char *opaque;
} http_auth_state_t;

typedef struct {
    http_auth_credentials_t credentials;
    http_auth_state_t state;
} http_auth_t;

void _avs_http_auth_reset(http_auth_t *auth);

int _avs_http_auth_setup(http_auth_t *auth, const char *challenge);

avs_error_t _avs_http_auth_send_header_basic(struct http_stream_struct *stream);

avs_error_t
_avs_http_auth_send_header_digest(struct http_stream_struct *stream);

avs_error_t _avs_http_auth_send_header(struct http_stream_struct *stream);

int _avs_http_auth_setup_stream(struct http_stream_struct *stream,
                                const avs_url_t *parsed_url,
                                const char *auth_username,
                                const char *auth_password);

void _avs_http_auth_clear(http_auth_t *auth);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_HTTP_AUTH_H */
