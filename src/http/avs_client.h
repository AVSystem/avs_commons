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

#ifndef AVS_COMMONS_HTTP_CLIENT_H
#define AVS_COMMONS_HTTP_CLIENT_H

#include <avsystem/commons/avs_http.h>
#include <avsystem/commons/avs_list.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef struct {
    char value[1]; // actually a FAM
} http_cookie_t;

struct avs_http {
    avs_http_buffer_sizes_t buffer_sizes;

    /* Cookies management */
    AVS_LIST(http_cookie_t) cookies;
    bool use_cookie2;

    char *user_agent;

    avs_http_ssl_pre_connect_cb_t *ssl_pre_connect_cb;
    void *ssl_pre_connect_cb_arg;

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO
    const volatile avs_net_ssl_configuration_t *ssl_configuration;
#endif // AVS_COMMONS_WITH_AVS_CRYPTO
    const volatile avs_net_socket_configuration_t *tcp_configuration;
};

extern const char *const _AVS_HTTP_METHOD_NAMES[];

int _avs_http_set_cookie(avs_http_t *client,
                         bool use_cookie2,
                         const char *cookie_header);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_HTTP_CLIENT_H */
