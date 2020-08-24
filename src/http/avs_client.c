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

#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_client.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

const avs_http_buffer_sizes_t AVS_HTTP_DEFAULT_BUFFER_SIZES = {
    .body_recv = 4096,
    .body_send = 4096,
#    ifdef AVS_COMMONS_HTTP_WITH_ZLIB
    .content_coding_input = 4096,
    .content_coding_min_input = 128,
#    endif
    .header_line = 512,
    .recv_shaper = 128,
    .send_shaper = 128
};

const char *const _AVS_HTTP_METHOD_NAMES[] = { "GET", "POST", "PUT" };

avs_http_t *avs_http_new(const avs_http_buffer_sizes_t *buffer_sizes) {
    avs_http_t *result = (avs_http_t *) avs_calloc(1, sizeof(avs_http_t));
    if (!result) {
        LOG(ERROR, _("Out of memory"));
        return NULL;
    }
    result->buffer_sizes = *buffer_sizes;
    return result;
}

void avs_http_free(avs_http_t *http) {
    if (http) {
        avs_http_clear_cookies(http);
        avs_free(http->user_agent);
        avs_free(http);
    }
}

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO
void avs_http_ssl_configuration(
        avs_http_t *http,
        const volatile avs_net_ssl_configuration_t *ssl_configuration) {
    http->ssl_configuration = ssl_configuration;
}
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO

void avs_http_ssl_pre_connect_cb(avs_http_t *http,
                                 avs_http_ssl_pre_connect_cb_t *cb,
                                 void *user_ptr) {
    http->ssl_pre_connect_cb = cb;
    http->ssl_pre_connect_cb_arg = user_ptr;
}

void avs_http_tcp_configuration(
        avs_http_t *http,
        const volatile avs_net_socket_configuration_t *tcp_configuration) {
    http->tcp_configuration = tcp_configuration;
}

int avs_http_set_user_agent(avs_http_t *http, const char *user_agent) {
    char *new_user_agent = NULL;
    if (user_agent) {
        if (!(new_user_agent = avs_strdup(user_agent))) {
            LOG(ERROR, _("Out of memory"));
            return -1;
        }
    }
    avs_free(http->user_agent);
    http->user_agent = new_user_agent;
    return 0;
}

void avs_http_clear_cookies(avs_http_t *http) {
    AVS_LIST_CLEAR(&http->cookies);
    http->use_cookie2 = false;
}

int _avs_http_set_cookie(avs_http_t *client,
                         bool use_cookie2,
                         const char *cookie_header) {
    const char *equal_sign = strchr(cookie_header, '=');
    const char *end = strchr(cookie_header, ';');
    LOG(TRACE, _("Set-Cookie") "%s" _(": ") "%s", use_cookie2 ? "2" : "",
        cookie_header);
    if (!equal_sign) {
        LOG(ERROR, _("Invalid cookie format: ") "%s", cookie_header);
        return -1;
    }
    if (!end) { /* no semicolon; read to the end */
        end = cookie_header + strlen(cookie_header);
    }

    // remove old cookie, if any
    AVS_LIST(http_cookie_t) *it;
    AVS_LIST_FOREACH_PTR(it, &client->cookies) {
        if (strncmp((*it)->value, cookie_header,
                    (size_t) (equal_sign + 1 - cookie_header))
                == 0) {
            AVS_LIST_DELETE(it);
            break;
        }
    }
    // it now points either at the place of the old cookie, or at the tail

    if (!AVS_LIST_INSERT(it, (AVS_LIST(http_cookie_t)) AVS_LIST_NEW_BUFFER(
                                     (size_t) ((end - cookie_header) + 1)))) {
        LOG(ERROR, _("Not enough space to store the cookie"));
        return -1;
    }
    memcpy((*it)->value, cookie_header, (size_t) (end - cookie_header));
    (*it)->value[end - cookie_header] = '\0';
    client->use_cookie2 = use_cookie2;
    return 0;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
