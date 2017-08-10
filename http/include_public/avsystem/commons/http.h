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

#ifndef AVS_COMMONS_HTTP_H
#define AVS_COMMONS_HTTP_H

#include <avsystem/commons/net.h>
#include <avsystem/commons/stream.h>
#include <avsystem/commons/url.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
    size_t body_recv;
    size_t body_send;
    size_t content_coding_input;
    size_t content_coding_min_input;
    size_t header_line;
    size_t recv_shaper;
    size_t send_shaper;
} avs_http_buffer_sizes_t;

extern const avs_http_buffer_sizes_t AVS_HTTP_DEFAULT_BUFFER_SIZES;

typedef enum {
    AVS_HTTP_GET, AVS_HTTP_POST, AVS_HTTP_PUT
} avs_http_method_t;

typedef enum {
    AVS_HTTP_CONTENT_IDENTITY,
    AVS_HTTP_CONTENT_GZIP,
    AVS_HTTP_CONTENT_COMPRESS,
    AVS_HTTP_CONTENT_DEFLATE
} avs_http_content_encoding_t;

typedef enum {
    AVS_HTTP_ERROR_GENERAL = -1,
    AVS_HTTP_ERROR_TOO_MANY_REDIRECTS = -2
} avs_http_error_t;

struct avs_http;
typedef struct avs_http avs_http_t;

avs_http_t *avs_http_new(const avs_http_buffer_sizes_t *buffer_sizes);

void avs_http_free(avs_http_t *http);

void avs_http_ssl_configuration(
        avs_http_t *http,
        const volatile avs_net_ssl_configuration_t *ssl_configuration);

void avs_http_tcp_configuration(
        avs_http_t* http,
        const volatile avs_net_socket_configuration_t *tcp_configuration);

int avs_http_set_user_agent(avs_http_t *http, const char *user_agent);

int avs_http_open_stream(avs_stream_abstract_t **out,
                         avs_http_t *http,
                         avs_http_method_t method,
                         avs_http_content_encoding_t encoding,
                         const avs_url_t *parsed_url,
                         const char *auth_username,
                         const char *auth_password);

void avs_http_clear_cookies(avs_http_t *http);

int avs_http_add_header(avs_stream_abstract_t *stream,
                        const char *key, const char *value);

int avs_http_should_retry(avs_stream_abstract_t *stream);

#define AVS_HTTP_ERRNO_BACKEND (-0xEE0)
#define AVS_HTTP_ERRNO_DECODER 499

int avs_http_status_code(avs_stream_abstract_t *stream);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_HTTP_H */
