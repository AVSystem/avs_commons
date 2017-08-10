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

#include <string.h>

#include <avsystem/commons/stream/net.h>
#include <avsystem/commons/utils.h>

#include "client.h"
#include "headers.h"
#include "log.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

static int send_common_headers(avs_stream_abstract_t *stream,
                               avs_http_method_t method,
                               const char *host,
                               const char *port,
                               const char *path) {
    avs_net_abstract_socket_t *socket = NULL;
    int is_ipv6 = !!strchr(host, ':');

    return !(socket = avs_stream_net_getsock(stream))
            || avs_stream_write_f(stream, "%s %s HTTP/1.1\r\n",
                                  _AVS_HTTP_METHOD_NAMES[method], path)
            || avs_stream_write_f(stream, "Host: %s%s%s%s%s\r\n",
                                  is_ipv6 ? "[" : "", host,
                                  is_ipv6 ? "]" : "",
                                  port ? ":" : "", port ? port : "");
}

int _avs_http_send_headers(http_stream_t *stream, size_t content_length) {
    stream->status = 0;
    LOG(TRACE, "http_send_headers");
    if (send_common_headers(stream->backend, stream->method,
                            avs_url_host(stream->url),
                            avs_url_port(stream->url),
                            avs_url_path(stream->url))
#ifdef WITH_AVS_HTTP_ZLIB
            || (stream->http->buffer_sizes.content_coding_input > 0
                    && avs_stream_write_f(stream->backend,
                                          "Accept-Encoding: gzip, deflate\r\n"))
#endif
            || (stream->http->user_agent
                    && avs_stream_write_f(stream->backend, "User-Agent: %s\r\n",
                                          stream->http->user_agent))
            || _avs_http_auth_send_header(stream)) {
        return -1;
    }
    AVS_LIST(http_cookie_t) cookie;
    AVS_LIST_FOREACH(cookie, stream->http->cookies) {
        if (avs_stream_write_f(stream->backend, "Cookie: %s%s\r\n",
                               stream->http->use_cookie2
                                       ? "$Version=\"1\";" : "",
                               cookie->value)) {
            return -1;
        }
    }
    AVS_LIST(http_header_t) header;
    AVS_LIST_FOREACH(header, stream->user_headers) {
        if (avs_stream_write_f(stream->backend, "%s: %s\r\n",
                               header->key, header->value)) {
            return -1;
        }
    }
    if (content_length == (size_t) -1) {
        if ((!stream->flags.no_expect
                        && avs_stream_write_f(stream->backend,
                                              "Expect: 100-continue\r\n"))
                || avs_stream_write_f(stream->backend,
                                      "Transfer-Encoding: chunked\r\n")) {
            return -1;
        }
    } else if (content_length > 0 || stream->method != AVS_HTTP_GET) {
        char buf[sizeof("Content-Length: \r\n")
                         + UINT_STR_BUF_SIZE(unsigned long)];
        if (avs_simple_snprintf(buf, sizeof(buf), "Content-Length: %lu\r\n",
                                (unsigned long) content_length) < 0
                || avs_stream_write(stream->backend, buf, strlen(buf))) {
            return -1;
        }
    }
#ifdef WITH_AVS_HTTP_ZLIB
    if (content_length != 0) {
        int result;
        switch (stream->encoding) {
        case AVS_HTTP_CONTENT_IDENTITY:
            result = 0;
            break;
        case AVS_HTTP_CONTENT_GZIP:
            result = avs_stream_write_f(stream->backend,
                                        "Content-Encoding: gzip\r\n");
            break;
        case AVS_HTTP_CONTENT_COMPRESS:
            LOG(ERROR, "'compress' content encoding is not supported");
            result = -1;
            break;
        case AVS_HTTP_CONTENT_DEFLATE:
            result = avs_stream_write_f(stream->backend,
                                        "Content-Encoding: deflate\r\n");
            break;
        default:
            LOG(ERROR, "Unknown content encoding");
            result = -1;
        }
        if (result) {
            return -1;
        }
    }
#endif
    if (avs_stream_write(stream->backend, "\r\n", 2)
            || avs_stream_finish_message(stream->backend)) {
        return -1;
    }
    LOG(TRACE, "http_send_headers: success");
    return 0;
}
