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

#    include <assert.h>
#    include <string.h>

#    include <avsystem/commons/avs_stream_net.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_client.h"
#    include "avs_headers.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

static avs_error_t send_common_headers(avs_stream_t *stream,
                                       avs_http_method_t method,
                                       const char *host,
                                       const char *port,
                                       const char *path) {
    assert(host);
    assert(path);
    const int is_ipv6 = !!strchr(host, ':');

    if (!avs_stream_net_getsock(stream)) {
        return avs_errno(AVS_EBADF);
    }
    avs_error_t err;
    (void) (avs_is_err((err = avs_stream_write_f(stream, "%s %s HTTP/1.1\r\n",
                                                 _AVS_HTTP_METHOD_NAMES[method],
                                                 path)))
            || avs_is_err((err = avs_stream_write_f(
                                   stream, "Host: %s%s%s%s%s\r\n",
                                   is_ipv6 ? "[" : "", host, is_ipv6 ? "]" : "",
                                   port ? ":" : "", port ? port : ""))));
    return err;
}

avs_error_t _avs_http_send_headers(http_stream_t *stream,
                                   size_t content_length) {
    stream->status = 0;
    LOG(TRACE, _("http_send_headers"));
    avs_error_t err;
    if (avs_is_err((err = send_common_headers(stream->backend, stream->method,
                                              avs_url_host(stream->url),
                                              avs_url_port(stream->url),
                                              avs_url_path(stream->url))))
#    ifdef AVS_COMMONS_HTTP_WITH_ZLIB
            || (stream->http->buffer_sizes.content_coding_input > 0
                && avs_is_err((err = avs_stream_write_f(
                                       stream->backend,
                                       "Accept-Encoding: gzip, deflate\r\n"))))
#    endif
            || (stream->http->user_agent
                && avs_is_err((
                           err = avs_stream_write_f(stream->backend,
                                                    "User-Agent: %s\r\n",
                                                    stream->http->user_agent))))
            || avs_is_err((err = _avs_http_auth_send_header(stream)))) {
        return err;
    }
    if (stream->http->cookies) {
        bool first_cookie = true;
        AVS_LIST(http_cookie_t) cookie;
        AVS_LIST_FOREACH(cookie, stream->http->cookies) {
            if (avs_is_err(
                        (err = avs_stream_write_f(
                                 stream->backend, "%s%s",
                                 first_cookie
                                         ? (stream->http->use_cookie2
                                                    ? "Cookie: $Version=\"1\"; "
                                                    : "Cookie: ")
                                         : "; ",
                                 cookie->value)))) {
                return err;
            }
            first_cookie = false;
        }
        if (avs_is_err((err = avs_stream_write_f(stream->backend, "\r\n")))) {
            return err;
        }
    }
    AVS_LIST(http_header_t) header;
    AVS_LIST_FOREACH(header, stream->user_headers) {
        if (avs_is_err(
                    (err = avs_stream_write_f(stream->backend, "%s: %s\r\n",
                                              header->key, header->value)))) {
            return err;
        }
    }
    if (content_length == (size_t) -1) {
        if ((!stream->flags.no_expect
             && avs_is_err(
                        (err = avs_stream_write_f(stream->backend,
                                                  "Expect: 100-continue\r\n"))))
                || avs_is_err((err = avs_stream_write_f(
                                       stream->backend,
                                       "Transfer-Encoding: chunked\r\n")))) {
            return err;
        }
    } else if (content_length > 0 || stream->method != AVS_HTTP_GET) {
        char buf[sizeof("Content-Length: \r\n")
                 + AVS_UINT_STR_BUF_SIZE(unsigned long)];
        if (avs_simple_snprintf(buf, sizeof(buf), "Content-Length: %lu\r\n",
                                (unsigned long) content_length)
                < 0) {
            AVS_UNREACHABLE();
        }
        if (avs_is_err((err = avs_stream_write(stream->backend, buf,
                                               strlen(buf))))) {
            return err;
        }
    }
#    ifdef AVS_COMMONS_HTTP_WITH_ZLIB
    if (content_length != 0) {
        switch (stream->encoding) {
        case AVS_HTTP_CONTENT_IDENTITY:
            err = AVS_OK;
            break;
        case AVS_HTTP_CONTENT_GZIP:
            err = avs_stream_write_f(stream->backend,
                                     "Content-Encoding: gzip\r\n");
            break;
        case AVS_HTTP_CONTENT_COMPRESS:
            LOG(ERROR, _("'compress' content encoding is not supported"));
            err = avs_errno(AVS_ENOTSUP);
            break;
        case AVS_HTTP_CONTENT_DEFLATE:
            err = avs_stream_write_f(stream->backend,
                                     "Content-Encoding: deflate\r\n");
            break;
        default:
            LOG(ERROR, _("Unknown content encoding"));
            err = avs_errno(AVS_ENOTSUP);
        }
        if (avs_is_err(err)) {
            return err;
        }
    }
#    endif
    if (avs_is_ok((err = avs_stream_write(stream->backend, "\r\n", 2)))
            && avs_is_ok((err = avs_stream_finish_message(stream->backend)))) {
        LOG(TRACE, _("http_send_headers: success"));
    }
    return err;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
