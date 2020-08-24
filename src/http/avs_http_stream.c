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

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_net.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_chunked.h"
#    include "avs_client.h"
#    include "avs_headers.h"
#    include "avs_http_stream.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

#    define HTTP_MOVE_LIMIT 5

#    ifdef AVS_UNIT_TESTING
#        define avs_net_tcp_socket_create avs_net_tcp_socket_create_TEST_WRAPPER
avs_error_t avs_net_tcp_socket_create_TEST_WRAPPER(avs_net_socket_t **socket,
                                                   ...);

#        define avs_net_ssl_socket_create avs_net_ssl_socket_create_TEST_WRAPPER
avs_error_t avs_net_ssl_socket_create_TEST_WRAPPER(avs_net_socket_t **socket,
                                                   ...);
#    endif

typedef enum {
    HTTP_URI_PROTOCOL_UNKNOWN,
    HTTP_URI_PROTOCOL_HTTP,
    HTTP_URI_PROTOCOL_HTTPS
} http_uri_protocol_t;

static http_uri_protocol_t check_protocol(const char *protocol) {
    if (avs_strcasecmp(protocol, "http") == 0) {
        return HTTP_URI_PROTOCOL_HTTP;
    } else if (avs_strcasecmp(protocol, "https") == 0) {
        return HTTP_URI_PROTOCOL_HTTPS;
    } else {
        LOG(WARNING, _("unknown protocol '") "%s" _("'"), protocol);
        return HTTP_URI_PROTOCOL_UNKNOWN;
    }
}

static const char *default_port_for_protocol(http_uri_protocol_t protocol) {
    switch (protocol) {
    case HTTP_URI_PROTOCOL_HTTP:
        return "80";
    case HTTP_URI_PROTOCOL_HTTPS:
        return "443";
    case HTTP_URI_PROTOCOL_UNKNOWN:
        break;
    }
    return "";
}

static const char *resolve_port(const avs_url_t *parsed_url) {
    const char *port = avs_url_port(parsed_url);
    if (port) {
        return port;
    } else {
        return default_port_for_protocol(
                check_protocol(avs_url_protocol(parsed_url)));
    }
}

avs_error_t _avs_http_socket_new(avs_net_socket_t **out,
                                 avs_http_t *client,
                                 const avs_url_t *url) {
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO
    avs_net_ssl_configuration_t ssl_config_full;
#    else  // AVS_COMMONS_WITH_AVS_CRYPTO
    avs_net_socket_configuration_t tcp_config_full;
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO
    LOG(TRACE, _("http_new_socket"));
    assert(out != NULL);
    *out = NULL;
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO
    if (client->ssl_configuration) {
        ssl_config_full = *client->ssl_configuration;
    } else {
        memset(&ssl_config_full, 0, sizeof(ssl_config_full));
    }
    if (client->tcp_configuration) {
        ssl_config_full.backend_configuration = *client->tcp_configuration;
    }
#    else  // AVS_COMMONS_WITH_AVS_CRYPTO
    if (client->tcp_configuration) {
        tcp_config_full = *client->tcp_configuration;
    } else {
        memset(&tcp_config_full, 0, sizeof(tcp_config_full));
    }
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO
    const char *host = avs_url_host(url);
    const char *port = resolve_port(url);
    avs_error_t err = avs_errno(AVS_EINVAL);
    switch (check_protocol(avs_url_protocol(url))) {
    case HTTP_URI_PROTOCOL_HTTP:
        LOG(TRACE, _("creating TCP socket"));
        err = avs_net_tcp_socket_create(out,
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO
                                        &ssl_config_full.backend_configuration
#    else  // AVS_COMMONS_WITH_AVS_CRYPTO
                                        &tcp_config_full
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO
        );
        break;
    case HTTP_URI_PROTOCOL_HTTPS:
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO
        LOG(TRACE, _("creating SSL socket"));
        if (avs_is_ok((err = avs_net_ssl_socket_create(out, &ssl_config_full)))
                && client->ssl_pre_connect_cb
                && avs_is_err((err = client->ssl_pre_connect_cb(
                                       client, *out, host, port,
                                       client->ssl_pre_connect_cb_arg)))) {
            avs_net_socket_cleanup(out);
        }
        break;
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO
    case HTTP_URI_PROTOCOL_UNKNOWN:
        break;
    }
    if (avs_is_ok(err)) {
        assert(*out);
        LOG(TRACE, _("socket OK, connecting"));
        err = avs_net_socket_connect(*out, host, port);
    }
    if (avs_is_err(err)) {
        avs_net_socket_cleanup(out);
        LOG(ERROR, _("http_new_socket: failure"));
    } else {
        LOG(TRACE, _("http_new_socket: success"));
    }
    return err;
}

static avs_error_t reconnect_tcp_socket(avs_net_socket_t *socket,
                                        const avs_url_t *url) {
    LOG(TRACE, _("reconnect_tcp_socket"));
    if (!socket) {
        LOG(ERROR, _("socket not configured"));
        return avs_errno(AVS_EBADF);
    }
    avs_error_t err;
    if (avs_is_err((err = avs_net_socket_close(socket)))
            || avs_is_err(
                       (err = avs_net_socket_connect(socket, avs_url_host(url),
                                                     resolve_port(url))))) {
        LOG(ERROR, _("reconnect failed"));
        return err;
    }
    return AVS_OK;
}

avs_error_t _avs_http_redirect(http_stream_t *stream, avs_url_t **url_move) {
    assert(stream->status / 100 == 3);
    avs_net_socket_t *old_socket = avs_stream_net_getsock(stream->backend);
    avs_net_socket_t *new_socket = NULL;
    LOG(TRACE, _("http_redirect"));
    ++stream->redirect_count;
    if (stream->redirect_count > HTTP_MOVE_LIMIT) {
        LOG(ERROR, _("redirect count exceeded"));
        avs_error_t err = (avs_error_t) {
            .category = AVS_HTTP_ERROR_CATEGORY,
            .code = (uint16_t) stream->status
        };
        assert(avs_is_err(err));
        return err;
    }
    avs_error_t err = avs_stream_reset(stream->backend);
    if (avs_is_err(err)) {
        LOG(ERROR, _("stream reset failed"));
        return err;
    }
    stream->flags.close_handling_required = 0;
    _avs_http_auth_reset(&stream->auth);
    avs_net_socket_close(old_socket);

    if (avs_is_err((err = _avs_http_socket_new(&new_socket, stream->http,
                                               *url_move)))) {
        return err;
    }

    if (avs_is_err(
                (err = avs_stream_net_setsock(stream->backend, new_socket)))) {
        /* error, clean new socket */
        avs_net_socket_cleanup(&new_socket);
        LOG(ERROR, _("setsock failed"));
        return err;
    }
    avs_net_socket_cleanup(&old_socket);
    avs_url_free(stream->url);
    stream->url = *url_move;
    *url_move = NULL;
    stream->flags.no_expect = 0;
    stream->flags.keep_connection = 1;
    if ((stream->auth.credentials.user || stream->auth.credentials.password)
            && strcmp(avs_url_protocol(stream->url), "https") == 0) {
        stream->auth.state.flags.type = HTTP_AUTH_TYPE_BASIC;
    }
    return AVS_OK;
}

avs_error_t _avs_http_prepare_for_sending(http_stream_t *stream) {
    LOG(TRACE, _("http_prepare_for_sending"));
    stream->flags.should_retry = 0;

    /* check stream state */
    if (stream->body_receiver) {
        /* we might be at the end of stream already */
        bool finished = false;
        avs_error_t err = avs_stream_read(stream->body_receiver, NULL,
                                          &finished, NULL, 0);
        if (avs_is_ok(err) && finished) {
            avs_stream_cleanup(&stream->body_receiver);
            stream->flags.close_handling_required = 1;
        } else {
            LOG(ERROR, _("trying to send while still receiving"));
            return avs_is_ok(err) ? avs_errno(AVS_EBUSY) : err;
        }
    }

    /* reconnect, if keep-alive not set */
    if (!stream->flags.keep_connection) {
        LOG(TRACE, _("reconnecting stream"));
        stream->flags.close_handling_required = 0;
        avs_error_t err;
        if (avs_is_err((err = avs_stream_reset(stream->backend)))
                || avs_is_err((err = reconnect_tcp_socket(
                                       avs_stream_net_getsock(stream->backend),
                                       stream->url)))) {
            return err;
        } else {
            stream->flags.keep_connection = 1;
        }
    }

    LOG(TRACE, _("http_prepare_for_sending: success"));
    return AVS_OK;
}

void _avs_http_maybe_schedule_retry_after_send(http_stream_t *stream,
                                               avs_error_t err) {
    if (err.category == AVS_ERRNO_CATEGORY && err.code == AVS_EPIPE
            && stream->flags.close_handling_required) {
        stream->flags.keep_connection = 0;
        stream->flags.should_retry = 1;
    }
}

static avs_error_t http_send_simple_request(http_stream_t *stream,
                                            const void *buffer,
                                            size_t buffer_length) {
    avs_error_t err;
    LOG(TRACE, _("http_send_simple_request, buffer_length == ") "%lu",
        (unsigned long) buffer_length);
    stream->auth.state.flags.retried = 0;
    do {
        if (avs_is_err((err = _avs_http_prepare_for_sending(stream)))
                || avs_is_err((
                           err = _avs_http_send_headers(stream, buffer_length)))
                || avs_is_err((err = avs_stream_write(stream->backend, buffer,
                                                      buffer_length)))
                || avs_is_err((
                           err = avs_stream_finish_message(stream->backend)))) {
            _avs_http_maybe_schedule_retry_after_send(stream, err);
        } else {
            err = _avs_http_receive_headers(stream);
        }
    } while (avs_is_err(err) && stream->flags.should_retry);
    if (avs_is_ok(err)) {
        AVS_LIST_CLEAR(&stream->user_headers);
    }
    return err;
}

/**
 * Send buffered and encoded block of data. @ref http_send above it does
 * buffering and encoding (i.e. compression). This function could be the public
 * send function if buffering and encoding were not requirements.
 */
static avs_error_t http_send_block(http_stream_t *stream,
                                   bool message_finished,
                                   const void *data,
                                   size_t data_length) {
    avs_error_t err = AVS_OK;
    if (stream->flags.chunked_sending) {
        err = _avs_http_chunked_send(stream, message_finished, data,
                                     data_length);
        if (avs_is_ok(err) && message_finished) {
            stream->flags.chunked_sending = 0;
        }
    } else {
        if (message_finished) {
            err = http_send_simple_request(stream, data, data_length);
        } else {
            err = _avs_http_chunked_send_first(stream, data, data_length);
        }
    }
    return err;
}

avs_error_t _avs_http_buffer_flush(http_stream_t *stream,
                                   bool message_finished) {
    avs_error_t err =
            http_send_block(stream, message_finished, stream->out_buffer,
                            stream->out_buffer_pos);
    if (avs_is_ok(err)) {
        stream->out_buffer_pos = 0;
    }
    return err;
}

avs_error_t _avs_http_send_via_buffer(http_stream_t *stream,
                                      const void *data,
                                      size_t data_length) {
    avs_error_t err = AVS_OK;
    if (data_length > stream->http->buffer_sizes.body_send
                                  - stream->out_buffer_pos
            && avs_is_err((err = _avs_http_buffer_flush(stream, false)))) {
        return err;
    }
    if (data_length > stream->http->buffer_sizes.body_send) {
        err = http_send_block(stream, 0, data, data_length);
    } else {
        memcpy(stream->out_buffer + stream->out_buffer_pos, data, data_length);
        stream->out_buffer_pos += data_length;
    }
    return err;
}

avs_error_t _avs_http_encoder_flush(http_stream_t *stream) {
    char *buffer = (char *) avs_malloc(
            stream->http->buffer_sizes.content_coding_min_input);
    if (!buffer) {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }
    size_t bytes_read = 0;
    bool message_finished = false;
    avs_error_t err;
    while (avs_is_ok((err = avs_stream_read(stream->encoder, &bytes_read,
                                            &message_finished, buffer,
                                            stream->http->buffer_sizes
                                                    .content_coding_min_input)))
           && bytes_read
           && avs_is_ok((err = _avs_http_send_via_buffer(stream, buffer,
                                                         bytes_read)))) {
    }
    avs_free(buffer);
    return err;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
