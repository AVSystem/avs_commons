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
#include <errno.h>
#include <string.h>

#include <avsystem/commons/stream/stream_net.h>

#include "chunked.h"
#include "client.h"
#include "headers.h"
#include "http_log.h"
#include "http_stream.h"

VISIBILITY_SOURCE_BEGIN

#define HTTP_MOVE_LIMIT 5

#ifdef AVS_UNIT_TESTING
#define avs_net_socket_create avs_net_socket_create_TEST_WRAPPER
int avs_net_socket_create_TEST_WRAPPER(avs_net_abstract_socket_t **socket,
                                       avs_net_socket_type_t type, ...);
#endif

static const char *default_port_for_protocol(const char *protocol) {
    if (strcmp(protocol, "http") == 0) {
        return "80";
    } else if (strcmp(protocol, "https") == 0) {
        return "443";
    } else {
        LOG(WARNING, "unknown protocol '%s'", protocol);
        return "";
    }
}

static const char *resolve_port(const avs_url_t *parsed_url) {
    const char *port = avs_url_port(parsed_url);
    if (port) {
        return port;
    } else {
        return default_port_for_protocol(avs_url_protocol(parsed_url));
    }
}

int _avs_http_socket_new(avs_net_abstract_socket_t **out,
                         avs_http_t *client,
                         const avs_url_t *url) {
    int result = 0;
    avs_net_ssl_configuration_t ssl_config_full;
    LOG(TRACE, "http_new_socket");
    assert(out != NULL);
    *out = NULL;
    if (client->ssl_configuration) {
        ssl_config_full = *client->ssl_configuration;
    } else {
        memset(&ssl_config_full, 0, sizeof(ssl_config_full));
    }
    if (client->tcp_configuration) {
        ssl_config_full.backend_configuration = *client->tcp_configuration;
    }
    const char *protocol = avs_url_protocol(url);
    if (strcmp(protocol, "http") == 0) {
        LOG(TRACE, "creating TCP socket");
        result = avs_net_socket_create(out, AVS_NET_TCP_SOCKET,
                                       &ssl_config_full.backend_configuration);
    } else if (strcmp(protocol, "https") == 0) {
        LOG(TRACE, "creating SSL socket");
        result = avs_net_socket_create(out, AVS_NET_SSL_SOCKET,
                                       &ssl_config_full);
    }
    if (!result) {
        LOG(TRACE, "socket OK, connecting");
        if (avs_net_socket_connect(*out,
                                   avs_url_host(url), resolve_port(url))) {
            result = errno ? errno : -1;
        }
    }
    if (result) {
        LOG(ERROR, "http_new_socket: failure: %d", result);
        avs_net_socket_cleanup(out);
    } else {
        LOG(TRACE, "http_new_socket: success");
    }
    return result;
}

static int reconnect_tcp_socket(avs_net_abstract_socket_t *socket,
                                const avs_url_t *url) {
    LOG(TRACE, "reconnect_tcp_socket");
    if (!socket
            || avs_net_socket_close(socket)
            || avs_net_socket_connect(socket,
                                      avs_url_host(url), resolve_port(url))) {
        LOG(ERROR, "reconnect failed");
        return -1;
    }
    return 0;
}

int _avs_http_redirect(http_stream_t *stream, avs_url_t **url_move) {
    avs_net_abstract_socket_t *old_socket =
            avs_stream_net_getsock(stream->backend);
    avs_net_abstract_socket_t *new_socket = NULL;
    int result = 0;
    LOG(TRACE, "http_redirect");
    ++stream->redirect_count;
    if (stream->redirect_count > HTTP_MOVE_LIMIT) {
        LOG(ERROR, "redirect count exceeded");
        return AVS_HTTP_ERROR_TOO_MANY_REDIRECTS;
    }
    if (avs_stream_reset(stream->backend)) {
        LOG(ERROR, "stream reset failed");
        return -1;
    }
    _avs_http_auth_reset(&stream->auth);
    avs_net_socket_close(old_socket);

    if ((result = _avs_http_socket_new(&new_socket, stream->http, *url_move))) {
        return result;
    }
    if (avs_stream_net_setsock(stream->backend, new_socket)) {
        /* error, clean new socket */
        avs_net_socket_cleanup(&new_socket);
        LOG(ERROR, "setsock failed");
        return -1;
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
    return 0;
}

int _avs_http_prepare_for_sending(http_stream_t *stream) {
    LOG(TRACE, "http_prepare_for_sending");

    /* check stream state */
    if (stream->body_receiver) {
        /* we might be at the end of stream already */
        char finished = 0;
        if (!avs_stream_read(stream->body_receiver, NULL, &finished, NULL, 0)
                && finished) {
            avs_stream_cleanup(&stream->body_receiver);
        } else {
            LOG(ERROR, "trying to send while still receiving");
            stream->error_code = EBUSY;
            return -1;
        }
    }

    /* reconnect, if keep-alive not set */
    if (!stream->flags.keep_connection) {
        LOG(TRACE, "reconnecting stream");
        if (avs_stream_reset(stream->backend)
                || reconnect_tcp_socket(avs_stream_net_getsock(stream->backend),
                                        stream->url)) {
            return -1;
        } else {
            stream->flags.keep_connection = 1;
        }
    }

    LOG(TRACE, "http_prepare_for_sending: success");
    return 0;
}

static int http_send_simple_request(http_stream_t *stream,
                                    const void *buffer,
                                    size_t buffer_length) {
    int result;
    LOG(TRACE, "http_send_simple_request, buffer_length == %lu",
             (unsigned long) buffer_length);
    stream->auth.state.flags.retried = 0;
    do {
        result = (_avs_http_prepare_for_sending(stream)
                || _avs_http_send_headers(stream, buffer_length)
                || avs_stream_write(stream->backend, buffer, buffer_length)
                || avs_stream_finish_message(stream->backend)
                || _avs_http_receive_headers(stream)) ? -1 : 0;
    } while (result && stream->flags.should_retry);
    if (result == 0) {
        AVS_LIST_CLEAR(&stream->user_headers);
    }
    LOG(TRACE, "result == %d", result);
    return result;
}

/**
 * Send buffered and encoded block of data. @ref http_send above it does
 * buffering and encoding (i.e. compression). This function could be the public
 * send function if buffering and encoding were not requirements.
 */
static int http_send_block(http_stream_t *stream,
                           char message_finished,
                           const void *data,
                           size_t data_length) {
    int result = 0;
    if (stream->flags.chunked_sending) {
        result = _avs_http_chunked_send(stream, message_finished,
                                        data, data_length);
        if (result == 0 && message_finished) {
            stream->flags.chunked_sending = 0;
        }
    } else {
        if (message_finished) {
            result = http_send_simple_request(stream, data, data_length);
        } else {
            stream->flags.chunked_sending = 1;
            if (!(result = _avs_http_chunked_request_init(stream))) {
                result = _avs_http_chunked_send(stream, 0, data, data_length);
            }
        }
    }
    return result;
}

int _avs_http_buffer_flush(http_stream_t *stream, char message_finished) {
    int result = http_send_block(stream, message_finished,
                                 stream->out_buffer, stream->out_buffer_pos);
    if (result == 0) {
        stream->out_buffer_pos = 0;
    }
    return result;
}

int _avs_http_send_via_buffer(http_stream_t *stream,
                              const void *data,
                              size_t data_length) {
    int result = 0;
    if (data_length > stream->http->buffer_sizes.body_send
                    - stream->out_buffer_pos
            && _avs_http_buffer_flush(stream, 0)) {
        return -1;
    }
    if (data_length > stream->http->buffer_sizes.body_send) {
        result = http_send_block(stream, 0, data, data_length);
    } else {
        memcpy(stream->out_buffer + stream->out_buffer_pos, data, data_length);
        stream->out_buffer_pos += data_length;
    }
    return result;
}

int _avs_http_encoder_flush(http_stream_t *stream) {
    char buffer[stream->http->buffer_sizes.content_coding_min_input];
    size_t bytes_read = 0;
    char message_finished = 0;
    while (1) {
        if (avs_stream_read(stream->encoder, &bytes_read, &message_finished,
                            buffer, sizeof(buffer))) {
            return -1;
        }
        if (!bytes_read) {
            return 0;
        }
        if (_avs_http_send_via_buffer(stream, buffer, bytes_read)) {
            return -1;
        }
    }
}
