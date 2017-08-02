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

#include <avsystem/commons/coap/socket.h>
#include <avsystem/commons/coap/msg_builder.h>

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#include <avsystem/commons/list.h>

#include "log.h"
#include "msg_cache.h"

#pragma GCC visibility push(hidden)

struct anjay_coap_socket {
    avs_net_abstract_socket_t *dtls_socket;

    const anjay_coap_tx_params_t *tx_params;
    coap_msg_cache_t *msg_cache;
};

static const anjay_coap_tx_params_t DEFAULT_SOCKET_TX_PARAMS = {
    .ack_timeout_ms = 2000,
    .ack_random_factor = 1.5,
    .max_retransmit = 4
};

int avs_coap_socket_create(anjay_coap_socket_t **sock,
                              avs_net_abstract_socket_t *backend,
                              size_t msg_cache_size) {
    *sock = (anjay_coap_socket_t *) calloc(1, sizeof(anjay_coap_socket_t));
    if (!*sock) {
        return -1;
    }

    if (msg_cache_size > 0) {
        (*sock)->msg_cache = _avs_coap_msg_cache_create(msg_cache_size);
        if (!(*sock)->msg_cache) {
            LOG(ERROR, "could not create message cache");
            free(*sock);
            return -1;
        }
    }

    (*sock)->dtls_socket = backend;
    (*sock)->tx_params = &DEFAULT_SOCKET_TX_PARAMS;
    return 0;
}

int avs_coap_socket_close(anjay_coap_socket_t *sock) {
    assert(sock);
    if (!sock->dtls_socket) {
        return 0;
    }
    return avs_net_socket_close(sock->dtls_socket);
}

void avs_coap_socket_cleanup(anjay_coap_socket_t **sock) {
    if (!sock || !*sock) {
        return;
    }

    _avs_coap_msg_cache_release(&(*sock)->msg_cache);
    avs_coap_socket_close(*sock);
    avs_net_socket_cleanup(&(*sock)->dtls_socket);
    free(*sock);
    *sock = NULL;
}

static int map_io_error(avs_net_abstract_socket_t *socket,
                        int result,
                        const char *operation) {
    if (result) {
        int error = avs_net_socket_errno(socket);
        LOG(ERROR, "%s failed: errno = %d", operation, error);
        if (error == ETIMEDOUT) {
            result = AVS_COAP_SOCKET_ERR_TIMEOUT;
        } else if (error == EMSGSIZE) {
            result = AVS_COAP_SOCKET_ERR_MSG_TOO_LONG;
        } else {
            result = AVS_COAP_SOCKET_ERR_NETWORK;
        }
    }
    return result;
}

#ifndef WITH_AVS_COAP_MESSAGE_CACHE
#define try_cache_response(...) (void)0
#else // WITH_AVS_COAP_MESSAGE_CACHE

static int try_cache_response(anjay_coap_socket_t *sock,
                               const anjay_coap_msg_t *res) {
    if (!avs_coap_msg_is_response(res) || !sock->msg_cache) {
        return 0;
    }

    char addr[INET6_ADDRSTRLEN];
    char port[sizeof("65535")];
    if (avs_net_socket_get_remote_host(sock->dtls_socket, addr, sizeof(addr))
            || avs_net_socket_get_remote_port(sock->dtls_socket,
                                              port, sizeof(port))) {
        LOG(DEBUG, "could not get remote remote host/port");
        return -1;
    }

    return _avs_coap_msg_cache_add(sock->msg_cache, addr, port, res,
                                     sock->tx_params);
}

#endif // WITH_AVS_COAP_MESSAGE_CACHE

int avs_coap_socket_send(anjay_coap_socket_t *sock,
                            const anjay_coap_msg_t *msg) {
    assert(sock && sock->dtls_socket);
    if (!avs_coap_msg_is_valid(msg)) {
        LOG(ERROR, "cannot send an invalid CoAP message\n");
        return -1;
    }

    LOG(TRACE, "send: %s", AVS_COAP_MSG_SUMMARY(msg));
    int result = avs_net_socket_send(sock->dtls_socket,
                                     &msg->header, msg->length);
    if (!result) {
        int cache_result = try_cache_response(sock, msg);
        (void) cache_result;
    }
    return map_io_error(sock->dtls_socket, result, "send");
}

#ifndef WITH_AVS_COAP_MESSAGE_CACHE
#define try_send_cached_response(...) (-1)
#else // WITH_AVS_COAP_MESSAGE_CACHE

static int try_send_cached_response(anjay_coap_socket_t *sock,
                                    const anjay_coap_msg_t *req) {
    if (!avs_coap_msg_is_request(req) || !sock->msg_cache) {
        return -1;
    }

    char addr[INET6_ADDRSTRLEN];
    char port[sizeof("65535")];
    if (avs_net_socket_get_remote_host(sock->dtls_socket, addr, sizeof(addr))
            || avs_net_socket_get_remote_port(sock->dtls_socket,
                                              port, sizeof(port))) {
        LOG(DEBUG, "could not get remote remote host/port");
        return -1;
    }

    uint16_t msg_id = avs_coap_msg_get_id(req);
    const anjay_coap_msg_t *res = _avs_coap_msg_cache_get(sock->msg_cache,
                                                            addr, port, msg_id);
    if (res) {
        return avs_coap_socket_send(sock, res);
    } else {
        return -1;
    }
}

#endif // WITH_AVS_COAP_MESSAGE_CACHE

static inline bool is_coap_ping(const anjay_coap_msg_t *msg) {
    return avs_coap_msg_header_get_type(&msg->header)
                   == AVS_COAP_MSG_CONFIRMABLE
           && msg->header.code == AVS_COAP_CODE_EMPTY;
}

int avs_coap_socket_recv(anjay_coap_socket_t *sock,
                            anjay_coap_msg_t *out_msg,
                            size_t msg_capacity) {
    assert(sock && sock->dtls_socket);
    assert(msg_capacity < UINT32_MAX);

    size_t msg_length = 0;
    int result = avs_net_socket_receive(sock->dtls_socket, &msg_length,
                                        &out_msg->header,
                                        msg_capacity - sizeof(out_msg->length));
    out_msg->length = (uint32_t) msg_length;

    if (result) {
        return map_io_error(sock->dtls_socket, result, "receive");
    }

    if (!avs_coap_msg_is_valid(out_msg)) {
        LOG(DEBUG, "recv: malformed message");
        return AVS_COAP_SOCKET_ERR_MSG_MALFORMED;
    }

    LOG(TRACE, "recv: %s", AVS_COAP_MSG_SUMMARY(out_msg));

    if (is_coap_ping(out_msg)) {
        avs_coap_send_empty(sock, AVS_COAP_MSG_RESET,
                               avs_coap_msg_get_id(out_msg));
        return AVS_COAP_SOCKET_ERR_MSG_WAS_PING;
    }

    if (!try_send_cached_response(sock, out_msg)) {
        return AVS_COAP_SOCKET_ERR_DUPLICATE;
    }

    return 0;
}

int avs_coap_socket_get_recv_timeout(anjay_coap_socket_t *sock) {
    avs_net_socket_opt_value_t value;

    if (avs_net_socket_get_opt(sock->dtls_socket,
                               AVS_NET_SOCKET_OPT_RECV_TIMEOUT, &value)) {
        assert(0 && "should never happen");
        LOG(ERROR, "could not get socket recv timeout");
        return 0;
    }

    return value.recv_timeout;
}

void avs_coap_socket_set_recv_timeout(anjay_coap_socket_t *sock,
                                         int timeout_ms) {
    avs_net_socket_opt_value_t value = {
        .recv_timeout = timeout_ms
    };

    if (avs_net_socket_set_opt(sock->dtls_socket,
                               AVS_NET_SOCKET_OPT_RECV_TIMEOUT, value)) {
        assert(0 && "should never happen");
        LOG(ERROR, "could not set socket recv timeout");
    }
}

const anjay_coap_tx_params_t *
avs_coap_socket_get_tx_params(anjay_coap_socket_t *sock) {
    return sock->tx_params;
}

void
avs_coap_socket_set_tx_params(anjay_coap_socket_t *sock,
                                 const anjay_coap_tx_params_t *tx_params) {
    sock->tx_params = tx_params;
}

avs_net_abstract_socket_t *
avs_coap_socket_get_backend(anjay_coap_socket_t *sock) {
    return sock->dtls_socket;
}

void avs_coap_socket_set_backend(anjay_coap_socket_t *sock,
                                    avs_net_abstract_socket_t *backend) {
    sock->dtls_socket = backend;
}

int avs_coap_send_empty(anjay_coap_socket_t *socket,
                           anjay_coap_msg_type_t msg_type,
                           uint16_t msg_id) {
    anjay_coap_msg_info_t info = avs_coap_msg_info_init();

    info.type = msg_type;
    info.code = AVS_COAP_CODE_EMPTY;
    info.identity.msg_id = msg_id;

    union {
        uint8_t buffer[offsetof(anjay_coap_msg_t, content)];
        anjay_coap_msg_t force_align_;
    } aligned_buffer;
    const anjay_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(&aligned_buffer),
            sizeof(aligned_buffer), &info);
    assert(msg);

    return avs_coap_socket_send(socket, msg);
}

static void send_response(anjay_coap_socket_t *socket,
                          const anjay_coap_msg_t *msg,
                          uint8_t code,
                          const uint32_t *max_age) {
    anjay_coap_msg_info_t info = avs_coap_msg_info_init();

    info.type = AVS_COAP_MSG_ACKNOWLEDGEMENT;
    info.code = code;
    info.identity.msg_id = avs_coap_msg_get_id(msg);
    info.identity.token_size = avs_coap_msg_get_token(msg,
                                                         &info.identity.token);

    if (max_age && avs_coap_msg_info_opt_u32(&info, AVS_COAP_OPT_MAX_AGE,
                                                *max_age)) {
        LOG(WARNING, "unable to add Max-Age option to response");
    }

    union {
        uint8_t buffer[offsetof(anjay_coap_msg_t, content)
                       + AVS_COAP_MAX_TOKEN_LENGTH
                       + AVS_COAP_OPT_INT_MAX_SIZE];
        anjay_coap_msg_t force_align_;
    } aligned_buffer;
    const anjay_coap_msg_t *error = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(&aligned_buffer),
            sizeof(aligned_buffer), &info);
    assert(error);

    if (avs_coap_socket_send(socket, error)) {
        LOG(WARNING, "failed to send error message");
    }

    avs_coap_msg_info_reset(&info);
}

void avs_coap_send_error(anjay_coap_socket_t *socket,
                            const anjay_coap_msg_t *msg,
                            uint8_t error_code) {
    send_response(socket, msg, error_code, NULL);
}

void avs_coap_send_service_unavailable(anjay_coap_socket_t *socket,
                                          const anjay_coap_msg_t *msg,
                                          int32_t retry_after_ms) {
    uint32_t ms_to_retry_after =
        retry_after_ms >= 0 ? (uint32_t)retry_after_ms : 0;

    // round up to nearest full second
    uint32_t s_to_retry_after = (ms_to_retry_after + 999) / 1000;

    send_response(socket, msg, AVS_COAP_CODE_SERVICE_UNAVAILABLE,
                  &s_to_retry_after);
}

#ifdef AVS_UNIT_TESTING
#include "test/socket.c"
#endif // AVS_UNIT_TESTING
