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

#include <avsystem/commons/coap/ctx.h>
#include <avsystem/commons/coap/msg_builder.h>

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#include <avsystem/commons/list.h>

#include "coap_log.h"
#include "msg_cache.h"

VISIBILITY_SOURCE_BEGIN

struct avs_coap_ctx {
    avs_coap_tx_params_t tx_params;
    coap_msg_cache_t *msg_cache;
#ifdef WITH_AVS_COAP_NET_STATS
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t num_incoming_retransmissions;
    uint64_t num_outgoing_retransmissions;
    avs_coap_msg_identity_t last_request_identity;
#endif
};

static const avs_coap_tx_params_t DEFAULT_TX_PARAMS = {
    .ack_timeout = { 2, 0 },
    .ack_random_factor = 1.5,
    .max_retransmit = 4
};

int avs_coap_ctx_create(avs_coap_ctx_t **ctx, size_t msg_cache_size) {
    *ctx = (avs_coap_ctx_t *) calloc(1, sizeof(avs_coap_ctx_t));
    if (!*ctx) {
        return -1;
    }

    if (msg_cache_size > 0) {
        (*ctx)->msg_cache = _avs_coap_msg_cache_create(msg_cache_size);
        if (!(*ctx)->msg_cache) {
            LOG(ERROR, "could not create message cache");
            free(*ctx);
            return -1;
        }
    }

    (*ctx)->tx_params = DEFAULT_TX_PARAMS;
    return 0;
}

uint64_t avs_coap_ctx_get_rx_bytes(avs_coap_ctx_t *ctx) {
#ifdef WITH_AVS_COAP_NET_STATS
    return ctx->rx_bytes;
#else
    (void) ctx;
    return 0;
#endif // WITH_AVS_COAP_NET_STATS
}

uint64_t avs_coap_ctx_get_tx_bytes(avs_coap_ctx_t *ctx) {
#ifdef WITH_AVS_COAP_NET_STATS
    return ctx->tx_bytes;
#else
    (void) ctx;
    return 0;
#endif // WITH_AVS_COAP_NET_STATS
}

uint64_t
avs_coap_ctx_get_num_incoming_retransmissions(avs_coap_ctx_t *ctx) {
#ifdef WITH_AVS_COAP_NET_STATS
    return ctx->num_incoming_retransmissions;
#else
    (void) ctx;
    return 0;
#endif // WITH_AVS_COAP_NET_STATS
}

uint64_t
avs_coap_ctx_get_num_outgoing_retransmissions(avs_coap_ctx_t *ctx) {
#ifdef WITH_AVS_COAP_NET_STATS
    return ctx->num_outgoing_retransmissions;
#else
    (void) ctx;
    return 0;
#endif // WITH_AVS_COAP_NET_STATS
}

void avs_coap_ctx_cleanup(avs_coap_ctx_t **ctx) {
    if (!ctx || !*ctx) {
        return;
    }

    _avs_coap_msg_cache_release(&(*ctx)->msg_cache);
    free(*ctx);
    *ctx = NULL;
}

static int map_io_error(avs_net_abstract_socket_t *socket,
                        int result,
                        const char *operation) {
    if (result) {
        int error = avs_net_socket_errno(socket);
        LOG(ERROR, "%s failed: errno = %d", operation, error);
        if (error == ETIMEDOUT) {
            result = AVS_COAP_CTX_ERR_TIMEOUT;
        } else if (error == EMSGSIZE) {
            result = AVS_COAP_CTX_ERR_MSG_TOO_LONG;
        } else {
            result = AVS_COAP_CTX_ERR_NETWORK;
        }
    }
    return result;
}

#ifndef WITH_AVS_COAP_MESSAGE_CACHE
#define try_cache_response(...) 0
#else // WITH_AVS_COAP_MESSAGE_CACHE

static int try_cache_response(avs_coap_ctx_t *ctx,
                              avs_net_abstract_socket_t *socket,
                              const avs_coap_msg_t *res) {
    if (!avs_coap_msg_is_response(res) || !ctx->msg_cache) {
        return 0;
    }

    char addr[AVS_ADDRSTRLEN];
    char port[sizeof("65535")];
    if (avs_net_socket_get_remote_host(socket, addr, sizeof(addr))
            || avs_net_socket_get_remote_port(socket, port, sizeof(port))) {
        LOG(DEBUG, "could not get remote host/port");
        return -1;
    }

    return _avs_coap_msg_cache_add(ctx->msg_cache, addr, port, res,
                                   &ctx->tx_params);
}

#endif // WITH_AVS_COAP_MESSAGE_CACHE

#ifdef WITH_AVS_COAP_NET_STATS
static size_t packet_overhead(avs_net_abstract_socket_t *socket) {
    avs_net_socket_opt_value_t mtu;
    avs_net_socket_opt_value_t mtu_inner;
    if (avs_net_socket_get_opt(socket, AVS_NET_SOCKET_OPT_MTU, &mtu)
        || avs_net_socket_get_opt(socket, AVS_NET_SOCKET_OPT_INNER_MTU,
                                  &mtu_inner)) {
        goto error;
    }
    if (mtu.mtu < mtu_inner.mtu) {
        goto error;
    }
    return (size_t) mtu.mtu - (size_t) mtu_inner.mtu;

error:
    return 0;
}
#endif // WITH_AVS_COAP_NET_STATS

int avs_coap_ctx_send(avs_coap_ctx_t *ctx,
                      avs_net_abstract_socket_t *socket,
                      const avs_coap_msg_t *msg) {
    assert(ctx && socket);
    if (!avs_coap_msg_is_valid(msg)) {
        LOG(ERROR, "cannot send an invalid CoAP message\n");
        return -1;
    }

    LOG(TRACE, "send: %s", AVS_COAP_MSG_SUMMARY(msg));
    int result = avs_net_socket_send(socket, msg->content, msg->length);
    if (!result) {
        int cache_result = try_cache_response(ctx, socket, msg);
#ifdef WITH_AVS_COAP_NET_STATS
        bool request_retransmission = false;
        if (avs_coap_msg_is_request(msg)) {
            const avs_coap_msg_identity_t msg_identity =
                    avs_coap_msg_get_identity(msg);

            request_retransmission =
                    avs_coap_identity_equal(&msg_identity,
                                            &ctx->last_request_identity);
            ctx->last_request_identity = msg_identity;
        }

        if (cache_result == AVS_COAP_MSG_CACHE_DUPLICATE
                || request_retransmission) {
            ++ctx->num_outgoing_retransmissions;
        }
        ctx->tx_bytes += msg->length + packet_overhead(socket);
#endif // WITH_AVS_COAP_NET_STATS
        (void) cache_result;
    }
    return map_io_error(socket, result, "send");
}

#ifndef WITH_AVS_COAP_MESSAGE_CACHE
#define try_send_cached_response(...) (-1)
#else // WITH_AVS_COAP_MESSAGE_CACHE

static int try_send_cached_response(avs_coap_ctx_t *ctx,
                                    avs_net_abstract_socket_t *socket,
                                    const avs_coap_msg_t *req) {
    if (!avs_coap_msg_is_request(req) || !ctx->msg_cache) {
        return -1;
    }

    char addr[AVS_ADDRSTRLEN];
    char port[sizeof("65535")];
    if (avs_net_socket_get_remote_host(socket, addr, sizeof(addr))
            || avs_net_socket_get_remote_port(socket, port, sizeof(port))) {
        LOG(DEBUG, "could not get remote remote host/port");
        return -1;
    }

    uint16_t msg_id = avs_coap_msg_get_id(req);
    const avs_coap_msg_t *res =
            _avs_coap_msg_cache_get(ctx->msg_cache, addr, port, msg_id);
    if (res) {
#ifdef WITH_AVS_COAP_NET_STATS
        ++ctx->num_incoming_retransmissions;
#endif // WITH_AVS_COAP_NET_STATS
        return avs_coap_ctx_send(ctx, socket, res);
    } else {
        return -1;
    }
}

#endif // WITH_AVS_COAP_MESSAGE_CACHE

static inline bool is_coap_ping(const avs_coap_msg_t *msg) {
    return avs_coap_msg_get_type(msg) == AVS_COAP_MSG_CONFIRMABLE
           && avs_coap_msg_get_code(msg) == AVS_COAP_CODE_EMPTY;
}

int avs_coap_ctx_recv(avs_coap_ctx_t *ctx,
                      avs_net_abstract_socket_t *socket,
                      avs_coap_msg_t *out_msg,
                      size_t msg_capacity) {
    assert(ctx && socket);
    assert(msg_capacity < UINT32_MAX);

    size_t msg_length = 0;
    int result = avs_net_socket_receive(socket, &msg_length, out_msg->content,
                                        msg_capacity - sizeof(out_msg->length));
    out_msg->length = (uint32_t) msg_length;

    if (result) {
        return map_io_error(socket, result, "receive");
    }
#ifdef WITH_AVS_COAP_NET_STATS
    ctx->rx_bytes += msg_length + packet_overhead(socket);
#endif // WITH_AVS_COAP_NET_STATS

    if (!avs_coap_msg_is_valid(out_msg)) {
        LOG(DEBUG, "recv: malformed message");
        return AVS_COAP_CTX_ERR_MSG_MALFORMED;
    }

    LOG(TRACE, "recv: %s", AVS_COAP_MSG_SUMMARY(out_msg));

    if (is_coap_ping(out_msg)) {
        avs_coap_ctx_send_empty(ctx, socket, AVS_COAP_MSG_RESET,
                                avs_coap_msg_get_id(out_msg));
        return AVS_COAP_CTX_ERR_MSG_WAS_PING;
    }

    if (!try_send_cached_response(ctx, socket, out_msg)) {
        return AVS_COAP_CTX_ERR_DUPLICATE;
    }

    return 0;
}

avs_coap_tx_params_t avs_coap_ctx_get_tx_params(avs_coap_ctx_t *ctx) {
    return ctx->tx_params;
}

void avs_coap_ctx_set_tx_params(avs_coap_ctx_t *ctx,
                                const avs_coap_tx_params_t *tx_params) {
    assert(avs_coap_tx_params_valid(tx_params, NULL));
    ctx->tx_params = *tx_params;
}

int avs_coap_ctx_send_empty(avs_coap_ctx_t *ctx,
                            avs_net_abstract_socket_t *socket,
                            avs_coap_msg_type_t msg_type,
                            uint16_t msg_id) {
    avs_coap_msg_info_t info = avs_coap_msg_info_init();

    info.type = msg_type;
    info.code = AVS_COAP_CODE_EMPTY;
    info.identity.msg_id = msg_id;

    union {
        uint8_t buffer[offsetof(avs_coap_msg_t, content)];
        avs_coap_msg_t force_align_;
    } aligned_buffer;
    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(&aligned_buffer),
            sizeof(aligned_buffer), &info);
    assert(msg);

    return avs_coap_ctx_send(ctx, socket, msg);
}

static void send_response(avs_coap_ctx_t *ctx,
                          avs_net_abstract_socket_t *socket,
                          const avs_coap_msg_t *request,
                          uint8_t code,
                          const uint32_t *max_age) {
    avs_coap_msg_info_t info = avs_coap_msg_info_init();

    info.type = AVS_COAP_MSG_ACKNOWLEDGEMENT;
    info.code = code;
    info.identity = avs_coap_msg_get_identity(request);

    if (max_age
        && avs_coap_msg_info_opt_u32(&info, AVS_COAP_OPT_MAX_AGE, *max_age)) {
        LOG(WARNING, "unable to add Max-Age option to response");
    }

    union {
        uint8_t buffer[offsetof(avs_coap_msg_t, content)
                       + AVS_COAP_MAX_TOKEN_LENGTH
                       + AVS_COAP_OPT_INT_MAX_SIZE];
        avs_coap_msg_t force_align_;
    } aligned_buffer;
    const avs_coap_msg_t *error = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(&aligned_buffer),
            sizeof(aligned_buffer), &info);
    assert(error);

    if (avs_coap_ctx_send(ctx, socket, error)) {
        LOG(WARNING, "failed to send error message");
    }

    avs_coap_msg_info_reset(&info);
}

void avs_coap_ctx_send_error(avs_coap_ctx_t *ctx,
                             avs_net_abstract_socket_t *socket,
                             const avs_coap_msg_t *request,
                             uint8_t error_code) {
    send_response(ctx, socket, request, error_code, NULL);
}

void avs_coap_ctx_send_service_unavailable(avs_coap_ctx_t *ctx,
                                           avs_net_abstract_socket_t *socket,
                                           const avs_coap_msg_t *request,
                                           avs_time_duration_t retry_after) {
    uint32_t s_to_retry_after = 0;
    if (avs_time_duration_valid(retry_after)) {
        s_to_retry_after = (uint32_t) AVS_MIN(
                retry_after.seconds + (retry_after.nanoseconds > 0 ? 1 : 0),
                (int64_t) UINT32_MAX);
    }

    send_response(ctx, socket, request, AVS_COAP_CODE_SERVICE_UNAVAILABLE,
                  &s_to_retry_after);
}

#ifdef AVS_UNIT_TESTING
#include "test/ctx.c"
#endif // AVS_UNIT_TESTING
