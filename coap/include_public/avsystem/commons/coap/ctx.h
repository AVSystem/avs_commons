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

#ifndef AVS_COMMONS_COAP_CTX_H
#define AVS_COMMONS_COAP_CTX_H

#include <avsystem/commons/coap/msg.h>
#include <avsystem/commons/coap/tx_params.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVS_COAP_CTX_ERR_TIMEOUT       (-0x5E1)
#define AVS_COAP_CTX_ERR_MSG_MALFORMED (-0x5E2)
#define AVS_COAP_CTX_ERR_NETWORK       (-0x5E3)
#define AVS_COAP_CTX_ERR_MSG_TOO_LONG  (-0x5E4)
#define AVS_COAP_CTX_ERR_DUPLICATE     (-0x5E5)
#define AVS_COAP_CTX_ERR_MSG_WAS_PING  (-0x5E6)

typedef struct avs_coap_ctx avs_coap_ctx_t;

int avs_coap_ctx_create(avs_coap_ctx_t **sock, size_t msg_cache_size);

void avs_coap_ctx_cleanup(avs_coap_ctx_t **sock);

/**
 * @returns 0 on success, a negative value in case of error:
 * - AVS_COAP_CTX_ERR_TIMEOUT if the ctx timeout expired, but message
 *   could not be sent
 * - AVS_COAP_CTX_ERR_MSG_TOO_LONG when the message to be sent was too big
 *   for the ctx
 * - AVS_COAP_CTX_ERR_NETWORK in case of other error on a layer below the
 *   application layer
 */
int avs_coap_ctx_send(avs_coap_ctx_t *ctx,
                      avs_net_abstract_socket_t *socket,
                      const avs_coap_msg_t *msg);

/**
 * @returns 0 on success, a negative value in case of error:
 * - AVS_COAP_CTX_ERR_TIMEOUT if the ctx timeout expired, but no message
 *   was received
 * - AVS_COAP_CTX_ERR_MSG_MALFORMED when a packet was successfully
 *   received, but it was not a correct CoAP message
 * - AVS_COAP_CTX_ERR_MSG_TOO_LONG when the buffer was too small to receive
 *   the packet in its entirety
 * - AVS_COAP_CTX_ERR_NETWORK in case of other error on a layer below the
 *   application layer
 * - AVS_COAP_CTX_ERR_DUPLICATE in case duplicate request was received
 *   and then handled by response cache
 * - AVS_COAP_CTX_ERR_MSG_WAS_PING in case a ping was received and then
 *   handled by the ctx layer
 **/
int avs_coap_ctx_recv(avs_coap_ctx_t *ctx,
                      avs_net_abstract_socket_t *socket,
                      avs_coap_msg_t *out_msg,
                      size_t msg_capacity);

const avs_coap_tx_params_t *
avs_coap_ctx_get_tx_params(avs_coap_ctx_t *sock);
void avs_coap_ctx_set_tx_params(avs_coap_ctx_t *sock,
                                   const avs_coap_tx_params_t *tx_params);

/**
 * Auxiliary functions for sending simple messages.
 * @{
 */

/**
 * Sends an Empty message with given values of @p msg_type and @p msg_id.
 */
int avs_coap_send_empty(avs_coap_ctx_t *ctx,
                        avs_net_abstract_socket_t *socket,
                        avs_coap_msg_type_t msg_type,
                        uint16_t msg_id);

/**
 * Responds with error specified as @p error_code to the message @p msg.
 */
void avs_coap_send_error(avs_coap_ctx_t *ctx,
                         avs_net_abstract_socket_t *socket,
                         const avs_coap_msg_t *msg,
                         uint8_t error_code);

/**
 * Responds with a Service Unavailable messages, with Max-Age option set to
 * @p retry_after_ms converted to seconds.
 */
void avs_coap_send_service_unavailable(avs_coap_ctx_t *ctx,
                                       avs_net_abstract_socket_t *socket,
                                       const avs_coap_msg_t *msg,
                                       int32_t retry_after_ms);

/**
 * @returns the total amount of bytes transmitted through the ctx.
 *
 * NOTE: When AVS_COAP_WITH_NET_STATS is disabled this function always return 0.
 */
uint64_t avs_coap_ctx_get_tx_bytes(avs_coap_ctx_t *ctx);

/**
 * @returns the amount of bytes received through the ctx.
 *
 * NOTE: When AVS_COAP_WITH_NET_STATS is disabled this function always return 0.
 */
uint64_t avs_coap_ctx_get_rx_bytes(avs_coap_ctx_t *ctx);

/**
 * @returns the number of packets received through the ctx to which cached
 *          responses were found.
 *
 * NOTE: When AVS_COAP_WITH_NET_STATS is disabled this function always return 0.
 */
uint64_t
avs_coap_ctx_get_num_incoming_retransmissions(avs_coap_ctx_t *ctx);

/**
 * @returns the number of packets sent through the ctx that were already
 *          cached as well as requests which the CoAP client did not get any
 *          response to.
 *
 * NOTE: When AVS_COAP_WITH_NET_STATS is disabled this function always return 0.
 */
uint64_t
avs_coap_ctx_get_num_outgoing_retransmissions(avs_coap_ctx_t *ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_CTX_H
