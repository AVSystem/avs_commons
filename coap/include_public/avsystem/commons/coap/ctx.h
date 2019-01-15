/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

/**
 * @name Specific error codes that might be returned from
 *       @ref avs_coap_ctx_recv, @ref avs_coap_ctx_send etc.
 */
/**@{*/

/**
 * The network socket indicate that a timeout expired, but message could not be
 * sent or received.
 */
#define AVS_COAP_CTX_ERR_TIMEOUT       (-0x5E1)

/**
 * A UDP or DTLS datagram was successfully received, but could not be decoded as
 * a CoAP message.
 */
#define AVS_COAP_CTX_ERR_MSG_MALFORMED (-0x5E2)

/**
 * Unspecified error on some layer lower than CoAP. Please check error state of
 * the network socket for details.
 */
#define AVS_COAP_CTX_ERR_NETWORK       (-0x5E3)

/**
 * While sending: the network socket's internal buffers were too small to hold
 * the packet to send.
 *
 * While receiving: <c>msg_capacity</c> was too small to hold the entire
 * received message.
 */
#define AVS_COAP_CTX_ERR_MSG_TOO_LONG  (-0x5E4)

/**
 * Some message was successfully received and identified as a duplicate of some
 * already handled message. Previous response has been found in the cache and
 * already sent.
 */
#define AVS_COAP_CTX_ERR_DUPLICATE     (-0x5E5)

/**
 * A message has been successfully received and identified as a CoAP-layer ping
 * message. Ping response has been already sent.
 */
#define AVS_COAP_CTX_ERR_MSG_WAS_PING  (-0x5E6)
/**@}*/

/**
 * Type representing a CoAP context object.
 *
 * It may optionally have an internal message cache for detection and automatic
 * handling of duplicate packets.
 */
typedef struct avs_coap_ctx avs_coap_ctx_t;

/**
 * Creates a new CoAP context.
 *
 * @param ctx            Pointer to a variable that the newly created context
 *                       handle will be assigned to.
 *
 * @param msg_cache_size Size in bytes of the internal message cache. Note that
 *                       if the library was compiled without message cache
 *                       support (<c>WITH_AVS_COAP_MESSAGE_CACHE</c>),
 *                       specifying a non-zero value will result in an error.
 *
 * @returns 0 on success, negative value on error.
 */
int avs_coap_ctx_create(avs_coap_ctx_t **ctx, size_t msg_cache_size);

/**
 * Destroys the CoAP context, releases any resources allocated for it, and sets
 * <c>*ctx</c> to NULL.
 *
 * @param ctx CoAP context to clean up.
 */
void avs_coap_ctx_cleanup(avs_coap_ctx_t **ctx);

/**
 * Sends a CoAP message via a specified network socket and possibly records it
 * in the message cache.
 *
 * @param ctx    CoAP context to operate on.
 * @param socket Network socket to send the message through.
 * @param msg    Message to send.
 *
 * @returns 0 on success, or a negative value (possibly one of the
 *          <c>AVS_COAP_CTX_ERR_*</c> constants) in case of error.
 */
int avs_coap_ctx_send(avs_coap_ctx_t *ctx,
                      avs_net_abstract_socket_t *socket,
                      const avs_coap_msg_t *msg);

/**
 * Receives a datagram from the specified network socket and decodes it as a
 * CoAP message. If a message can be identified as a duplicate or a CoAP ping,
 * a response is sent automatically (see @ref AVS_COAP_CTX_ERR_DUPLICATE and
 * @ref AVS_COAP_CTX_ERR_MSG_WAS_PING).
 *
 * @param ctx          CoAP context to operate on.
 * @param socket       Network socket to receive the message from.
 * @param out_msg      Output buffer to store the message in.
 * @param msg_capacity Number of bytes allocated for the <c>out_msg</c>
 *                     structure (counting all fields, including <c>length</c>).
 *                     Attempting to pass a value smaller than
 *                     <c>sizeof(avs_coap_msg_t)</c> is undefined behaviour.
 *
 * @returns 0 on success, or a negative value (possibly one of the
 *          <c>AVS_COAP_CTX_ERR_*</c> constants) in case of error or automatic
 *          response.
 **/
int avs_coap_ctx_recv(avs_coap_ctx_t *ctx,
                      avs_net_abstract_socket_t *socket,
                      avs_coap_msg_t *out_msg,
                      size_t msg_capacity);

/**
 * Gets the CoAP transmission parameters used by the CoAP context.
 *
 * @param ctx CoAP context to operate on.
 *
 * @returns Copy of the CoAP transmission parameters structure currently used by
 *          the context.
 */
avs_coap_tx_params_t avs_coap_ctx_get_tx_params(avs_coap_ctx_t *ctx);

/**
 * Sets the CoAP transmission parameters used by the CoAP context.
 *
 * @param ctx       CoAP context to operate on.
 * @param tx_params CoAP transmission parameters structure to use. The structure
 *                  is copied into the CoAP context.
 */
void avs_coap_ctx_set_tx_params(avs_coap_ctx_t *ctx,
                                const avs_coap_tx_params_t *tx_params);

/**
 * Auxiliary functions for sending simple messages.
 * @{
 */

/**
 * Sends an Empty message with given values of @p msg_type and @p msg_id.
 *
 * @param ctx      CoAP context to operate on.
 * @param socket   Network socket to send the message through.
 * @param msg_type Type of the message to send.
 * @param msg_id   Identity of the message to send.
 *
 * @returns 0 on success, or a negative value (possibly one of the
 *          <c>AVS_COAP_CTX_ERR_*</c> constants) in case of error.
 */
int avs_coap_ctx_send_empty(avs_coap_ctx_t *ctx,
                            avs_net_abstract_socket_t *socket,
                            avs_coap_msg_type_t msg_type,
                            uint16_t msg_id);

/**
 * Responds with error specified as @p error_code to the message @p request.
 *
 * @param ctx        CoAP context to operate on.
 * @param socket     Network socket to send the message through.
 * @param request    CoAP message that the error is intended to be a response
 *                   to.
 * @param error_code CoAP code of the error to send, e.g.
 *                   <c>AVS_COAP_CODE_BAD_REQUEST</c>.
 *
 * @returns 0 on success, or a negative value (possibly one of the
 *          <c>AVS_COAP_CTX_ERR_*</c> constants) in case of error.
 */
void avs_coap_ctx_send_error(avs_coap_ctx_t *ctx,
                             avs_net_abstract_socket_t *socket,
                             const avs_coap_msg_t *request,
                             uint8_t error_code);

/**
 * Responds with a Service Unavailable messages, with Max-Age option set to
 * @p retry_after converted to seconds.
 *
 * @param ctx         CoAP context to operate on.
 * @param socket      Network socket to send the message through.
 * @param request     CoAP message that the error is intended to be a response
 *                    to.
 * @param retry_after Amount of time after which the remote endpoint shall
 *                    repeat the request.
 *
 * @returns 0 on success, or a negative value (possibly one of the
 *          <c>AVS_COAP_CTX_ERR_*</c> constants) in case of error.
 */
void avs_coap_ctx_send_service_unavailable(avs_coap_ctx_t *ctx,
                                           avs_net_abstract_socket_t *socket,
                                           const avs_coap_msg_t *request,
                                           avs_time_duration_t retry_after);

/**
 * @param ctx CoAP context to operate on.
 *
 * @returns Total number of bytes transmitted through the CoAP context.
 *
 * NOTE: When <c>WITH_AVS_COAP_NET_STATS</c> is disabled, this function always
 * returns 0.
 */
uint64_t avs_coap_ctx_get_tx_bytes(avs_coap_ctx_t *ctx);

/**
 * @param ctx CoAP context to operate on.
 *
 * @returns Number of bytes received through the CoAP context.
 *
 * NOTE: When <c>WITH_AVS_COAP_NET_STATS</c> is disabled, this function always
 * returns 0.
 */
uint64_t avs_coap_ctx_get_rx_bytes(avs_coap_ctx_t *ctx);

/**
 * @param ctx CoAP context to operate on.
 *
 * @returns Number of packets received through the CoAP context to which cached
 *          responses were found.
 *
 * NOTE: When <c>WITH_AVS_COAP_NET_STATS</c> is disabled, this function always
 * returns 0.
 */
uint64_t
avs_coap_ctx_get_num_incoming_retransmissions(avs_coap_ctx_t *ctx);

/**
 * @param ctx CoAP context to operate on.
 *
 * @returns Number of packets sent through the ctx that were already cached as
 *          well as requests which the CoAP client did not get any response to.
 *
 * NOTE: When <c>WITH_AVS_COAP_NET_STATS</c> is disabled, this function always
 * returns 0.
 */
uint64_t
avs_coap_ctx_get_num_outgoing_retransmissions(avs_coap_ctx_t *ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_CTX_H
