/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_COAP_TX_PARAMS_H
#define AVS_COMMONS_COAP_TX_PARAMS_H

#include <assert.h>
#include <stdint.h>

#include <avsystem/commons/net.h>
#include <avsystem/commons/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** CoAP transmission params object. */
typedef struct {
    /** RFC 7252: ACK_TIMEOUT */
    avs_time_duration_t ack_timeout;
    /** RFC 7252: ACK_RANDOM_FACTOR */
    double ack_random_factor;
    /** RFC 7252: MAX_RETRANSMIT */
    unsigned max_retransmit;
} avs_coap_tx_params_t;

/**
 * @param[in]  tx_params     Transmission parameters to check.
 * @param[out] error_details If not NULL, <c>*error_details</c> is set to
 *                           a string describing what part of @p tx_params
 *                           is invalid, or to NULL if @p tx_params are valid.
 *
 * @returns true if @p tx_params are valid according to RFC7252,
 *          false otherwise.
 */
bool avs_coap_tx_params_valid(const avs_coap_tx_params_t *tx_params,
                              const char **error_details);

/**
 * @returns MAX_TRANSMIT_WAIT value derived from @p tx_params according to the
 *          formula specified in RFC7252.
 */
avs_time_duration_t
avs_coap_max_transmit_wait(const avs_coap_tx_params_t *tx_params);

/**
 * @returns EXCHANGE_LIFETIME value derived from @p tx_params according
 *          to the formula specified in RFC7252.
 */
avs_time_duration_t
avs_coap_exchange_lifetime(const avs_coap_tx_params_t *tx_params);

/**
 * @returns MAX_TRANSMIT_SPAN value derived from @p tx_params according
 *          to the formula specified in RFC7252.
 */
avs_time_duration_t
avs_coap_max_transmit_span(const avs_coap_tx_params_t *tx_params);

/** Maximum time the client can wait for a Separate Response */
extern const avs_time_duration_t AVS_COAP_SEPARATE_RESPONSE_TIMEOUT;

/** Retry state object used to calculate retransmission timeouts. */
typedef struct {
    unsigned retry_count;
    avs_time_duration_t recv_timeout;
} avs_coap_retry_state_t;

/**
 * Updates @p retry_state and calculates next retransmission timeout that
 * should be used according to @p tx_params .
 *
 * @param[inout] retry_state Retry state to update.
 * @param[in]    tx_params   CoAP transmission parameters.
 * @param[inout] rand_seed   Random seed to use for deriving a random factor
 *                           of the retransmission state.
 */
void avs_coap_update_retry_state(avs_coap_retry_state_t *retry_state,
                                 const avs_coap_tx_params_t *tx_params,
                                 unsigned *rand_seed);

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_TX_PARAMS_H
