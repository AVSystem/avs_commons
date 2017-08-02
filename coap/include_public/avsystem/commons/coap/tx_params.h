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

#ifndef AVS_COAP_TX_PARAMS_H
#define AVS_COAP_TX_PARAMS_H

#include <stdint.h>
#include <unistd.h>
#include <assert.h>

#include <sys/time.h>

#include <avsystem/commons/net.h>
#include <avsystem/commons/time.h>

typedef struct {
    /** RFC 7252: ACK_TIMEOUT */
    avs_net_timeout_t ack_timeout_ms;
    /** RFC 7252: ACK_RANDOM_FACTOR */
    double ack_random_factor;
    /** RFC 7252: MAX_RETRANSMIT */
    unsigned max_retransmit;
} anjay_coap_tx_params_t;

bool avs_coap_tx_params_valid(const anjay_coap_tx_params_t *tx_params,
                                 const char **error_details);

int32_t
avs_coap_max_transmit_wait_ms(const anjay_coap_tx_params_t *tx_params);

int32_t
avs_coap_exchange_lifetime_ms(const anjay_coap_tx_params_t *tx_params);

struct timespec
avs_coap_exchange_lifetime(const anjay_coap_tx_params_t *tx_params);

int32_t
avs_coap_max_transmit_span_ms(const anjay_coap_tx_params_t *tx_params);

struct timespec
avs_coap_max_transmit_span(const anjay_coap_tx_params_t *tx_params);

/** Maximum time the client can wait for a Separate Response */
#define AVS_COAP_SEPARATE_RESPONSE_TIMEOUT_MS (30 * 1000)

typedef struct {
    unsigned retry_count;
    int32_t recv_timeout_ms;
} coap_retry_state_t;

void avs_coap_update_retry_state(coap_retry_state_t *retry_state,
                                    const anjay_coap_tx_params_t *tx_params,
                                    unsigned *rand_seed);

#endif // AVS_COAP_TX_PARAMS_H
