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

/* for timespec */
#define _GNU_SOURCE
#include <config.h>

#include <avsystem/commons/coap/tx_params.h>
#include <avsystem/commons/time.h>
#include <avsystem/commons/utils.h>

bool avs_coap_tx_params_valid(const avs_coap_tx_params_t *tx_params,
                              const char **error_details) {
    // ACK_TIMEOUT below 1 second would violate the guidelines of [RFC5405].
    // -- RFC 7252, 4.8.1
    if (tx_params->ack_timeout_ms < 1000) {
        if (error_details) {
            *error_details = "ACK_TIMEOUT below 1000 milliseconds";
        }
        return false;
    }

    // ACK_RANDOM_FACTOR MUST NOT be decreased below 1.0, and it SHOULD have
    // a value that is sufficiently different from 1.0 to provide some
    // protection from synchronization effects.
    // -- RFC 7252, 4.8.1
    if (tx_params->ack_random_factor <= 1.0) {
        if (error_details) {
            *error_details = "ACK_RANDOM_FACTOR less than or equal to 1.0";
        }
        return false;
    }
    if (error_details) {
        *error_details = NULL;
    }
    return true;
}

int32_t
avs_coap_max_transmit_wait_ms(const avs_coap_tx_params_t *tx_params) {
    return (int32_t) (tx_params->ack_timeout_ms *
            ((1 << (tx_params->max_retransmit + 1)) - 1) *
                    tx_params->ack_random_factor);
}

int32_t
avs_coap_exchange_lifetime_ms(const avs_coap_tx_params_t *tx_params) {
    return (int32_t) (tx_params->ack_timeout_ms *
            (((1 << tx_params->max_retransmit) - 1) *
                    tx_params->ack_random_factor + 1.0)) + 200000;
}

struct timespec
avs_coap_exchange_lifetime(const avs_coap_tx_params_t *tx_params) {
    return avs_time_from_ms(avs_coap_exchange_lifetime_ms(tx_params));
}

int32_t
avs_coap_max_transmit_span_ms(const avs_coap_tx_params_t *tx_params) {
    return (int32_t)((double)tx_params->ack_timeout_ms
                     * (double)((1 << tx_params->max_retransmit) - 1)
                     * tx_params->ack_random_factor);
}

struct timespec
avs_coap_max_transmit_span(const avs_coap_tx_params_t *tx_params) {
    return avs_time_from_ms(avs_coap_max_transmit_span_ms(tx_params));
}

#if AVS_RAND_MAX >= UINT32_MAX
#define RAND32_ITERATIONS 1
#elif AVS_RAND_MAX >= UINT16_MAX
#define RAND32_ITERATIONS 2
#else
/* standard guarantees RAND_MAX to be at least 32767 */
#define RAND32_ITERATIONS 3
#endif

static uint32_t rand32(unsigned *seed) {
    uint32_t result = 0;
    int i;
    for (i = 0; i < RAND32_ITERATIONS; ++i) {
        result *= (uint32_t) AVS_RAND_MAX + 1;
        result += (uint32_t) avs_rand_r(seed);
    }
    return result;
}

void avs_coap_update_retry_state(avs_coap_retry_state_t *retry_state,
                                 const avs_coap_tx_params_t *tx_params,
                                 unsigned *rand_seed) {
    ++retry_state->retry_count;
    if (retry_state->retry_count == 1) {
        uint32_t delta = (uint32_t) (tx_params->ack_timeout_ms *
                (tx_params->ack_random_factor - 1.0));
        retry_state->recv_timeout_ms = tx_params->ack_timeout_ms +
                (int32_t) (rand32(rand_seed) % delta);
    } else {
        retry_state->recv_timeout_ms *= 2;
    }
}
