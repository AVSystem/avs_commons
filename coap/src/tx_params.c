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

#include <avsystem/commons/coap/tx_params.h>
#include <avsystem/commons/time.h>
#include <avsystem/commons/utils.h>

VISIBILITY_SOURCE_BEGIN

const avs_time_duration_t AVS_COAP_SEPARATE_RESPONSE_TIMEOUT = { 30, 0 };

bool avs_coap_tx_params_valid(const avs_coap_tx_params_t *tx_params,
                              const char **error_details) {
    // ACK_TIMEOUT below 1 second would violate the guidelines of [RFC5405].
    // -- RFC 7252, 4.8.1
    if (avs_time_duration_less(tx_params->ack_timeout,
                               avs_time_duration_from_scalar(1, AVS_TIME_S))) {
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

avs_time_duration_t
avs_coap_max_transmit_wait(const avs_coap_tx_params_t *tx_params) {
    return avs_time_duration_fmul(tx_params->ack_timeout,
                                  ((1 << (tx_params->max_retransmit + 1)) - 1)
                                          * tx_params->ack_random_factor);
}

avs_time_duration_t
avs_coap_exchange_lifetime(const avs_coap_tx_params_t *tx_params) {
    return avs_time_duration_add(
            avs_time_duration_fmul(tx_params->ack_timeout,
                                   ((1 << tx_params->max_retransmit) - 1) *
                                           tx_params->ack_random_factor + 1.0),
            avs_time_duration_from_scalar(20, AVS_TIME_S));
}

avs_time_duration_t
avs_coap_max_transmit_span(const avs_coap_tx_params_t *tx_params) {
    return avs_time_duration_fmul(tx_params->ack_timeout,
                                  (double)((1 << tx_params->max_retransmit) - 1)
                                          * tx_params->ack_random_factor);
}

#if AVS_RAND_MAX >= INT64_MAX
#define RAND63_ITERATIONS 1
#elif AVS_RAND_MAX >= 3037000499 // ceil(2^(63/2)) - 1
#define RAND63_ITERATIONS 2
#elif AVS_RAND_MAX >= ((1 << 21) - 1)
#define RAND63_ITERATIONS 3
#elif AVS_RAND_MAX >= 55108 // ceil(2^(63/4)) - 1
#define RAND63_ITERATIONS 4
#else // if AVS_RAND_MAX >= 6208 // ceil(2^(63/5)) - 1
#define RAND63_ITERATIONS 5
#endif

static int64_t rand63(unsigned *seed) {
    uint64_t result = 0;
    int i;
    for (i = 0; i < RAND63_ITERATIONS; ++i) {
        result *= (uint64_t) AVS_RAND_MAX + 1;
        result += (uint64_t) avs_rand_r(seed);
    }
    return (int64_t) (result & INT64_MAX);
}

void avs_coap_update_retry_state(avs_coap_retry_state_t *retry_state,
                                 const avs_coap_tx_params_t *tx_params,
                                 unsigned *rand_seed) {
    ++retry_state->retry_count;
    if (retry_state->retry_count == 1) {
        avs_time_duration_t delta =
                avs_time_duration_fmul(tx_params->ack_timeout,
                                       tx_params->ack_random_factor - 1.0);
        int64_t delta_ns;
        int err = avs_time_duration_to_scalar(&delta_ns, AVS_TIME_NS, delta);
        (void) err;
        assert(!err);
        assert(delta_ns > 0);
        retry_state->recv_timeout =
                avs_time_duration_add(tx_params->ack_timeout,
                                      avs_time_duration_from_scalar(
                                              rand63(rand_seed) % delta_ns,
                                              AVS_TIME_NS));
    } else {
        retry_state->recv_timeout =
                avs_time_duration_mul(retry_state->recv_timeout, 2);
    }
}
