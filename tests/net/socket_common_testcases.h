/*
 * Copyright 2025 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_TEST_SOCKET_COMMON_TESTCASES_H
#define AVS_COMMONS_TEST_SOCKET_COMMON_TESTCASES_H

#include <avsystem/commons/avs_socket.h>
#include <avsystem/commons/avs_unit_test.h>

#include "socket_common.h"

typedef enum { SUCCESS, FAIL } test_case_result_t;

typedef struct {
    test_case_result_t expected_result;
    avs_net_socket_opt_key_t tested_option;
} socket_opt_test_case_t;

static void
run_socket_get_opt_test_cases(avs_net_socket_t *socket,
                              const socket_opt_test_case_t test_cases[],
                              size_t test_cases_count) {
    avs_net_socket_opt_value_t opt_val;

    for (size_t i = 0; i < test_cases_count; i++) {
        if (test_cases[i].expected_result == SUCCESS) {
            AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
                    socket, test_cases[i].tested_option, &opt_val));
        } else {
            AVS_UNIT_ASSERT_FAILED(avs_net_socket_get_opt(
                    socket, test_cases[i].tested_option, &opt_val));
        }
    }
}

static void
run_socket_set_opt_test_cases(avs_net_socket_t *socket,
                              const socket_opt_test_case_t test_cases[],
                              size_t test_cases_count) {
    for (size_t i = 0; i < test_cases_count; i++) {
        avs_net_socket_opt_value_t opt_val;
        switch (test_cases[i].tested_option) {
        case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
            opt_val.recv_timeout =
                    avs_time_duration_from_scalar(10, AVS_TIME_S);
            break;
        case AVS_NET_SOCKET_OPT_STATE:
            opt_val.state = AVS_NET_SOCKET_STATE_CONNECTED;
            break;
        case AVS_NET_SOCKET_OPT_ADDR_FAMILY:
        case AVS_NET_SOCKET_OPT_PREFERRED_ADDR_FAMILY:
        case AVS_NET_SOCKET_OPT_FORCED_ADDR_FAMILY:
            opt_val.addr_family = AVS_NET_AF_INET4;
            break;
        case AVS_NET_SOCKET_OPT_MTU:
        case AVS_NET_SOCKET_OPT_INNER_MTU:
            opt_val.mtu = 5;
            break;
        case AVS_NET_SOCKET_OPT_SESSION_RESUMED:
        case AVS_NET_SOCKET_HAS_BUFFERED_DATA:
        case AVS_NET_SOCKET_OPT_CONNECTION_ID_RESUMED:
            opt_val.flag = true;
            break;
        case AVS_NET_SOCKET_OPT_BYTES_SENT:
            opt_val.bytes_sent = 123;
            break;
        case AVS_NET_SOCKET_OPT_BYTES_RECEIVED:
            opt_val.bytes_received = 321;
            break;
        case AVS_NET_SOCKET_OPT_DANE_TLSA_ARRAY:
            AVS_UNREACHABLE("unsupported case");
            break;
        case AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS:
            opt_val.dtls_handshake_timeouts =
                    (avs_net_dtls_handshake_timeouts_t) {
                        .min = avs_time_duration_from_scalar(5, AVS_TIME_S),
                        .max = avs_time_duration_from_scalar(10, AVS_TIME_S)
                    };
            break;
        }

        if (test_cases[i].expected_result == SUCCESS) {
            AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_set_opt(
                    socket, test_cases[i].tested_option, opt_val));
        } else {
            AVS_UNIT_ASSERT_FAILED(avs_net_socket_set_opt(
                    socket, test_cases[i].tested_option, opt_val));
        }
    }
}

#endif /* AVS_COMMONS_TEST_SOCKET_COMMON_TESTCASES_H */
