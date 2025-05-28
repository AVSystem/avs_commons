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

#include <string.h>

#include <avsystem/commons/avs_log.h>

#include "socket_common_testcases.h"

AVS_UNIT_GLOBAL_INIT(verbose) {
    avs_log_set_default_level((
            avs_log_level_t) (AVS_LOG_QUIET - AVS_MIN(verbose, AVS_LOG_QUIET)));
}

//// avs_net_socket_get_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, udp_get_opt) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_udp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { SUCCESS, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, tcp_get_opt) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_tcp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { SUCCESS, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_get_opt after avs_net_socket_close /////////////////////////

AVS_UNIT_TEST(socket, udp_get_opt_after_close) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_udp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { SUCCESS, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, tcp_get_opt_after_close) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_tcp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { SUCCESS, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_set_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, udp_set_opt) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_udp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { FAIL, AVS_NET_SOCKET_OPT_STATE },
        { FAIL, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { FAIL, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, tcp_set_opt) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_tcp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { FAIL, AVS_NET_SOCKET_OPT_STATE },
        { FAIL, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { FAIL, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_set_opt after avs_net_socket_close /////////////////////////

AVS_UNIT_TEST(socket, udp_set_opt_after_close) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_udp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { FAIL, AVS_NET_SOCKET_OPT_STATE },
        { FAIL, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { FAIL, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, tcp_set_opt_after_close) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_tcp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { FAIL, AVS_NET_SOCKET_OPT_STATE },
        { FAIL, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { FAIL, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_connect ////////////////////////////////////////////////////

#if defined(AVS_COMMONS_NET_WITH_IPV4) && defined(AVS_COMMONS_NET_WITH_IPV6)
AVS_UNIT_TEST(socket, udp_connect_ipv4v6) {
    avs_net_socket_t *listening_socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_udp_socket_create(&listening_socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(listening_socket, "::", "0"));

    char listen_port[sizeof("65536")];
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_local_port(
            listening_socket, listen_port, sizeof(listen_port)));

    char bound_port[sizeof("65536")];
    char new_bound_port[sizeof("65536")];

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_udp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, "0.0.0.0", "0"));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_local_port(socket, bound_port,
                                                          sizeof(bound_port)));
    // Upgrading from IPv4 to IPv6
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "::1", listen_port));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_udp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, "::", bound_port));
    // Downgrading from IPv6 to IPv4
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(socket, "127.0.0.1", listen_port));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_local_port(
            socket, new_bound_port, sizeof(new_bound_port)));
    AVS_UNIT_ASSERT_EQUAL_STRING(new_bound_port, bound_port);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&listening_socket));
}
#endif // defined(AVS_COMMONS_NET_WITH_IPV4) &&
       // defined(AVS_COMMONS_NET_WITH_IPV6)
