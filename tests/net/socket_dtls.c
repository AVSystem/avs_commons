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

#include "socket_common_testcases.h"

//// avs_net_socket_get_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, dtls_get_opt) {
    avs_net_socket_t *socket = NULL;

    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_dtls_socket_create(&socket, &config));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { SUCCESS, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}

//// avs_net_socket_get_opt after avs_net_socket_close /////////////////////////

AVS_UNIT_TEST(socket, dtls_get_opt_after_close) {
    avs_net_socket_t *socket = NULL;

    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_dtls_socket_create(&socket, &config));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED },
        { SUCCESS, AVS_NET_SOCKET_HAS_BUFFERED_DATA },
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}

//// avs_net_socket_set_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, dtls_set_opt) {
    avs_net_socket_t *socket = NULL;

    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_dtls_socket_create(&socket, &config));
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
#ifndef AVS_COMMONS_TINYDTLS_TEST
        { SUCCESS, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
#else  // AVS_COMMONS_TINYDTLS_TEST
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
#endif // AVS_COMMONS_TINYDTLS_TEST
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}

//// avs_net_socket_set_opt after avs_net_socket_close /////////////////////////

AVS_UNIT_TEST(socket, dtls_set_opt_after_close) {
    avs_net_socket_t *socket = NULL;

    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_dtls_socket_create(&socket, &config));
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
#ifndef AVS_COMMONS_TINYDTLS_TEST
        { SUCCESS, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
#else  // AVS_COMMONS_TINYDTLS_TEST
        { FAIL, AVS_NET_SOCKET_OPT_DTLS_HANDSHAKE_TIMEOUTS }
#endif // AVS_COMMONS_TINYDTLS_TEST
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}
