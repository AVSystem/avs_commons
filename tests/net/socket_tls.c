/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

#include <stdio.h>
#include <string.h>

#include "socket_common.h"

//// avs_net_socket_get_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, ssl_get_opt) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_ssl_socket_create(&socket, &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_get_opt after avs_net_socket_close /////////////////////////

AVS_UNIT_TEST(socket, ssl_get_opt_after_close) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_ssl_socket_create(&socket, &DEFAULT_SSL_CONFIGURATION));
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
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_set_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, ssl_set_opt) {
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_ssl_socket_create(&socket, &DEFAULT_SSL_CONFIGURATION));
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
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_RECEIVED }
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

#define SMTP_SERVER_HOSTNAME "smtp.gmail.com"
#define SMTP_SERVER_PORT "587"

static void assert_receive_smtp_status(avs_net_socket_t *socket, int status) {
    char line_beginning[16];
    char line_full[16];
    char buffer[1024];
    size_t received = 0;
    snprintf(line_beginning, sizeof(line_beginning), "%d ", status);
    snprintf(line_full, sizeof(line_full), "%d\r\n", status);
    while (1) {
        AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_receive(socket, &received,
                                                       buffer, sizeof(buffer)));
        AVS_UNIT_ASSERT_TRUE(received > 0);
        if (received >= strlen(line_full)
                && memcmp(buffer + received - 2, "\r\n", 2) == 0) {
            size_t line_start = received - 2;
            while (line_start > 0 && buffer[line_start - 1] != '\n') {
                --line_start;
            }
            if (memcmp(buffer + line_start, line_beginning,
                       strlen(line_beginning))
                            == 0
                    || memcmp(buffer + line_start, line_full, strlen(line_full))
                                   == 0) {
                break;
            }
        }
    }
}

AVS_UNIT_TEST(starttls, starttls_smtp) {
    static const char ehlo_msg[] = "EHLO [127.0.0.1]\r\n";
    static const char starttls_msg[] = "STARTTLS\r\n";
    avs_net_socket_t *socket = NULL;
    avs_net_ssl_configuration_t ssl_config;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_tcp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, SMTP_SERVER_HOSTNAME,
                                                   SMTP_SERVER_PORT));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_send(socket, ehlo_msg, strlen(ehlo_msg)));
    assert_receive_smtp_status(socket, 250);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_send(socket, starttls_msg, strlen(starttls_msg)));
    assert_receive_smtp_status(socket, 220);

    memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.version = AVS_NET_SSL_VERSION_TLSv1;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_ssl_socket_decorate_in_place(&socket, &ssl_config));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_send(socket, ehlo_msg, strlen(ehlo_msg)));
    assert_receive_smtp_status(socket, 250);

    avs_net_socket_cleanup(&socket);
}
