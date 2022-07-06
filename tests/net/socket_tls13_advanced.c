/*
 * Copyright 2022 AVSystem <avsystem@avsystem.com>
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

#include "socket_tls13_common.h"

AVS_UNIT_TEST(tls13, verify_with_explicit_version) {
    INIT_TLS13_TEST(SERVER_CERT_VERIFY);
    config.version = AVS_NET_SSL_VERSION_TLSv1_3;

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(tls13, noverify_with_explicit_version) {
    INIT_TLS13_TEST(SERVER_CERT_NOVERIFY);
    config.version = AVS_NET_SSL_VERSION_TLSv1_3;

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(tls13, session_resumption) {
    INIT_TLS13_TEST(SERVER_CERT_NOVERIFY);
    char resumption_buffer[8192] = "";
    config.version = AVS_NET_SSL_VERSION_TLSv1_3;
    config.session_resumption_buffer = resumption_buffer;
    config.session_resumption_buffer_size = sizeof(resumption_buffer);

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    avs_net_socket_shutdown(socket);
    avs_net_socket_close(socket);

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);

    avs_net_socket_opt_value_t opt_value;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
            socket, AVS_NET_SOCKET_OPT_SESSION_RESUMED, &opt_value));
    AVS_UNIT_ASSERT_TRUE(opt_value.flag);

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(tls13, psk) {
    INIT_TLS13_TEST(SERVER_PSK);
    config.version = AVS_NET_SSL_VERSION_TLSv1_3;

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}
