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

AVS_UNIT_TEST(tls13, verify_with_default_version) {
    INIT_TLS13_TEST(SERVER_CERT_VERIFY);

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(tls13, noverify_with_default_version) {
    INIT_TLS13_TEST(SERVER_CERT_NOVERIFY);

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(tls13, noverify_noticket_with_default_version) {
    INIT_TLS13_TEST(SERVER_CERT_NOVERIFY, "-num_tickets 0");

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}
