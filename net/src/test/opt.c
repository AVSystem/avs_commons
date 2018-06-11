/*
 * Copyright 2018 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/socket.h>
#include <avsystem/commons/unit/test.h>

#include <string.h>

static bool is_socket_secure(avs_net_socket_type_t type, void *configuration) {
    avs_net_abstract_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_create(&socket, type, configuration));

    avs_net_socket_opt_value_t value;
    memset(&value, 0, sizeof(value));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
            socket, AVS_NET_SOCKET_OPT_IS_SECURE, &value));
    avs_net_socket_close(socket);

    return value.flag;
}


AVS_UNIT_TEST(get_opt, socket_secure) {
#if defined(WITH_SSL) || defined(WITH_DTLS)
    avs_net_ssl_configuration_t TEST_SSL_CONFIG;
    memset(&TEST_SSL_CONFIG, 0, sizeof(TEST_SSL_CONFIG));
    TEST_SSL_CONFIG.security = avs_net_security_info_from_psk(
            (avs_net_psk_info_t) {
                .psk = "psk",
                .psk_size = sizeof("psk") - 1,
                .identity = "identity",
                .identity_size = sizeof("identity") - 1
            });
#endif // WITH_SSL || WITH_DTLS

#ifdef WITH_SSL
    AVS_UNIT_ASSERT_TRUE(
            is_socket_secure(AVS_NET_SSL_SOCKET, &TEST_SSL_CONFIG));
#endif // WITH_SSL

#ifdef WITH_DTLS
    AVS_UNIT_ASSERT_TRUE(
            is_socket_secure(AVS_NET_DTLS_SOCKET, &TEST_SSL_CONFIG));
#endif // WITH_DTLS
}

AVS_UNIT_TEST(get_opt, socket_insecure) {
    AVS_UNIT_ASSERT_FALSE(is_socket_secure(AVS_NET_TCP_SOCKET, NULL));
    AVS_UNIT_ASSERT_FALSE(is_socket_secure(AVS_NET_UDP_SOCKET, NULL));
}
