/*
 * Copyright 2024 AVSystem <avsystem@avsystem.com>
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

#define DISABLE_SOCKET_OPT_TEST_CASES
#include "../socket_common.h"

#include <avs_commons_posix_init.h>

#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_TEST(socket, ciphersuites_psk) {
    avs_net_socket_t *socket = NULL;
    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    ssl_socket_t *ssl_socket = (ssl_socket_t *) socket;
    int *ciphers = ssl_socket->effective_ciphersuites;

    AVS_UNIT_ASSERT_EQUAL(ciphers[0], 0xC0A8);
    AVS_UNIT_ASSERT_EQUAL(ciphers[1], 0);

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}

AVS_UNIT_TEST(socket, ciphersuites_cert) {
    avs_net_socket_t *socket = NULL;
    avs_net_ssl_configuration_t config = create_default_cert_ssl_config();
    memset(&config.security.data.psk.key, 0,
           sizeof(config.security.data.psk.key));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    ssl_socket_t *ssl_socket = (ssl_socket_t *) socket;
    int *ciphers = ssl_socket->effective_ciphersuites;

    AVS_UNIT_ASSERT_EQUAL(ciphers[0], 0xC0AE);
    AVS_UNIT_ASSERT_EQUAL(ciphers[1], 0);

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}
