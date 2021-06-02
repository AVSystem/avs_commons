/*
 * Copyright 2021 AVSystem <avsystem@avsystem.com>
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

#include <openssl/ssl.h>

#define DISABLE_SOCKET_OPT_TEST_CASES
#include "../socket_common.h"

#include <avs_commons_posix_init.h>

#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_TEST(socket, ciphersuites_psk) {
    avs_net_socket_t *socket = NULL;
    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    ssl_socket_t *ssl_socket = (ssl_socket_t *) socket;

    AVS_UNIT_ASSERT_EQUAL(ssl_socket->enabled_ciphersuites.num_ids, 2);

    ssl_socket->ssl = SSL_new(ssl_socket->ctx);
    AVS_UNIT_ASSERT_NOT_NULL(ssl_socket->ssl);

    AVS_UNIT_ASSERT_SUCCESS(fix_socket_ciphersuites(ssl_socket));

    // We remove TLS 1.3 ciphersuites, because all of them can be used with both
    // PSK and certs, so they are not interesting in terms of this test
    SSL_set_ciphersuites(ssl_socket->ssl, "");

    STACK_OF(SSL_CIPHER) *ciphers = SSL_get1_supported_ciphers(ssl_socket->ssl);
    AVS_UNIT_ASSERT_EQUAL(sk_SSL_CIPHER_num(ciphers), 1);
    const char *cipher_name =
            SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, 0));
    sk_SSL_CIPHER_free(ciphers);

    AVS_UNIT_ASSERT_EQUAL(strcmp(cipher_name, "PSK-AES128-CCM8"), 0);

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}

AVS_UNIT_TEST(socket, ciphersuites_cert) {
    avs_net_socket_t *socket = NULL;
    avs_net_ssl_configuration_t config = create_default_cert_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    ssl_socket_t *ssl_socket = (ssl_socket_t *) socket;

    AVS_UNIT_ASSERT_EQUAL(ssl_socket->enabled_ciphersuites.num_ids, 2);

    ssl_socket->ssl = SSL_new(ssl_socket->ctx);
    AVS_UNIT_ASSERT_NOT_NULL(ssl_socket->ssl);

    AVS_UNIT_ASSERT_SUCCESS(fix_socket_ciphersuites(ssl_socket));

    // We remove TLS 1.3 ciphersuites, because all of them can be used with both
    // PSK and certs, so they are not interesting in terms of this test
    SSL_set_ciphersuites(ssl_socket->ssl, "");

    STACK_OF(SSL_CIPHER) *ciphers = SSL_get1_supported_ciphers(ssl_socket->ssl);
    AVS_UNIT_ASSERT_EQUAL(sk_SSL_CIPHER_num(ciphers), 1);
    const char *cipher_name =
            SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, 0));
    sk_SSL_CIPHER_free(ciphers);

    AVS_UNIT_ASSERT_EQUAL(strcmp(cipher_name, "ECDHE-ECDSA-AES128-CCM8"), 0);

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}
