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

#ifndef AVS_COMMONS_TEST_SOCKET_COMMON_H
#define AVS_COMMONS_TEST_SOCKET_COMMON_H

#include <avsystem/commons/avs_socket.h>
#include <avsystem/commons/avs_unit_test.h>

#define DEFAULT_ADDRESS "localhost"
#define DEFAULT_PORT "0"
#define DEFAULT_IDENTITY "sesame"
#define DEFAULT_PSK "password"
#define DEFAULT_CERT "IT IS NOT A REAL CERT"

// Default ciphersuites mandated by LwM2M:
static uint32_t default_ciphersuites[] = { 0xC0A8, 0xC0AE };
static uint32_t default_ciphersuites_num =
        sizeof(default_ciphersuites) / sizeof(uint32_t);

static inline avs_net_ssl_configuration_t create_default_ssl_config() {
    avs_net_ssl_configuration_t config = {
        .version = AVS_NET_SSL_VERSION_DEFAULT,
        .security = avs_net_security_info_from_generic_psk((
                avs_net_generic_psk_info_t) {
            .key = avs_crypto_psk_key_info_from_buffer(DEFAULT_PSK,
                                                       sizeof(DEFAULT_PSK) - 1),
            .identity = avs_crypto_psk_identity_info_from_buffer(
                    DEFAULT_IDENTITY, sizeof(DEFAULT_IDENTITY) - 1),
        }),
        .ciphersuites = {
            .ids = default_ciphersuites,
            .num_ids = default_ciphersuites_num
        },
        .prng_ctx = avs_crypto_prng_new(NULL, NULL)
    };
    AVS_UNIT_ASSERT_NOT_NULL(config.prng_ctx);
    return config;
}

static inline avs_net_ssl_configuration_t create_default_cert_ssl_config() {
    avs_net_ssl_configuration_t config = {
        .version = AVS_NET_SSL_VERSION_DEFAULT,
        .security = {
            .mode = AVS_NET_SECURITY_CERTIFICATE,
        },
        .ciphersuites = {
            .ids = default_ciphersuites,
            .num_ids = default_ciphersuites_num
        },
        .prng_ctx = avs_crypto_prng_new(NULL, NULL)
    };
    AVS_UNIT_ASSERT_NOT_NULL(config.prng_ctx);
    return config;
}

static inline void
cleanup_default_ssl_config(avs_net_ssl_configuration_t *config) {
    avs_crypto_prng_free(&config->prng_ctx);
}

#endif /* AVS_COMMONS_TEST_SOCKET_COMMON_H */
