/*
 * Copyright 2023 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_TEST_SOCKET_TLS13_COMMON_H
#define AVS_COMMONS_TEST_SOCKET_TLS13_COMMON_H

#include <avsystem/commons/avs_socket.h>
#include <avsystem/commons/avs_unit_test.h>
#include <avsystem/commons/avs_utils.h>

#define CA_CERT_FILE "../certs/root.crt"
#define CLIENT_CERT_FILE "../certs/client.crt"
#define CLIENT_KEY_FILE "../certs/client.key"
#define SERVER_CERT_FILE "../certs/server.crt"
#define SERVER_KEY_FILE "../certs/server.key"

#define PSK_IDENTITY "test_server"
#define PSK_KEY "5eCr3tP@s$w0rD"

typedef enum {
    SERVER_CERT_VERIFY,
    SERVER_CERT_NOVERIFY,
    SERVER_PSK
} test_server_mode_t;

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

typedef struct {
    const char *port;
    test_server_mode_t mode;
    const char *additional_args;
} test_server_args_t;

FILE *socket_tls13_test_launch_server(test_server_args_t args);
void socket_tls13_test_cleanup_server(FILE **fptr);

#define SCOPED_OPENSSL_SERVER(Name, ...)                           \
    __attribute__((__cleanup__(socket_tls13_test_cleanup_server))) \
            FILE *Name = socket_tls13_test_launch_server(          \
                    (test_server_args_t) { __VA_ARGS__ })

const char *socket_tls13_test_choose_ephemeral_port(void);

avs_net_ssl_configuration_t
socket_tls13_test_default_config(avs_crypto_prng_ctx_t *prng_ctx,
                                 test_server_mode_t mode);

#define INIT_TLS13_TEST(...)                                                   \
    __attribute__((__cleanup__(avs_crypto_prng_free)))                         \
            avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL); \
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);                                        \
    const char *port = socket_tls13_test_choose_ephemeral_port();              \
    SCOPED_OPENSSL_SERVER(server, port, __VA_ARGS__);                          \
    avs_net_ssl_configuration_t config =                                       \
            socket_tls13_test_default_config(prng_ctx,                         \
                                             AVS_VARARG0(__VA_ARGS__))

void socket_tls13_test_assert_connectivity(avs_net_socket_t *socket);

#endif /* AVS_COMMONS_TEST_SOCKET_COMMON_H */
