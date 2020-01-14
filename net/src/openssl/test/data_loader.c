/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_posix_config.h>

#include <avsystem/commons/socket.h>
#include <avsystem/commons/unit/test.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <unistd.h>

#include "../data_loader.h"

__attribute__((constructor)) static void global_ssl_init(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    AVS_UNIT_ASSERT_NOT_EQUAL(RAND_load_file("/dev/urandom", -1), 0);
    /* On some OpenSSL version, RAND_load file causes hell to break loose.
     * Get rid of any "uninitialized" memory that it created :( */
    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(0, sbrk(0));
}

static SSL_CTX *make_ssl_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
    AVS_UNIT_ASSERT_NOT_NULL(ctx);
    return ctx;
}

#define WITH_OPENSSL_CONTEXT(Context)                                  \
    for (bool _exit = ((Context) = make_ssl_context(), false); !_exit; \
         _exit = (SSL_CTX_free(Context), true))

AVS_UNIT_TEST(backend_openssl, chain_loading_from_file) {
    SSL_CTX *ctx;

    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_trusted_cert_info_t pem =
                avs_net_trusted_cert_info_from_file(AVS_TEST_BIN_DIR
                                                    "/certs/root.crt");
        AVS_UNIT_ASSERT_SUCCESS(_avs_net_openssl_load_ca_certs(ctx, &pem));
    }

    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_trusted_cert_info_t der =
                avs_net_trusted_cert_info_from_file(AVS_TEST_BIN_DIR
                                                    "/certs/root.crt.der");
        AVS_UNIT_ASSERT_SUCCESS(_avs_net_openssl_load_ca_certs(ctx, &der));
    }

    WITH_OPENSSL_CONTEXT(ctx) {
        // Unsupported.
        const avs_net_trusted_cert_info_t p12 =
                avs_net_trusted_cert_info_from_file(AVS_TEST_BIN_DIR
                                                    "/certs/server.p12");
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_ca_certs(ctx, &p12));
    }
}

AVS_UNIT_TEST(backend_openssl, chain_loading_from_path) {
    SSL_CTX *ctx;

    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_trusted_cert_info_t path =
                avs_net_trusted_cert_info_from_path(AVS_TEST_BIN_DIR "/certs");
        AVS_UNIT_ASSERT_SUCCESS(_avs_net_openssl_load_ca_certs(ctx, &path));
    }

    // Empty directory case.
    char name[] = "/tmp/empty-XXXXXX";
    (void) mkdtemp(name);

    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_trusted_cert_info_t empty_dir =
                avs_net_trusted_cert_info_from_path(name);
        avs_error_t err = _avs_net_openssl_load_ca_certs(ctx, &empty_dir);
        (void) rmdir(name);
        AVS_UNIT_ASSERT_SUCCESS(err);
    }

    WITH_OPENSSL_CONTEXT(ctx) {
        // Directory without permissions - OpenSSL doesn't care.
        const avs_net_trusted_cert_info_t no_permissions_dir =
                avs_net_trusted_cert_info_from_path("/root");
        AVS_UNIT_ASSERT_SUCCESS(
                _avs_net_openssl_load_ca_certs(ctx, &no_permissions_dir));
    }
}

AVS_UNIT_TEST(backend_openssl, chain_loading_from_null) {
    SSL_CTX *ctx;
    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_trusted_cert_info_t pem =
                avs_net_trusted_cert_info_from_file(NULL);
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_ca_certs(ctx, &pem));
        const avs_net_trusted_cert_info_t buffer =
                avs_net_trusted_cert_info_from_buffer(NULL, 0);
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_ca_certs(ctx, &buffer));
        const avs_net_trusted_cert_info_t path =
                avs_net_trusted_cert_info_from_path(NULL);
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_ca_certs(ctx, &path));
    }
}

AVS_UNIT_TEST(backend_openssl, cert_loading_from_null) {
    SSL_CTX *ctx;
    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_client_cert_info_t pem =
                avs_net_client_cert_info_from_file(NULL);
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_client_cert(ctx, &pem));
        const avs_net_client_cert_info_t buffer =
                avs_net_client_cert_info_from_buffer(NULL, 0);
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_client_cert(ctx, &buffer));
    }
}

AVS_UNIT_TEST(backend_openssl, key_loading) {
    SSL_CTX *ctx;

    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_client_key_info_t pem = avs_net_client_key_info_from_file(
                AVS_TEST_BIN_DIR "/certs/client.key", NULL);
        AVS_UNIT_ASSERT_SUCCESS(_avs_net_openssl_load_client_key(ctx, &pem));
    }

    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_client_key_info_t der = avs_net_client_key_info_from_file(
                AVS_TEST_BIN_DIR "/certs/client.key.der", NULL);
        AVS_UNIT_ASSERT_SUCCESS(_avs_net_openssl_load_client_key(ctx, &der));
    }

    WITH_OPENSSL_CONTEXT(ctx) {
        // Unsupported.
        const avs_net_client_key_info_t p12 = avs_net_client_key_info_from_file(
                AVS_TEST_BIN_DIR "/certs/client.p12", NULL);
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_client_key(ctx, &p12));
    }
}

AVS_UNIT_TEST(backend_openssl, key_loading_from_null) {
    SSL_CTX *ctx;

    WITH_OPENSSL_CONTEXT(ctx) {
        const avs_net_client_key_info_t pem =
                avs_net_client_key_info_from_file(NULL, NULL);
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_client_key(ctx, &pem));
        const avs_net_client_key_info_t buffer =
                avs_net_client_key_info_from_buffer(NULL, 0, NULL);
        AVS_UNIT_ASSERT_FAILED(_avs_net_openssl_load_client_key(ctx, &buffer));
    }
}
