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

#include <avs_commons_posix_init.h>

#include <avsystem/commons/avs_unit_test.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <stdlib.h>
#include <unistd.h>

#include "src/crypto/openssl/avs_openssl_common.h"
#include "src/crypto/openssl/avs_openssl_data_loader.h"

__attribute__((constructor)) static void global_ssl_init(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    AVS_UNIT_ASSERT_NOT_EQUAL(RAND_load_file("/dev/urandom", -1), 0);
    /* On some OpenSSL version, RAND_load file causes hell to break loose.
     * Get rid of any "uninitialized" memory that it created :( */
    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(0, sbrk(0));
}

static X509_STORE *make_x509_store(void) {
    X509_STORE *store = X509_STORE_new();
    AVS_UNIT_ASSERT_NOT_NULL(store);
    return store;
}

#define WITH_X509_STORE(Context)                                      \
    for (bool _exit = ((Context) = make_x509_store(), false); !_exit; \
         _exit = (X509_STORE_free(Context), true))

AVS_UNIT_TEST(backend_openssl, chain_loading_from_file) {
    X509_STORE *store;

    WITH_X509_STORE(store) {
        const avs_crypto_trusted_cert_info_t pem =
                avs_crypto_trusted_cert_info_from_file("../certs/root.crt");
        AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_ca_certs(store, &pem));
    }

    WITH_X509_STORE(store) {
        const avs_crypto_trusted_cert_info_t der =
                avs_crypto_trusted_cert_info_from_file("../certs/root.crt.der");
        AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_ca_certs(store, &der));
    }

    WITH_X509_STORE(store) {
        // Unsupported.
        const avs_crypto_trusted_cert_info_t p12 =
                avs_crypto_trusted_cert_info_from_file("../certs/server.p12");
        AVS_UNIT_ASSERT_FAILED(_avs_crypto_openssl_load_ca_certs(store, &p12));
    }
}

AVS_UNIT_TEST(backend_openssl, chain_loading_from_path) {
    X509_STORE *store;

    WITH_X509_STORE(store) {
        const avs_crypto_trusted_cert_info_t path =
                avs_crypto_trusted_cert_info_from_path("../certs");
        AVS_UNIT_ASSERT_SUCCESS(
                _avs_crypto_openssl_load_ca_certs(store, &path));
    }

    // Empty directory case.
    char name[] = "/tmp/empty-XXXXXX";
    (void) mkdtemp(name);

    WITH_X509_STORE(store) {
        const avs_crypto_trusted_cert_info_t empty_dir =
                avs_crypto_trusted_cert_info_from_path(name);
        avs_error_t err = _avs_crypto_openssl_load_ca_certs(store, &empty_dir);
        (void) rmdir(name);
        AVS_UNIT_ASSERT_SUCCESS(err);
    }

    WITH_X509_STORE(store) {
        // Directory without permissions - OpenSSL doesn't care.
        const avs_crypto_trusted_cert_info_t no_permissions_dir =
                avs_crypto_trusted_cert_info_from_path("/root");
        AVS_UNIT_ASSERT_SUCCESS(
                _avs_crypto_openssl_load_ca_certs(store, &no_permissions_dir));
    }
}

AVS_UNIT_TEST(backend_openssl, chain_loading_from_null) {
    X509_STORE *store;
    WITH_X509_STORE(store) {
        const avs_crypto_trusted_cert_info_t pem =
                avs_crypto_trusted_cert_info_from_file(NULL);
        AVS_UNIT_ASSERT_FAILED(_avs_crypto_openssl_load_ca_certs(store, &pem));
        const avs_crypto_trusted_cert_info_t buffer =
                avs_crypto_trusted_cert_info_from_buffer(NULL, 0);
        AVS_UNIT_ASSERT_FAILED(
                _avs_crypto_openssl_load_ca_certs(store, &buffer));
        const avs_crypto_trusted_cert_info_t path =
                avs_crypto_trusted_cert_info_from_path(NULL);
        AVS_UNIT_ASSERT_FAILED(_avs_crypto_openssl_load_ca_certs(store, &path));
    }
}

AVS_UNIT_TEST(backend_openssl, cert_loading_from_null) {
    X509 *cert = NULL;
    const avs_crypto_client_cert_info_t pem =
            avs_crypto_client_cert_info_from_file(NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_openssl_load_client_cert(&cert, &pem));
    AVS_UNIT_ASSERT_NULL(cert);
    const avs_crypto_client_cert_info_t buffer =
            avs_crypto_client_cert_info_from_buffer(NULL, 0);
    AVS_UNIT_ASSERT_FAILED(
            _avs_crypto_openssl_load_client_cert(&cert, &buffer));
    AVS_UNIT_ASSERT_NULL(cert);
}

AVS_UNIT_TEST(backend_openssl, key_loading) {
    EVP_PKEY *key = NULL;
    const avs_crypto_client_key_info_t pem =
            avs_crypto_client_key_info_from_file("../certs/client.key", NULL);
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_client_key(&key, &pem));
    AVS_UNIT_ASSERT_NOT_NULL(key);
    EVP_PKEY_free(key);

    key = NULL;
    const avs_crypto_client_key_info_t der =
            avs_crypto_client_key_info_from_file("../certs/client.key.der",
                                                 NULL);
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_client_key(&key, &der));
    AVS_UNIT_ASSERT_NOT_NULL(key);
    EVP_PKEY_free(key);

    key = NULL;
    // Unsupported.
    const avs_crypto_client_key_info_t p12 =
            avs_crypto_client_key_info_from_file("../certs/client.p12", NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_openssl_load_client_key(&key, &p12));
    AVS_UNIT_ASSERT_NULL(key);
}

AVS_UNIT_TEST(backend_openssl, key_loading_from_null) {
    EVP_PKEY *key = NULL;
    const avs_crypto_client_key_info_t pem =
            avs_crypto_client_key_info_from_file(NULL, NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_openssl_load_client_key(&key, &pem));
    AVS_UNIT_ASSERT_NULL(key);
    const avs_crypto_client_key_info_t buffer =
            avs_crypto_client_key_info_from_buffer(NULL, 0, NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_openssl_load_client_key(&key, &buffer));
    AVS_UNIT_ASSERT_NULL(key);
}
