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

#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_unit_test.h>

#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>

#include "../pki.h"

#include "src/crypto/mbedtls/avs_mbedtls_data_loader.h"

void assert_trust_store_loadable(
        const avs_crypto_trusted_cert_info_t *certs,
        const avs_crypto_cert_revocation_list_info_t *crls) {
    mbedtls_x509_crt *crt = NULL;
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_ca_certs(&crt, certs));
    _avs_crypto_mbedtls_x509_crt_cleanup(&crt);

    mbedtls_x509_crl *crl = NULL;
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_crls(&crl, crls));
    _avs_crypto_mbedtls_x509_crl_cleanup(&crl);
}

AVS_UNIT_TEST(backend_mbedtls, chain_loading_from_file) {
    mbedtls_x509_crt *chain = NULL;

    const avs_crypto_trusted_cert_info_t pem =
            avs_crypto_trusted_cert_info_from_file("../certs/root.crt");
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_ca_certs(&chain, &pem));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);

    const avs_crypto_trusted_cert_info_t der =
            avs_crypto_trusted_cert_info_from_file("../certs/root.crt.der");

    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_ca_certs(&chain, &der));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);

    // Unsupported pkcs12. Loading should fail.
    const avs_crypto_trusted_cert_info_t p12 =
            avs_crypto_trusted_cert_info_from_file("../certs/server.p12");
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_mbedtls_load_ca_certs(&chain, &p12));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);
}

AVS_UNIT_TEST(backend_mbedtls, chain_loading_from_path) {
    mbedtls_x509_crt *chain = NULL;

    const avs_crypto_trusted_cert_info_t path =
            avs_crypto_trusted_cert_info_from_path("../certs");
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_ca_certs(&chain, &path));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);

    // Empty directory case.
    {
        char name[] = "/tmp/empty-XXXXXX";
        AVS_UNIT_ASSERT_NOT_NULL(mkdtemp(name));
        const avs_crypto_trusted_cert_info_t empty_dir =
                avs_crypto_trusted_cert_info_from_path(name);
        avs_error_t err = _avs_crypto_mbedtls_load_ca_certs(&chain, &empty_dir);
        (void) rmdir(name);
        AVS_UNIT_ASSERT_SUCCESS(err);
    }
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);

    // Directory without permissions.
    {
        uid_t original_uid = geteuid();
        if (original_uid == 0) {
            // we need to drop root privileges
            // otherwise we have access to everything
            // UID == 65534 is often assigned to the user "nobody"
            AVS_UNIT_ASSERT_SUCCESS(seteuid(65534));
        }

        char name[] = "/tmp/locked-XXXXXX";
        AVS_UNIT_ASSERT_NOT_NULL(mkdtemp(name));
        int retval = chmod(name, 0);
        if (retval) {
            (void) rmdir(name);
        }
        AVS_UNIT_ASSERT_SUCCESS(retval);
        const avs_crypto_trusted_cert_info_t no_permissions_dir =
                avs_crypto_trusted_cert_info_from_path(name);
        avs_error_t err =
                _avs_crypto_mbedtls_load_ca_certs(&chain, &no_permissions_dir);
        (void) rmdir(name);
        AVS_UNIT_ASSERT_FAILED(err);

        if (original_uid == 0) {
            // restore root privileges if we had them
            // we need _POSIX_SAVED_IDS feature for this to work
            AVS_STATIC_ASSERT(_POSIX_SAVED_IDS, posix_saved_ids);
            AVS_UNIT_ASSERT_SUCCESS(seteuid(0));
        }
    }

    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);
}

AVS_UNIT_TEST(backend_mbedtls, chain_loading_from_null) {
    mbedtls_x509_crt *chain = NULL;
    const avs_crypto_trusted_cert_info_t pem =
            avs_crypto_trusted_cert_info_from_file(NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_mbedtls_load_ca_certs(&chain, &pem));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);

    const avs_crypto_trusted_cert_info_t buffer =
            avs_crypto_trusted_cert_info_from_buffer(NULL, 0);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_mbedtls_load_ca_certs(&chain, &buffer));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);

    const avs_crypto_trusted_cert_info_t path =
            avs_crypto_trusted_cert_info_from_path(NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_mbedtls_load_ca_certs(&chain, &path));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);
}

AVS_UNIT_TEST(backend_mbedtls, cert_loading_from_null) {
    mbedtls_x509_crt *chain = NULL;
    const avs_crypto_client_cert_info_t pem =
            avs_crypto_client_cert_info_from_file(NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_mbedtls_load_client_cert(&chain, &pem));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);

    const avs_crypto_client_cert_info_t buffer =
            avs_crypto_client_cert_info_from_buffer(NULL, 0);
    AVS_UNIT_ASSERT_FAILED(
            _avs_crypto_mbedtls_load_client_cert(&chain, &buffer));
    _avs_crypto_mbedtls_x509_crt_cleanup(&chain);
}

AVS_UNIT_TEST(backend_mbedtls, cert_loading_from_file) {
    mbedtls_x509_crt *cert = NULL;
    const avs_crypto_client_cert_info_t pem =
            avs_crypto_client_cert_info_from_file("../certs/client.crt");
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_client_cert(&cert, &pem));
    _avs_crypto_mbedtls_x509_crt_cleanup(&cert);

    const avs_crypto_client_cert_info_t der =
            avs_crypto_client_cert_info_from_file("../certs/client.crt.der");

    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_client_cert(&cert, &der));
    _avs_crypto_mbedtls_x509_crt_cleanup(&cert);

    // Unsupported pkcs12. Loading should fail.
    const avs_crypto_client_cert_info_t p12 =
            avs_crypto_client_cert_info_from_file("../certs/client.p12");
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_mbedtls_load_client_cert(&cert, &p12));
    _avs_crypto_mbedtls_x509_crt_cleanup(&cert);
}

AVS_UNIT_TEST(backend_mbedtls, key_loading) {
    mbedtls_pk_context *pk = NULL;
    const avs_crypto_client_key_info_t pem =
            avs_crypto_client_key_info_from_file("../certs/client.key", NULL);
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_client_key(&pk, &pem));
    _avs_crypto_mbedtls_pk_context_cleanup(&pk);

    const avs_crypto_client_key_info_t der =
            avs_crypto_client_key_info_from_file("../certs/client.key.der",
                                                 NULL);
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_mbedtls_load_client_key(&pk, &der));
    _avs_crypto_mbedtls_pk_context_cleanup(&pk);
}

AVS_UNIT_TEST(backend_mbedtls, key_loading_from_null) {
    mbedtls_pk_context *pk = NULL;
    const avs_crypto_client_key_info_t pem =
            avs_crypto_client_key_info_from_file(NULL, NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_mbedtls_load_client_key(&pk, &pem));
    _avs_crypto_mbedtls_pk_context_cleanup(&pk);

    const avs_crypto_client_key_info_t buffer =
            avs_crypto_client_key_info_from_buffer(NULL, 0, NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_crypto_mbedtls_load_client_key(&pk, &buffer));
    _avs_crypto_mbedtls_pk_context_cleanup(&pk);
}
