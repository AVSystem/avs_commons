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

#include <avsystem/commons/memory.h>
#include <avsystem/commons/socket.h>
#include <avsystem/commons/unit/test.h>

#include <unistd.h>

#include <sys/stat.h>

#include "src/net/mbedtls/mbedtls_data_loader.h"

AVS_UNIT_TEST(backend_mbedtls, chain_loading_from_file) {
    mbedtls_x509_crt *chain = NULL;

    const avs_net_trusted_cert_info_t pem =
            avs_net_trusted_cert_info_from_file("../certs/root.crt");
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_ca_certs(&chain, &pem));
    mbedtls_x509_crt_free(chain);

    const avs_net_trusted_cert_info_t der =
            avs_net_trusted_cert_info_from_file("../certs/root.crt.der");

    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_ca_certs(&chain, &der));
    mbedtls_x509_crt_free(chain);

    // Unsupported pkcs12. Loading should fail.
    const avs_net_trusted_cert_info_t p12 =
            avs_net_trusted_cert_info_from_file("../certs/server.p12");
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_ca_certs(&chain, &p12));
    avs_free(chain);
}

AVS_UNIT_TEST(backend_mbedtls, chain_loading_from_path) {
    mbedtls_x509_crt *chain = NULL;

    const avs_net_trusted_cert_info_t path =
            avs_net_trusted_cert_info_from_path("../certs");
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_ca_certs(&chain, &path));
    mbedtls_x509_crt_free(chain);

    // Empty directory case.
    {
        char name[] = "/tmp/empty-XXXXXX";
        AVS_UNIT_ASSERT_NOT_NULL(mkdtemp(name));
        const avs_net_trusted_cert_info_t empty_dir =
                avs_net_trusted_cert_info_from_path(name);
        avs_error_t err = _avs_net_mbedtls_load_ca_certs(&chain, &empty_dir);
        (void) rmdir(name);
        AVS_UNIT_ASSERT_SUCCESS(err);
    }

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
        const avs_net_trusted_cert_info_t no_permissions_dir =
                avs_net_trusted_cert_info_from_path(name);
        avs_error_t err =
                _avs_net_mbedtls_load_ca_certs(&chain, &no_permissions_dir);
        (void) rmdir(name);
        AVS_UNIT_ASSERT_FAILED(err);

        if (original_uid == 0) {
            // restore root privileges if we had them
            // we need _POSIX_SAVED_IDS feature for this to work
            AVS_STATIC_ASSERT(_POSIX_SAVED_IDS, posix_saved_ids);
            AVS_UNIT_ASSERT_SUCCESS(seteuid(0));
        }
    }

    avs_free(chain);
}

AVS_UNIT_TEST(backend_mbedtls, chain_loading_from_null) {
    mbedtls_x509_crt *chain = NULL;
    const avs_net_trusted_cert_info_t pem =
            avs_net_trusted_cert_info_from_file(NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_ca_certs(&chain, &pem));
    mbedtls_x509_crt_free(chain);

    const avs_net_trusted_cert_info_t buffer =
            avs_net_trusted_cert_info_from_buffer(NULL, 0);
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_ca_certs(&chain, &buffer));
    mbedtls_x509_crt_free(chain);

    const avs_net_trusted_cert_info_t path =
            avs_net_trusted_cert_info_from_path(NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_ca_certs(&chain, &path));
    mbedtls_x509_crt_free(chain);
    avs_free(chain);
}

AVS_UNIT_TEST(backend_mbedtls, cert_loading_from_null) {
    mbedtls_x509_crt *chain = NULL;
    const avs_net_client_cert_info_t pem =
            avs_net_client_cert_info_from_file(NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_client_cert(&chain, &pem));
    mbedtls_x509_crt_free(chain);

    const avs_net_client_cert_info_t buffer =
            avs_net_client_cert_info_from_buffer(NULL, 0);
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_client_cert(&chain, &buffer));
    mbedtls_x509_crt_free(chain);
    avs_free(chain);
}

AVS_UNIT_TEST(backend_mbedtls, cert_loading_from_file) {
    mbedtls_x509_crt *cert = NULL;
    const avs_net_client_cert_info_t pem =
            avs_net_client_cert_info_from_file("../certs/client.crt");
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_client_cert(&cert, &pem));
    mbedtls_x509_crt_free(cert);

    const avs_net_client_cert_info_t der =
            avs_net_client_cert_info_from_file("../certs/client.crt.der");

    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_client_cert(&cert, &der));
    mbedtls_x509_crt_free(cert);

    // Unsupported pkcs12. Loading should fail.
    const avs_net_client_cert_info_t p12 =
            avs_net_client_cert_info_from_file("../certs/client.p12");
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_client_cert(&cert, &p12));
    avs_free(cert);
}

AVS_UNIT_TEST(backend_mbedtls, key_loading) {
    mbedtls_pk_context *pk = NULL;
    const avs_net_client_key_info_t pem =
            avs_net_client_key_info_from_file("../certs/client.key", NULL);
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_client_key(&pk, &pem));
    mbedtls_pk_free(pk);

    const avs_net_client_key_info_t der =
            avs_net_client_key_info_from_file("../certs/client.key.der", NULL);
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_client_key(&pk, &der));
    mbedtls_pk_free(pk);
    avs_free(pk);
}

AVS_UNIT_TEST(backend_mbedtls, key_loading_from_null) {
    mbedtls_pk_context *pk = NULL;
    const avs_net_client_key_info_t pem =
            avs_net_client_key_info_from_file(NULL, NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_client_key(&pk, &pem));
    mbedtls_pk_free(pk);

    const avs_net_client_key_info_t buffer =
            avs_net_client_key_info_from_buffer(NULL, 0, NULL);
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_client_key(&pk, &buffer));
    mbedtls_pk_free(pk);
    avs_free(pk);
}
