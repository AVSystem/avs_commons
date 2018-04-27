/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/unit/test.h>
#include <avsystem/commons/socket.h>

#include <unistd.h>

AVS_UNIT_TEST(backend_mbedtls, chain_loading_from_file) {
    mbedtls_x509_crt *chain = NULL;

    const avs_net_trusted_cert_info_t pem = avs_net_trusted_cert_info_from_file(
            AVS_TEST_BIN_DIR "/certs/root.crt");
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_ca_certs(&chain, &pem));
    mbedtls_x509_crt_free(chain);

    const avs_net_trusted_cert_info_t der = avs_net_trusted_cert_info_from_file(
            AVS_TEST_BIN_DIR "/certs/root.crt.der");

    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_ca_certs(&chain, &der));
    mbedtls_x509_crt_free(chain);

    // Unsupported pkcs12. Loading should fail.
    const avs_net_trusted_cert_info_t p12 = avs_net_trusted_cert_info_from_file(
            AVS_TEST_BIN_DIR "/certs/server.p12");
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_ca_certs(&chain, &p12));
    free(chain);
}

AVS_UNIT_TEST(backend_mbedtls, chain_loading_from_path) {
    mbedtls_x509_crt *chain = NULL;

    const avs_net_trusted_cert_info_t path =
            avs_net_trusted_cert_info_from_path(AVS_TEST_BIN_DIR "/certs");
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_ca_certs(&chain, &path));
    mbedtls_x509_crt_free(chain);

    // Empty directory case.
    char name[] = "/tmp/empty-XXXXXX";
    (void) mkdtemp(name);
    const avs_net_trusted_cert_info_t empty_dir =
            avs_net_trusted_cert_info_from_path(name);
    int retval = _avs_net_mbedtls_load_ca_certs(&chain, &empty_dir);
    (void) rmdir(name);
    AVS_UNIT_ASSERT_SUCCESS(retval);

    // Directory without permissions - hopefully nobody runs tests as root.
    const avs_net_trusted_cert_info_t no_permissions_dir =
            avs_net_trusted_cert_info_from_path("/root");
    AVS_UNIT_ASSERT_FAILED(
            _avs_net_mbedtls_load_ca_certs(&chain, &no_permissions_dir));
    free(chain);
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
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_ca_certs(&chain, &buffer));
    mbedtls_x509_crt_free(chain);
    free(chain);
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
    free(chain);
}

AVS_UNIT_TEST(backend_mbedtls, cert_loading_from_file) {
    mbedtls_x509_crt *cert = NULL;
    const avs_net_client_cert_info_t pem = avs_net_client_cert_info_from_file(
            AVS_TEST_BIN_DIR "/certs/client.crt");
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_client_cert(&cert, &pem));
    mbedtls_x509_crt_free(cert);

    const avs_net_client_cert_info_t der = avs_net_client_cert_info_from_file(
            AVS_TEST_BIN_DIR "/certs/client.crt.der");

    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_client_cert(&cert, &der));
    mbedtls_x509_crt_free(cert);

    // Unsupported pkcs12. Loading should fail.
    const avs_net_client_cert_info_t p12 = avs_net_client_cert_info_from_file(
            AVS_TEST_BIN_DIR "/certs/client.p12");
    AVS_UNIT_ASSERT_FAILED(_avs_net_mbedtls_load_client_cert(&cert, &p12));
    free(cert);
}

AVS_UNIT_TEST(backend_mbedtls, key_loading) {
    mbedtls_pk_context *pk = NULL;
    const avs_net_client_key_info_t pem = avs_net_client_key_info_from_file(
            AVS_TEST_BIN_DIR "/certs/client.key", NULL);
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_client_key(&pk, &pem));
    mbedtls_pk_free(pk);

    const avs_net_client_key_info_t der = avs_net_client_key_info_from_file(
            AVS_TEST_BIN_DIR "/certs/client.key.der", NULL);
    AVS_UNIT_ASSERT_SUCCESS(_avs_net_mbedtls_load_client_key(&pk, &der));
    mbedtls_pk_free(pk);
    free(pk);
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
    free(pk);
}
