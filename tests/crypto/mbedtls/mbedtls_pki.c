/*
 * Copyright 2025 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_init.h>

#include <inttypes.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <avsystem/commons/avs_base64.h>
#include <avsystem/commons/avs_crypto_pki.h>
#include <avsystem/commons/avs_stream_membuf.h>
#include <avsystem/commons/avs_unit_test.h>
#include <avsystem/commons/avs_utils.h>

#include "src/crypto/avs_crypto_utils.h"
#include <mbedtls/version.h> // needed to check value of MBEDTLS_VERSION_NUMBER

AVS_UNIT_TEST(avs_crypto_mbedtls_pki_ec, test_csr_ext_create) {
#define TEST_CN "avs_crypto_pki_ec_test_csr_create"
#define TEST_COUNTRY "PL"
#define TEST_ORG "AVS"
    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    unsigned char key_usage = 0xA8;
    uint8_t secret_key[256];
    size_t secret_key_size = sizeof(secret_key);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_pki_ec_gen(prng_ctx, AVS_CRYPTO_PKI_ECP_GROUP_SECP256R1,
                                  secret_key, &secret_key_size));

    uint8_t csr[512];
    size_t csr_size = sizeof(csr);

    avs_crypto_private_key_info_t key_info =
            avs_crypto_private_key_info_from_buffer(secret_key, secret_key_size,
                                                    NULL);
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_pki_csr_create_ext(
            prng_ctx, &key_info, "SHA256",
            AVS_CRYPTO_PKI_X509_NAME({ AVS_CRYPTO_PKI_X509_NAME_CN, TEST_CN },
                                     { AVS_CRYPTO_PKI_X509_NAME_C,
                                       TEST_COUNTRY },
                                     { AVS_CRYPTO_PKI_X509_NAME_O, TEST_ORG }),
            &key_usage,
            AVS_CRYPTO_PKI_X509_EXTENDED_KEY_USAGE(
                    { "\x2b\x06\x01\x05\x05\x07\x03\x02" }),
            true, csr, &csr_size));

    avs_crypto_prng_free(&prng_ctx);

    AVS_UNIT_ASSERT_TRUE(csr_size > 299);
    AVS_UNIT_ASSERT_TRUE(csr_size <= 367);
    AVS_UNIT_ASSERT_EQUAL_BYTES(csr, "\x30\x82");
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &csr[4],
            "\x30\x81\xfb\x02\x01\x00\x30\x47"
            "\x31\x2a\x30\x28\x06\x03\x55\x04\x03\x0c\x21" TEST_CN
            "\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x0c\x02" TEST_COUNTRY
            "\x31\x0c\x30\x0a\x06\x03\x55\x04\x0a\x0c\x03" TEST_ORG
            "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
            "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04");
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &csr[204],
            "\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02"); // extended key usage
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &csr[216],
            "\x06\x03\x55\x1d\x0f\x04\x04\x03\x02\x03\xa8"); // key usage
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &csr[229], "\x06\x03\x55\x1d\x0e\x04\x16\x04\x14"); // key id tag
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &csr[260],
            "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02"); // signature algorithm
#undef TEST_CN
#undef TEST_ORG
#undef TEST_COUNTRY
}

#if MBEDTLS_VERSION_NUMBER <= 0x03010000
/**
 * For newer versions of mbedTLS calling the avs_crypto_pki_csr_create multiple
 * times will yield different results so we can't compare the output of the old
 * and new API.
 */
AVS_UNIT_TEST(avs_crypto_mbedtls_pki_ec,
              test_csr_create_ext_backward_compatibility) {
#    define TEST_CN "avs_crypto_pki_ec_test_csr_create"
    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    uint8_t secret_key[256];
    size_t secret_key_size = sizeof(secret_key);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_pki_ec_gen(prng_ctx, AVS_CRYPTO_PKI_ECP_GROUP_SECP256R1,
                                  secret_key, &secret_key_size));

    uint8_t csr_ext[512];
    size_t csr_ext_size = sizeof(csr_ext);

    avs_crypto_private_key_info_t key_info =
            avs_crypto_private_key_info_from_buffer(secret_key, secret_key_size,
                                                    NULL);
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_pki_csr_create_ext(
            prng_ctx, &key_info, "SHA256",
            AVS_CRYPTO_PKI_X509_NAME({ AVS_CRYPTO_PKI_X509_NAME_CN, TEST_CN }),
            NULL, NULL, false, csr_ext, &csr_ext_size));

    uint8_t csr[512];
    size_t csr_size = sizeof(csr);
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_pki_csr_create(
            prng_ctx, &key_info, "SHA256",
            AVS_CRYPTO_PKI_X509_NAME({ AVS_CRYPTO_PKI_X509_NAME_CN, TEST_CN }),
            csr, &csr_size));

    avs_crypto_prng_free(&prng_ctx);

    AVS_UNIT_ASSERT_EQUAL(csr_size, csr_ext_size);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(csr, csr_ext, csr_size);
#    undef TEST_CN
}
#endif // MBEDTLS_VERSION_NUMBER <= 0x03010000
