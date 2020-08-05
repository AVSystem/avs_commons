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

#include <inttypes.h>

#include <avsystem/commons/avs_crypto_pki.h>
#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_TEST(avs_crypto_pki_ec, test_ec_gen) {
    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    uint8_t secret_key[256];
    size_t secret_key_size = sizeof(secret_key);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_pki_ec_gen(prng_ctx, AVS_CRYPTO_PKI_ECP_GROUP_SECP256R1,
                                  secret_key, &secret_key_size));

    avs_crypto_prng_free(&prng_ctx);

    // The resulting data shall look like this:
    //
    // SEQUENCE (4 elem)                                     30 77
    //   INTEGER 1                                           02 01 01
    //   OCTET STRING (32 byte) [EC parameters]              04 20 [32bytesData]
    //   [0] (1 elem)                                        A0 0A
    //     OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1  06 08 2A 86 48 CE
    //                                                             3D 03 01 07
    //   [1] (1 elem)                                        A1 44
    //     BIT STRING (520 bit) [private key]                03 42 [66bytesData]
    //
    // (121 bytes total)

    AVS_UNIT_ASSERT_EQUAL(secret_key_size, 121);
    AVS_UNIT_ASSERT_EQUAL_BYTES(secret_key, "\x30\x77\x02\x01\x01\x04\x20");
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &secret_key[39],
            "\xA0\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\xA1\x44\x03\x42");
}

AVS_UNIT_TEST(avs_crypto_pki_ec, test_csr_create) {
#define TEST_CN "avs_crypto_pki_ec_test_csr_create"
    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    uint8_t secret_key[256];
    size_t secret_key_size = sizeof(secret_key);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_pki_ec_gen(prng_ctx, AVS_CRYPTO_PKI_ECP_GROUP_SECP256R1,
                                  secret_key, &secret_key_size));

    uint8_t csr[512];
    size_t csr_size = sizeof(csr);

    avs_crypto_client_key_info_t key_info =
            avs_crypto_client_key_info_from_buffer(secret_key, secret_key_size,
                                                   NULL);
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_pki_csr_create(
            prng_ctx, &key_info, "SHA256",
            AVS_CRYPTO_PKI_X509_NAME({ AVS_CRYPTO_PKI_X509_NAME_CN, TEST_CN }),
            csr, &csr_size));

    avs_crypto_prng_free(&prng_ctx);

    // The resulting data shall look like this:
    //
    // SEQUENCE (3 elem)                                         30 81 ??
    //   SEQUENCE (4 elem)                                       30 81 8E
    //     INTEGER 0                                             02 01 00
    //     SEQUENCE (1 elem)                                     30 2C
    //       SET (1 elem)                                        31 2A
    //         SEQUENCE (2 elem)                                 30 28
    //           OBJECT IDENTIFIER 2.5.4.3 commonName            06 03 55 04 03
    //           UTF8String avs_crypto_pki_ec_test_csr_create    0C 21 [string]
    //     SEQUENCE (2 elem)                                     30 59
    //       SEQUENCE (2 elem)                                   30 13
    //         OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey   06 07 2A 86 48
    //                                                           CE 3D 02 01
    //         OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1  06 08 2A 86 48
    //                                                           CE 3D 03 01 07
    //       BIT STRING (520 bit)                                03 42 [66bytes]
    //     [0] (0 elem)                                          A0 00
    //   SEQUENCE (1-2 elem)                                     30 (0A or 0C)
    //     OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 06 08 2A 86 48
    //                                                           CE 3D 04 03 02
    //     NULL                                                  05 00 (opt)
    //   BIT STRING (1 elem)                                     03 ?? 00
    //     SEQUENCE (2 elem)                                     30 ??
    //       INTEGER (max 256 bit)                               02 ??
    //       INTEGER (max 256 bit)                               02 ??

    AVS_UNIT_ASSERT_TRUE(csr_size > 169);
    AVS_UNIT_ASSERT_TRUE(csr_size <= 237);
    AVS_UNIT_ASSERT_EQUAL_BYTES(csr, "\x30\x81");
    AVS_UNIT_ASSERT_EQUAL(csr[2], csr_size - 3);
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &csr[3], "\x30\x81\x8E\x02\x01\x00\x30\x2C\x31\x2A\x30\x28\x06\x03"
                     "\x55\x04\x03\x0C\x21" TEST_CN
                     "\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06"
                     "\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42");
    AVS_UNIT_ASSERT_EQUAL_BYTES(&csr[146], "\xA0\x00\x30");
    AVS_UNIT_ASSERT_TRUE(csr[149] == 0x0A || csr[149] == 0x0C);
    bool has_additional_null_md = (csr[149] == 0x0C);
    AVS_UNIT_ASSERT_EQUAL_BYTES(&csr[150],
                                "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02");
    size_t signature_offset;
    if (has_additional_null_md) {
        AVS_UNIT_ASSERT_EQUAL_BYTES(&csr[160], "\x05\x00");
        signature_offset = 162;
    } else {
        signature_offset = 160;
    }
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset], 0x03);
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset + 1],
                          csr_size - signature_offset - 2);
    AVS_UNIT_ASSERT_EQUAL_BYTES(&csr[signature_offset + 2], "\x00\x30");
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset + 4],
                          csr_size - signature_offset - 5);
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset + 5], 0x02);
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset + 7 + csr[signature_offset + 6]],
                          0x02);
    AVS_UNIT_ASSERT_EQUAL(
            csr[signature_offset + 6]
                    + csr[signature_offset + 8 + csr[signature_offset + 6]],
            csr_size - signature_offset - 9);
#undef TEST_CN
}
