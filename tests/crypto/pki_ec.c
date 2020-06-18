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
