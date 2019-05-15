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

#define AVS_UNIT_ENABLE_SHORT_ASSERTS
#include <avsystem/commons/unit/test.h>

#include <avsystem/commons/aead.h>
#include <avsystem/commons/memory.h>

#include <string.h>

static void test_impl(const unsigned char *key, size_t key_len,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *aad, size_t aad_len,
                      const unsigned char *input, size_t input_len,
                      const unsigned char *ciphertext, size_t ciphertext_len) {
    unsigned char *encrypted =
            (unsigned char *) avs_calloc(input_len, sizeof(unsigned char));

    // Ciphertext = concatenated encrypted data and tag.
    // Encrypted data size is equal to input data len.
    size_t tag_len = ciphertext_len - input_len;
    unsigned char *tag =
            (unsigned char *) avs_calloc(tag_len, sizeof(unsigned char));

    unsigned char *decrypted =
            (unsigned char *) avs_calloc(input_len, sizeof(unsigned char));

    ASSERT_OK(
        avs_crypto_aead_aes_ccm_encrypt(key, key_len,
                                        iv, iv_len,
                                        aad, aad_len,
                                        input, input_len,
                                        tag, tag_len,
                                        encrypted));
    ASSERT_EQ_BYTES_SIZED(encrypted, ciphertext, input_len);
    ASSERT_EQ_BYTES_SIZED(tag, ciphertext + input_len, tag_len);

    ASSERT_OK(
        avs_crypto_aead_aes_ccm_decrypt(key, key_len,
                                        iv, iv_len,
                                        aad, aad_len,
                                        encrypted, input_len,
                                        tag, tag_len,
                                        decrypted));
    ASSERT_EQ_BYTES_SIZED(decrypted, input, input_len);

    avs_free(encrypted);
    avs_free(tag);
    avs_free(decrypted);
}

// Test vectors from draft-ietf-core-object-security-16
// https://tools.ietf.org/html/draft-ietf-core-object-security-16

AVS_UNIT_TEST(avs_crypto_aead, test_vector_4) {
    const unsigned char plaintext[] = {
        0x01, 0xb3, 0x74, 0x76, 0x31
    };

    const unsigned char encryption_key[] = {
        0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
        0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff
    };

    const unsigned char nonce[] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x68
    };

    const unsigned char aad[] = {
        0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x30, 0x40, 0x48, 0x85, 0x01, 0x81, 0x0a,
        0x40, 0x41, 0x14, 0x40
    };

    const unsigned char ciphertext[] = {
        0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c,
        0x16, 0x68, 0xb3, 0x82, 0x5e
    };

    test_impl(encryption_key, sizeof(encryption_key),
              nonce, sizeof(nonce),
              aad, sizeof(aad),
              plaintext, sizeof(plaintext),
              ciphertext, sizeof(ciphertext));
}

AVS_UNIT_TEST(avs_crypto_aead, test_vector_5) {
    const unsigned char plaintext[] = {
        0x01, 0xb3, 0x74, 0x76, 0x31
    };

    const unsigned char encryption_key[] = {
        0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff,
        0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41
    };

    const unsigned char nonce[] = {
        0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
        0x10, 0xc5, 0x2e, 0x99, 0xed
    };

    const unsigned char aad[] = {
        0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x30, 0x40, 0x49, 0x85, 0x01, 0x81, 0x0a,
        0x41, 0x00, 0x41, 0x14, 0x40
    };

    const unsigned char ciphertext[] = {
        0x4e, 0xd3, 0x39, 0xa5, 0xa3, 0x79, 0xb0, 0xb8,
        0xbc, 0x73, 0x1f, 0xff, 0xb0
    };

    test_impl(encryption_key, sizeof(encryption_key),
              nonce, sizeof(nonce),
              aad, sizeof(aad),
              plaintext, sizeof(plaintext),
              ciphertext, sizeof(ciphertext));
}

AVS_UNIT_TEST(avs_crypto_aead, test_vector_6) {
    const unsigned char plaintext[] = {
        0x01, 0xb3, 0x74, 0x76, 0x31
    };

    const unsigned char encryption_key[] = {
        0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88,
        0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd, 0x2b, 0x92
    };

    const unsigned char nonce[] = {
        0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
        0x0b, 0x71, 0x81, 0xb8, 0x4a
    };

    const unsigned char aad[] = {
        0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x30, 0x40, 0x48, 0x85, 0x01, 0x81, 0x0a,
        0x40, 0x41, 0x14, 0x40
    };

    const unsigned char ciphertext[] = {
        0x72, 0xcd, 0x72, 0x73, 0xfd, 0x33, 0x1a, 0xc4,
        0x5c, 0xff, 0xbe, 0x55, 0xc3
    };

    test_impl(encryption_key, sizeof(encryption_key),
              nonce, sizeof(nonce),
              aad, sizeof(aad),
              plaintext, sizeof(plaintext),
              ciphertext, sizeof(ciphertext));
}

AVS_UNIT_TEST(avs_crypto_aead, test_vector_7) {
    const unsigned char plaintext[] = {
        0x45, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
        0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21
    };

    const unsigned char encryption_key[] = {
        0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
        0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
    };

    const unsigned char nonce[] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x68
    };

    const unsigned char aad[] = {
        0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x30, 0x40, 0x48, 0x85, 0x01, 0x81, 0x0a,
        0x40, 0x41, 0x14, 0x40
    };

    const unsigned char ciphertext[] = {
        0xdb, 0xaa, 0xd1, 0xe9, 0xa7, 0xe7, 0xb2, 0xa8,
        0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37, 0x83, 0x03,
        0xcd, 0xaf, 0xae, 0x11, 0x91, 0x06
    };

    test_impl(encryption_key, sizeof(encryption_key),
              nonce, sizeof(nonce),
              aad, sizeof(aad),
              plaintext, sizeof(plaintext),
              ciphertext, sizeof(ciphertext));
}

AVS_UNIT_TEST(avs_crypto_aead, test_vector_8) {
    const unsigned char plaintext[] = {
        0x45, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
        0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21
    };

    const unsigned char encryption_key[] = {
        0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
        0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
    };

    const unsigned char nonce[] = {
        0x47, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x69,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    const unsigned char aad[] = {
        0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x30, 0x40, 0x48, 0x85, 0x01, 0x81, 0x0a,
        0x40, 0x41, 0x14, 0x40
    };

    const unsigned char ciphertext[] = {
        0x4d, 0x4c, 0x13, 0x66, 0x93, 0x84, 0xb6, 0x73,
        0x54, 0xb2, 0xb6, 0x17, 0x5f, 0xf4, 0xb8, 0x65,
        0x8c, 0x66, 0x6a, 0x6c, 0xf8, 0x8e
    };

    test_impl(encryption_key, sizeof(encryption_key),
              nonce, sizeof(nonce),
              aad, sizeof(aad),
              plaintext, sizeof(plaintext),
              ciphertext, sizeof(ciphertext));
}
