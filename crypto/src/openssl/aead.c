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
#include <openssl/evp.h>

#include <avs_commons_config.h>

#define MODULE_NAME avs_crypto_aead
#include <x_log_config.h>

#include <avsystem/commons/aead.h>

VISIBILITY_SOURCE_BEGIN

#define AES128_KEY_LENGTH_IN_BYTES 16
#define AES256_KEY_LENGTH_IN_BYTES 32

// Both functions adapted from
// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

int
avs_crypto_aead_aes_ccm_encrypt(const unsigned char *key, size_t key_len,
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *aad, size_t aad_len,
                                const unsigned char *input, size_t input_len,
                                unsigned char *tag, size_t tag_len,
                                unsigned char *output) {
    const EVP_CIPHER *cipher;
    if (key_len == AES128_KEY_LENGTH_IN_BYTES) {
        cipher = EVP_aes_128_ccm();
    } else if (key_len == AES256_KEY_LENGTH_IN_BYTES) {
        cipher = EVP_aes_256_ccm();
    } else {
        return -1;
    }

    int len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    int result = 0;
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0
             || EVP_CIPHER_CTX_ctrl(
                    ctx, EVP_CTRL_CCM_SET_IVLEN, (int) iv_len, NULL) <= 0
             || EVP_CIPHER_CTX_ctrl(
                    ctx, EVP_CTRL_CCM_SET_TAG, (int) tag_len, NULL) <= 0
             || EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) <= 0
             || EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int) input_len) <= 0
             || EVP_EncryptUpdate(ctx, NULL, &len, aad, (int) aad_len) <= 0
             || EVP_EncryptUpdate(
                    ctx, output, &len, input, (int) input_len) <= 0
             || EVP_CIPHER_CTX_ctrl(
                    ctx, EVP_CTRL_CCM_GET_TAG, (int) tag_len, tag) <= 0) {
        result = -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

int
avs_crypto_aead_aes_ccm_decrypt(const unsigned char *key, size_t key_len,
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *aad, size_t aad_len,
                                const unsigned char *input, size_t input_len,
                                const unsigned char *tag, size_t tag_len,
                                unsigned char *output) {
    const EVP_CIPHER *cipher;
    if (key_len == AES128_KEY_LENGTH_IN_BYTES) {
        cipher = EVP_aes_128_ccm();
    } else if (key_len == AES256_KEY_LENGTH_IN_BYTES) {
        cipher = EVP_aes_256_ccm();
    } else {
        return -1;
    }

    int len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    int result = 0;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0
             || EVP_CIPHER_CTX_ctrl(
                    ctx, EVP_CTRL_CCM_SET_IVLEN, (int) iv_len, NULL) <= 0
             || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, (int) tag_len,
                                    (void *) (intptr_t) tag) <= 0
             || EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) <= 0
             || EVP_DecryptUpdate(ctx, NULL, &len, NULL, (int) input_len) <= 0
             || EVP_DecryptUpdate(ctx, NULL, &len, aad, (int) aad_len) <= 0
             || EVP_DecryptUpdate(
                    ctx, output, &len, input, (int) input_len) <= 0) {
        result = -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}
