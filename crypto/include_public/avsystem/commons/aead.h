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

#ifndef AVS_COMMONS_CRYPTO_AEAD_H
#define AVS_COMMONS_CRYPTO_AEAD_H

#include <stddef.h>

/**
 * Encrypts data using AEAD encryption with AES-CCM mode.
 *
 * @param key        Encryption key to use. MUST NOT be NULL.
 * @param key_len    Length of @p key in bytes. For lengths other than 16 or 32
 *                   bytes behavior of this function is undefined.
 * @param iv         Initialization vector (nonce). MUST NOT be NULL.
 * @param iv_len     Length of @p iv . MUST be 7, 8, 9, 10, 11, 12 or 13 bytes.
 *                   For other values behavior of this function is undefined.
 * @param aad        Additional authenticated data.
 * @param aad_len    Length of @p aad .
 * @param input      Data to encrypt.
 * @param input_len  Length of @p input .
 * @param tag_len    Length of tag to generate. MUST be 4, 6, 8, 10, 12, 14
 *                   or 16 bytes. For other values behavior of this function is
 *                   undefined.
 * @param output     Buffer to store encrypted @p input with tag.
 *                   MUST be at least of size @p input_len + @p tag_len .
 *
 * @returns 0 on success, a negative value in case of failure.
 *
 * If this function succeeded, there are @p input_len + @p tag_len bytes
 * written to @p output .
 */
int
avs_crypto_aead_aes_ccm_encrypt(const unsigned char *key, size_t key_len,
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *aad, size_t aad_len,
                                const unsigned char *input, size_t input_len,
                                unsigned char *tag, size_t tag_len,
                                unsigned char *output);

int
avs_crypto_aead_aes_ccm_decrypt(const unsigned char *key, size_t key_len,
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *aad, size_t aad_len,
                                const unsigned char *input, size_t input_len,
                                const unsigned char *tag, size_t tag_len,
                                unsigned char *output);

#endif // AVS_COMMONS_CRYPTO_AEAD_H
