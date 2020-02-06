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

#ifndef AVS_COMMONS_CRYPTO_AEAD_H
#define AVS_COMMONS_CRYPTO_AEAD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encrypts data using AEAD encryption with AES-CCM mode.
 *
 * Encrypted data is written to @p output . Authentication tag is written to
 * @p tag .
 * If input is not provided, only authentication tag for given @p aad is
 * generated.
 *
 * @param key        Encryption key to use. MUST NOT be NULL.
 * @param key_len    Length of @p key in bytes. MUST be 16 or 32.
 * @param iv         Initialization vector (nonce). MUST NOT be NULL.
 * @param iv_len     Length of @p iv . MUST be 7, 8, 9, 10, 11, 12 or 13 bytes.
 * @param aad        Additional authenticated data. May be NULL if @p aad_len is
 *                   0.
 * @param aad_len    Length of @p aad .
 * @param input      Data to encrypt. May be NULL if @p input_len is 0.
 * @param input_len  Length of @p input .
 * @param tag        Buffer to store authentication tag. Must be at least of
 *                   length @p tag_len .
 * @param tag_len    Length of tag to generate. MUST be 4, 6, 8, 10, 12, 14
 *                   or 16 bytes.
 * @param output     Buffer to store encrypted @p input . Must be of the same
 *                   length as @p input .
 *
 * @returns 0 on success, a negative value in case of failure.
 */
int avs_crypto_aead_aes_ccm_encrypt(const unsigned char *key,
                                    size_t key_len,
                                    const unsigned char *iv,
                                    size_t iv_len,
                                    const unsigned char *aad,
                                    size_t aad_len,
                                    const unsigned char *input,
                                    size_t input_len,
                                    unsigned char *tag,
                                    size_t tag_len,
                                    unsigned char *output);

/**
 * Decrypts data encrypted using AEAD encryption with AES-CCM mode.
 *
 * Decrypted data is written to @p output if message is authentic.
 *
 * @param key       Decryption key to use. MUST NOT be NULL.
 * @param key_len   Length of @p key in bytes. MUST be 16 or 32.
 * @param iv        Initialization vector (nonce). MUST NOT be NULL.
 * @param iv_len    Length of @p iv . MUST be 7, 8, 9, 10, 11, 12 or 13 bytes.
 * @param aad       Additional authenticated data. May be NULL if @p aad_len is
 *                  0.
 * @param aad_len   Length of @p aad .
 * @param input     Data to decrypt. May be NULL if @p input_len is 0.
 * @param input_len Length of @p input .
 * @param tag       Authentication tag to validate.
 * @param tag_len   Length of authentication tag. MUST be 4, 6, 8, 10, 12, 14
 *                  or 16 bytes.
 * @param output    Buffer to store decrypted @p input . Must be of the same
 *                  length as @p input .
 *
 * @returns 0 on success, a negative value in case of failure or if message
 *          isn't authentic.
 */
int avs_crypto_aead_aes_ccm_decrypt(const unsigned char *key,
                                    size_t key_len,
                                    const unsigned char *iv,
                                    size_t iv_len,
                                    const unsigned char *aad,
                                    size_t aad_len,
                                    const unsigned char *input,
                                    size_t input_len,
                                    const unsigned char *tag,
                                    size_t tag_len,
                                    unsigned char *output);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // AVS_COMMONS_CRYPTO_AEAD_H
