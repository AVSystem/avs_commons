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

#ifndef AVS_COMMONS_CRYPTO_HKDF_H
#define AVS_COMMONS_CRYPTO_HKDF_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Derives a new key from input data using HKDF SHA-256 key derivation function.
 * See https://tools.ietf.org/html/rfc5869 for details.
 *
 * @param salt          Optional salt value. Must not be NULL if
 *                      @p salt_len != 0.
 * @param salt_len      Length of @p salt in bytes.
 * @param ikm           Input keying material. Must not be NULL.
 * @param ikm_len       Length of @p ikm in bytes. Must be non-zero.
 * @param info          Optional context and application specific information
 *                      string. Must not be NULL if @p info_len != 0.
 * @param info_len      Length of @p info in bytes.
 * @param out_okm       Output keing material. Must not be NULL.
 * @param inout_okm_len At the beginning, it must contain size of @p out_okm
 *                      buffer. After successfull call, it will contain number
 *                      of bytes written to @p out_okm .
 *
 * @returns 0 on success, a negative value in case of failure.
 */
int avs_crypto_hkdf_sha_256(const unsigned char *salt,
                            size_t salt_len,
                            const unsigned char *ikm,
                            size_t ikm_len,
                            const unsigned char *info,
                            size_t info_len,
                            unsigned char *out_okm,
                            size_t *inout_okm_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // AVS_COMMONS_CRYPTO_HKDF_H
