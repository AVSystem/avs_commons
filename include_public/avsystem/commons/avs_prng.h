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

#ifndef AVS_COMMONS_CRYPTO_PRNG_H
#define AVS_COMMONS_CRYPTO_PRNG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct avs_crypto_prng_ctx_struct avs_crypto_prng_ctx_t;

/**
 * Function called when PRNG requires new portion of random data.
 *
 * @param out_buf     Buffer to be filled with random data.
 * @param out_buf_len Number of bytes to write to @p out_buf .
 * @param user_ptr    User pointer passed in a call to
 *                    @ref avs_crypto_prng_new()
 *
 * @returns 0 on success, negative value otherwise.
 */
typedef int (*avs_prng_entropy_callback_t)(unsigned char *out_buf,
                                           size_t out_buf_len,
                                           void *user_ptr);

/**
 * Creates Pseudo-Random Number Generator context, which can be used then for
 * generating pseudo-random data.
 *
 * @param entropy_cb Pointer to @def avs_prng_entropy_callback_t function. If
 *                   @c NULL, a default entropy source for selected cryptography
 *                   backend will be used.
 * @param user_ptr   User pointer passed to @p entropy_cb in every call.
 *
 * @returns 0 on success, negative value otherwise.
 */
avs_crypto_prng_ctx_t *
avs_crypto_prng_new(avs_prng_entropy_callback_t entropy_cb, void *user_ptr);

/**
 * Frees PRNG context previously created with @ref avs_crypto_prng_new() .
 */
void avs_crypto_prng_free(avs_crypto_prng_ctx_t **ctx);

/**
 * Gets pseudo-random data from initialized PRNG context.
 *
 * @param ctx          Pointer to PRNG context created with
 *                     @ref avs_crypto_prng_new() . MUST NOT be @c NULL .
 * @param out_buf      Pointer to write the data to. MUST NOT be @c NULL .
 * @param out_buf_size Size of @p out_buf . MUST NOT be 0.
 *
 * @returns 0 on success, negative value otherwise.
 */
int avs_crypto_prng_bytes(avs_crypto_prng_ctx_t *ctx,
                          unsigned char *out_buf,
                          size_t out_buf_size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // AVS_COMMONS_CRYPTO_PRNG_H
