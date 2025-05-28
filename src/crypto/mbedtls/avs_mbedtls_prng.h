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

#ifndef AVS_COMMONS_CRYPTO_MBEDTLS_PRNG_H
#define AVS_COMMONS_CRYPTO_MBEDTLS_PRNG_H

#include <avsystem/commons/avs_prng.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef int avs_crypto_mbedtls_prng_cb_t(void *arg,
                                         unsigned char *out_buf,
                                         size_t out_buf_size);

int _avs_crypto_prng_get_random_cb(avs_crypto_prng_ctx_t *ctx,
                                   avs_crypto_mbedtls_prng_cb_t **out_random_cb,
                                   void **out_random_cb_arg);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_CRYPTO_MBEDTLS_PRNG_H */
