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

#ifndef AVS_COMMONS_CRYPTO_MBEDTLS_PRNG_H
#define AVS_COMMONS_CRYPTO_MBEDTLS_PRNG_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <avsystem/commons/avs_prng.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

struct avs_crypto_prng_ctx_struct {
    mbedtls_ctr_drbg_context mbedtls_prng_ctx;
    avs_prng_entropy_callback_t seed_callback;
    void *user_ptr;
    // FAM to avoid two allocations, but it's actually a single
    // mbedtls_entropy_context
    mbedtls_entropy_context mbedtls_entropy_ctx[];
};

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_CRYPTO_MBEDTLS_PRNG_H */
