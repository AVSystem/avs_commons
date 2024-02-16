/*
 * Copyright 2024 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) && defined(AVS_COMMONS_WITH_MBEDTLS)

#    include <mbedtls/version.h>

#    include <mbedtls/ctr_drbg.h>
#    include <mbedtls/entropy.h>

#    ifdef AVS_COMMONS_WITH_MBEDTLS_PSA_RNG
#        include <psa/crypto.h>
#    endif // AVS_COMMONS_WITH_MBEDTLS_PSA_RNG

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>

#    include "avs_mbedtls_prng.h"

#    include "../avs_crypto_global.h"

#    define MODULE_NAME avs_crypto_prng
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#    if !defined(MBEDTLS_CTR_DRBG_C) \
            && !defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
#        error "MBEDTLS_CTR_DRBG_C must be enabled in Mbed TLS configuration if AVS_COMMONS_WITH_MBEDTLS_PSA_RNG is not enabled"
#    endif // !defined(MBEDTLS_CTR_DRBG_C) &&
           // !defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)

#    ifdef MBEDTLS_CTR_DRBG_C
struct avs_crypto_prng_ctx_struct {
    avs_prng_entropy_callback_t seed_callback;
    void *user_ptr;
    mbedtls_ctr_drbg_context mbedtls_prng_ctx;
#        if defined(MBEDTLS_ENTROPY_C) \
                && !defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
    // FAM to avoid two allocations, but it's actually a single
    // mbedtls_entropy_context
    mbedtls_entropy_context mbedtls_entropy_ctx[];
#        endif // defined(MBEDTLS_ENTROPY_C) &&
               // !defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
};

static int
entropy_callback(void *ctx_, unsigned char *out_buf, size_t out_buf_size) {
    avs_crypto_prng_ctx_t *ctx = (avs_crypto_prng_ctx_t *) ctx_;
    return ctx->seed_callback(out_buf, out_buf_size, ctx->user_ptr);
}
#    endif // MBEDTLS_CTR_DRBG_C

#    ifdef AVS_COMMONS_WITH_MBEDTLS_PSA_RNG
// NOTE: This is essentially identical to mbedtls_psa_get_random() from
// mbedtls/psa_util.h. However, that function will not be available if
// MBEDTLS_PSA_CRYPTO_C is not enabled, which may be the case if we're merely
// using an offloaded PSA implementation (e.g. Trusted Firmware).
static int
psa_random_callback(void *ctx, unsigned char *out_buf, size_t out_buf_size) {
    (void) ctx;
    if (psa_generate_random(out_buf, out_buf_size) != PSA_SUCCESS) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    return 0;
}
#    endif // AVS_COMMONS_WITH_MBEDTLS_PSA_RNG

avs_crypto_prng_ctx_t *avs_crypto_prng_new(avs_prng_entropy_callback_t seed_cb,
                                           void *user_ptr) {
    if (avs_is_err(_avs_crypto_ensure_global_state())) {
        return NULL;
    }

    avs_crypto_prng_ctx_t *ctx = NULL;
#    ifdef MBEDTLS_CTR_DRBG_C
#        if defined(MBEDTLS_ENTROPY_C) \
                && !defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
    if (!seed_cb) {
        ctx = (avs_crypto_prng_ctx_t *) avs_calloc(
                1,
                sizeof(avs_crypto_prng_ctx_t)
                        + sizeof(mbedtls_entropy_context));
    } else
#        endif // defined(MBEDTLS_ENTROPY_C) &&
               // !defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
    {
        ctx = (avs_crypto_prng_ctx_t *) avs_calloc(
                1, sizeof(avs_crypto_prng_ctx_t));
    }

    if (!ctx) {
        return NULL;
    }

    mbedtls_ctr_drbg_init(&ctx->mbedtls_prng_ctx);

    int result = -1;
    if (seed_cb) {
        ctx->seed_callback = seed_cb;
        ctx->user_ptr = user_ptr;
        if ((result = mbedtls_ctr_drbg_seed(&ctx->mbedtls_prng_ctx,
                                            entropy_callback, ctx, NULL, 0))) {
            ctx->seed_callback = NULL;
            ctx->user_ptr = NULL;
        }
    }
#        ifdef AVS_COMMONS_WITH_MBEDTLS_PSA_RNG
    (void) result;
#        else // AVS_COMMONS_WITH_MBEDTLS_PSA_RNG
#            ifdef MBEDTLS_ENTROPY_C
    else {
        mbedtls_entropy_init(&ctx->mbedtls_entropy_ctx[0]);
        result = mbedtls_ctr_drbg_seed(&ctx->mbedtls_prng_ctx,
                                       mbedtls_entropy_func,
                                       &ctx->mbedtls_entropy_ctx, NULL, 0);
    }
#            endif // MBEDTLS_ENTROPY_C

    if (result) {
        LOG(ERROR, _("mbedtls_ctr_drbg_seed() failed"));
        avs_crypto_prng_free(&ctx);
    }
#        endif     // AVS_COMMONS_WITH_MBEDTLS_PSA_RNG
#    else          // MBEDTLS_CTR_DRBG_C
    (void) seed_cb;
    (void) user_ptr;
    // Set output to a dummy non-null pointer
    ctx = (avs_crypto_prng_ctx_t *) (intptr_t) "";
#    endif         // MBEDTLS_CTR_DRBG_C

    return ctx;
}

void avs_crypto_prng_free(avs_crypto_prng_ctx_t **ctx) {
    if (ctx && *ctx) {
#    ifdef MBEDTLS_CTR_DRBG_C
        mbedtls_ctr_drbg_free(&(*ctx)->mbedtls_prng_ctx);
#        if defined(MBEDTLS_ENTROPY_C) \
                && !defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
        if (!(*ctx)->seed_callback) {
            mbedtls_entropy_free((*ctx)->mbedtls_entropy_ctx);
        }
#        endif // defined(MBEDTLS_ENTROPY_C) &&
               // !defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
        avs_free(*ctx);
#    endif // MBEDTLS_CTR_DRBG_C
        *ctx = NULL;
    }
}

int _avs_crypto_prng_get_random_cb(avs_crypto_prng_ctx_t *ctx,
                                   avs_crypto_mbedtls_prng_cb_t **out_random_cb,
                                   void **out_random_cb_arg) {
    if (!ctx) {
        return -1;
    }
#    ifdef MBEDTLS_CTR_DRBG_C
#        if defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG) \
                || !defined(MBEDTLS_ENTROPY_C)
    if (ctx->seed_callback)
#        endif // defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG) ||
               // !defined(MBEDTLS_ENTROPY_C)
    {
        *out_random_cb = mbedtls_ctr_drbg_random;
        *out_random_cb_arg = &ctx->mbedtls_prng_ctx;
        return 0;
    }
#    endif // MBEDTLS_CTR_DRBG_C
#    if defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
    *out_random_cb = psa_random_callback;
    *out_random_cb_arg = NULL;
    return 0;
#    elif defined(MBEDTLS_CTR_DRBG_C) && !defined(MBEDTLS_ENTROPY_C)
    return -1;
#    endif
}

int avs_crypto_prng_bytes(avs_crypto_prng_ctx_t *ctx,
                          unsigned char *out_buf,
                          size_t out_buf_size) {
    if (!out_buf || !out_buf_size) {
        return -1;
    }
    avs_crypto_mbedtls_prng_cb_t *random_cb = NULL;
    void *random_cb_arg = NULL;
    if (_avs_crypto_prng_get_random_cb(ctx, &random_cb, &random_cb_arg)) {
        return -1;
    }
    assert(random_cb);
    return random_cb(random_cb_arg, out_buf, out_buf_size);
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
