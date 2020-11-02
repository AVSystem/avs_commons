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

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) && defined(AVS_COMMONS_WITH_MBEDTLS)

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>

#    include "avs_mbedtls_prng.h"

#    include "../avs_crypto_global.h"

#    define MODULE_NAME avs_crypto_prng
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static int
entropy_callback(void *ctx_, unsigned char *out_buf, size_t out_buf_size) {
    avs_crypto_prng_ctx_t *ctx = (avs_crypto_prng_ctx_t *) ctx_;
    return ctx->seed_callback(out_buf, out_buf_size, ctx->user_ptr);
}

avs_crypto_prng_ctx_t *avs_crypto_prng_new(avs_prng_entropy_callback_t seed_cb,
                                           void *user_ptr) {
    if (avs_is_err(_avs_crypto_ensure_global_state())) {
        return NULL;
    }

    avs_crypto_prng_ctx_t *ctx = NULL;
    if (seed_cb) {
        ctx = (avs_crypto_prng_ctx_t *) avs_calloc(
                1, sizeof(avs_crypto_prng_ctx_t));
    } else {
        ctx = (avs_crypto_prng_ctx_t *) avs_calloc(
                1,
                sizeof(avs_crypto_prng_ctx_t)
                        + sizeof(mbedtls_entropy_context));
    }

    if (!ctx) {
        return NULL;
    }

    mbedtls_ctr_drbg_init(&ctx->mbedtls_prng_ctx);
    ctx->seed_callback = seed_cb;

    int result = 0;
    if (seed_cb) {
        ctx->user_ptr = user_ptr;
        result = mbedtls_ctr_drbg_seed(&ctx->mbedtls_prng_ctx, entropy_callback,
                                       ctx, NULL, 0);
    } else {
        mbedtls_entropy_init(&ctx->mbedtls_entropy_ctx[0]);
        result = mbedtls_ctr_drbg_seed(&ctx->mbedtls_prng_ctx,
                                       mbedtls_entropy_func,
                                       &ctx->mbedtls_entropy_ctx, NULL, 0);
    }

    if (result) {
        LOG(ERROR, _("mbedtls_ctr_drbg_seed() failed"));
        avs_crypto_prng_free(&ctx);
    }

    return ctx;
}

void avs_crypto_prng_free(avs_crypto_prng_ctx_t **ctx) {
    if (ctx && *ctx) {
        mbedtls_ctr_drbg_free(&(*ctx)->mbedtls_prng_ctx);
        avs_free(*ctx);
        *ctx = NULL;
    }
}

int avs_crypto_prng_bytes(avs_crypto_prng_ctx_t *ctx,
                          unsigned char *out_buf,
                          size_t out_buf_size) {
    if (!ctx || !out_buf || !out_buf_size) {
        return -1;
    }
    return mbedtls_ctr_drbg_random(&ctx->mbedtls_prng_ctx, out_buf,
                                   out_buf_size);
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
