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

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) \
        && (defined(WITHOUT_SSL) || defined(AVS_COMMONS_WITH_TINYDTLS))

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_prng.h>
#    include <avsystem/commons/avs_time.h>
#    include <avsystem/commons/avs_utils.h>

#    include "../avs_crypto_global.h"

#    define MODULE_NAME avs_crypto_prng
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

struct avs_crypto_prng_ctx_struct {
    avs_rand_seed_t seed;
};

static int
seed_callback(unsigned char *out_buf, size_t out_buf_len, void *user_ptr) {
    (void) user_ptr;
    AVS_STATIC_ASSERT(sizeof(avs_rand_seed_t) == sizeof(uint32_t),
                      seed_size_does_not_match);
    uint32_t seed =
            (uint32_t) (avs_time_real_now().since_real_epoch.seconds
                        ^ avs_time_real_now().since_real_epoch.nanoseconds)
            % UINT32_MAX;
    memcpy(out_buf, (unsigned char *) &seed, out_buf_len);
    return 0;
}

avs_crypto_prng_ctx_t *avs_crypto_prng_new(avs_prng_entropy_callback_t seed_cb,
                                           void *user_ptr) {
    avs_error_t err = _avs_crypto_ensure_global_state();
    if (avs_is_err(err)) {
        return NULL;
    }

    avs_crypto_prng_ctx_t *ctx =
            (avs_crypto_prng_ctx_t *) avs_malloc(sizeof(avs_crypto_prng_ctx_t));

    if (!seed_cb) {
        seed_cb = seed_callback;
    }

    if (ctx
            && seed_cb((unsigned char *) &ctx->seed,
                       sizeof(ctx->seed),
                       user_ptr)) {
        avs_crypto_prng_free(&ctx);
    }

    return ctx;
}

void avs_crypto_prng_free(avs_crypto_prng_ctx_t **ctx) {
    if (ctx) {
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

    size_t complete_chunks_count = out_buf_size / sizeof(uint32_t);
    while (complete_chunks_count--) {
        uint32_t random_value = avs_rand32_r(&ctx->seed);
        memcpy(out_buf, &random_value, sizeof(random_value));
        out_buf += sizeof(random_value);
    }

    size_t remaining_bytes = out_buf_size % sizeof(uint32_t);
    if (remaining_bytes) {
        uint32_t random_value = avs_rand32_r(&ctx->seed);
        memcpy(out_buf, &random_value, remaining_bytes);
    }

    return 0;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) && (defined(WITHOUT_SSL) ||
       // defined(AVS_COMMONS_WITH_TINYDTLS))
