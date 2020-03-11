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

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) && defined(AVS_COMMONS_WITH_OPENSSL)

#    define MODULE_NAME avs_crypto_prng
#    include <avs_x_log_config.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_prng.h>

#    include <tinydtls/prng.h>

VISIBILITY_SOURCE_BEGIN

struct avs_crypto_prng_ctx_struct {
    avs_prng_entropy_callback_t seed_callback;
};

static int reseed_if_needed(avs_prng_entropy_callback_t seed_cb) {
    return 0;
}

avs_crypto_prng_ctx_t *
avs_crypto_prng_new(avs_prng_entropy_callback_t seed_cb) {
    return NULL;
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

    return 0;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_OPENSSL)
