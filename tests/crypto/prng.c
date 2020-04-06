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

#define AVS_UNIT_ENABLE_SHORT_ASSERTS
#include <avsystem/commons/avs_unit_test.h>

#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_prng.h>
#include <avsystem/commons/avs_utils.h>

#include <string.h>

char *test_user_arg = "rand";

static int test_entropy_callback(unsigned char *out_buf,
                                 size_t out_buf_len,
                                 void *user_ptr) {
    ASSERT_TRUE(user_ptr == test_user_arg);
    memset(out_buf, 7, out_buf_len);
    return 0;
}

static void test_impl(avs_prng_entropy_callback_t entropy_cb) {
    const size_t random_data_size = 64;
    avs_crypto_prng_ctx_t *ctx = avs_crypto_prng_new(entropy_cb, test_user_arg);
    ASSERT_NOT_NULL(ctx);

    unsigned char *random_data_buf =
            (unsigned char *) avs_calloc(1, random_data_size);
    ASSERT_NOT_NULL(random_data_buf);

    unsigned char *compare_buf =
            (unsigned char *) avs_calloc(1, random_data_size);
    ASSERT_NOT_NULL(compare_buf);

    size_t test_runs = 2;
    while (test_runs--) {
        ASSERT_OK(
                avs_crypto_prng_bytes(ctx, random_data_buf, random_data_size));
        ASSERT_NE_BYTES_SIZED(random_data_buf, compare_buf, random_data_size);
        memcpy(compare_buf, random_data_buf, random_data_size);
    }

    avs_crypto_prng_free(&ctx);
    ASSERT_NULL(ctx);
    avs_free(random_data_buf);
    avs_free(compare_buf);
}

AVS_UNIT_TEST(avs_crypto_prng, get_random_bytes) {
    test_impl(test_entropy_callback);
}

AVS_UNIT_TEST(avs_crypto_prng, no_callback_defined) {
    test_impl(NULL);
}
