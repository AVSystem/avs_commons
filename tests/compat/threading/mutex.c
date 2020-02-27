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

#include <avs_commons_posix_init.h>

#include <avsystem/commons/avs_mutex.h>

#include <pthread.h>

#include <avsystem/commons/avs_unit_test.h>

typedef struct {
    avs_mutex_t *mutex;
    const size_t num_increments;
    int counter;
} thread_func_args_t;

static void *thread_func(void *args_) {
    thread_func_args_t *args = (thread_func_args_t *) args_;

    for (size_t i = 0; i < args->num_increments; ++i) {
        avs_mutex_lock(args->mutex);
        ++args->counter;
        avs_mutex_unlock(args->mutex);
    }

    return NULL;
}

AVS_UNIT_TEST(mutex, basic) {
    pthread_t threads[4];

    avs_mutex_t *mutex = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_create(&mutex));

    thread_func_args_t args = {
        .mutex = mutex,
        .num_increments = 1000,
        .counter = 0
    };

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        AVS_UNIT_ASSERT_SUCCESS(
                pthread_create(&threads[i], NULL, thread_func, &args));
    }

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        void *status = NULL;
        AVS_UNIT_ASSERT_SUCCESS(pthread_join(threads[i], &status));
    }

    avs_mutex_cleanup(&mutex);
    AVS_UNIT_ASSERT_NULL(mutex);

    AVS_UNIT_ASSERT_EQUAL(args.counter,
                          AVS_ARRAY_SIZE(threads) * args.num_increments);
}
