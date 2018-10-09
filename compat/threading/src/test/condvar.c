/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_posix_config.h>

#include <avsystem/commons/condvar.h>

#include <pthread.h>
#include <string.h>

#include <avsystem/commons/unit/test.h>

// Test cases adapted from:
// https://github.com/v8/v8/blob/master/test/unittests/base/platform/condition-variable-unittest.cc
// Copyright 2014 the V8 project authors. All rights reserved.
// Used under a BSD-style license (https://github.com/v8/v8/blob/master/LICENSE)

AVS_UNIT_TEST(condvar, wait_after_notify_on_same_thread) {
    for (int64_t i = 0; i < 10; ++i) {
        avs_mutex_t *mutex = NULL;
        avs_condvar_t *cv = NULL;

        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_create(&mutex));
        AVS_UNIT_ASSERT_SUCCESS(avs_condvar_create(&cv));

        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(mutex));

        AVS_UNIT_ASSERT_SUCCESS(avs_condvar_notify(cv));
        AVS_UNIT_ASSERT_EQUAL(avs_condvar_wait(
                cv, mutex,
                avs_time_monotonic_add(
                        avs_time_monotonic_now(),
                        avs_time_duration_from_scalar(i, AVS_TIME_MS))),
                1); // timeout

        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(mutex));

        avs_condvar_cleanup(&cv);
        avs_mutex_cleanup(&mutex);
    }
}

typedef struct {
    pthread_t thread;
    bool running;
    bool finished;
    avs_condvar_t *cv;
    avs_mutex_t *mutex;
} thread_with_mutex_and_condition_variable_t;

static void *thread_with_mutex_and_condition_variable_func(void *self_) {
    thread_with_mutex_and_condition_variable_t *self =
            (thread_with_mutex_and_condition_variable_t *) self_;

    avs_mutex_lock(self->mutex);
    self->running = true;
    avs_condvar_notify(self->cv);
    while (self->running) {
        avs_condvar_wait(self->cv, self->mutex, AVS_TIME_MONOTONIC_INVALID);
    }
    self->finished = true;
    avs_condvar_notify(self->cv);
    avs_mutex_unlock(self->mutex);
    return NULL;
}

AVS_UNIT_TEST(condvar, multiple_threads_with_separate_condition_variables) {
    thread_with_mutex_and_condition_variable_t threads[4];
    memset(threads, 0, sizeof(threads));

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        AVS_UNIT_ASSERT_SUCCESS(avs_condvar_create(&threads[i].cv));
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_create(&threads[i].mutex));
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(threads[i].mutex));
        AVS_UNIT_ASSERT_FALSE(threads[i].running);
        AVS_UNIT_ASSERT_FALSE(threads[i].finished);
        AVS_UNIT_ASSERT_SUCCESS(pthread_create(
                &threads[i].thread,
                NULL,
                thread_with_mutex_and_condition_variable_func,
                &threads[i]));
        // wait for the thread to start
        while (!threads[i].running) {
            AVS_UNIT_ASSERT_SUCCESS(
                    avs_condvar_wait(threads[i].cv, threads[i].mutex,
                                     AVS_TIME_MONOTONIC_INVALID));
        }
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(threads[i].mutex));
    }

    for (ssize_t i = AVS_ARRAY_SIZE(threads) - 1; i >= 0; --i) {
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(threads[i].mutex));
        AVS_UNIT_ASSERT_TRUE(threads[i].running);
        AVS_UNIT_ASSERT_FALSE(threads[i].finished);
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(threads[i].mutex));
    }

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(threads[i].mutex));
        AVS_UNIT_ASSERT_TRUE(threads[i].running);
        AVS_UNIT_ASSERT_FALSE(threads[i].finished);
        // tell the thread to quit
        threads[i].running = false;
        AVS_UNIT_ASSERT_SUCCESS(avs_condvar_notify(threads[i].cv));
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(threads[i].mutex));
    }

    for (ssize_t i = AVS_ARRAY_SIZE(threads) - 1; i >= 0; --i) {
        // wait for the thread to quit
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(threads[i].mutex));
        while (!threads[i].finished) {
            AVS_UNIT_ASSERT_SUCCESS(
                    avs_condvar_wait(threads[i].cv, threads[i].mutex,
                                     AVS_TIME_MONOTONIC_INVALID));
        }
        AVS_UNIT_ASSERT_FALSE(threads[i].running);
        AVS_UNIT_ASSERT_TRUE(threads[i].finished);
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(threads[i].mutex));
    }

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        void *status = NULL;
        AVS_UNIT_ASSERT_SUCCESS(pthread_join(threads[i].thread, &status));
        AVS_UNIT_ASSERT_FALSE(threads[i].running);
        AVS_UNIT_ASSERT_TRUE(threads[i].finished);
        avs_mutex_cleanup(&threads[i].mutex);
        avs_condvar_cleanup(&threads[i].cv);
    }
}

#warning "TODO: Port rest of the tests, and do something about the fact that " \
         "even with 4 threads, the spinlock variant takes over half a minute " \
         "when ran under Valgrind"
