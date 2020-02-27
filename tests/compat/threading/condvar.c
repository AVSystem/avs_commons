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

#include <avsystem/commons/avs_condvar.h>

#include <pthread.h>
#include <string.h>

#include <avsystem/commons/avs_unit_test.h>

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

        AVS_UNIT_ASSERT_SUCCESS(avs_condvar_notify_all(cv));
        AVS_UNIT_ASSERT_EQUAL(
                avs_condvar_wait(
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
    avs_condvar_notify_all(self->cv);
    while (self->running) {
        avs_condvar_wait(self->cv, self->mutex, AVS_TIME_MONOTONIC_INVALID);
    }
    self->finished = true;
    avs_condvar_notify_all(self->cv);
    avs_mutex_unlock(self->mutex);
    return NULL;
}

AVS_UNIT_TEST(condvar, multiple_threads_with_separate_condition_variables) {
    thread_with_mutex_and_condition_variable_t threads[16];
    memset(threads, 0, sizeof(threads));

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        AVS_UNIT_ASSERT_SUCCESS(avs_condvar_create(&threads[i].cv));
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_create(&threads[i].mutex));
        AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(threads[i].mutex));
        AVS_UNIT_ASSERT_FALSE(threads[i].running);
        AVS_UNIT_ASSERT_FALSE(threads[i].finished);
        AVS_UNIT_ASSERT_SUCCESS(
                pthread_create(&threads[i].thread,
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
        AVS_UNIT_ASSERT_SUCCESS(avs_condvar_notify_all(threads[i].cv));
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

AVS_UNIT_TEST(condvar,
              multiple_threads_with_shared_separate_condition_variables) {
    thread_with_mutex_and_condition_variable_t threads[16];
    memset(threads, 0, sizeof(threads));

    avs_condvar_t *cv = NULL;
    avs_mutex_t *mutex = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_condvar_create(&cv));
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_create(&mutex));

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        threads[i].mutex = mutex;
        threads[i].cv = cv;
    }

    // start all threads
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(mutex));
    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        AVS_UNIT_ASSERT_FALSE(threads[i].running);
        AVS_UNIT_ASSERT_FALSE(threads[i].finished);
        AVS_UNIT_ASSERT_SUCCESS(
                pthread_create(&threads[i].thread,
                               NULL,
                               thread_with_mutex_and_condition_variable_func,
                               &threads[i]));
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(mutex));

    // wait for all threads to start
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(mutex));
    for (ssize_t i = AVS_ARRAY_SIZE(threads) - 1; i >= 0; --i) {
        while (!threads[i].running) {
            AVS_UNIT_ASSERT_SUCCESS(
                    avs_condvar_wait(cv, mutex, AVS_TIME_MONOTONIC_INVALID));
        }
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(mutex));

    // make sure that all threads are running
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(mutex));
    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        AVS_UNIT_ASSERT_TRUE(threads[i].running);
        AVS_UNIT_ASSERT_FALSE(threads[i].finished);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(mutex));

    // tell all threads to quit
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(mutex));
    for (ssize_t i = AVS_ARRAY_SIZE(threads) - 1; i >= 0; --i) {
        AVS_UNIT_ASSERT_TRUE(threads[i].running);
        AVS_UNIT_ASSERT_FALSE(threads[i].finished);
        threads[i].running = false;
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_condvar_notify_all(cv));
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(mutex));

    // wait for all threads to quit
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(mutex));
    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        while (!threads[i].finished) {
            AVS_UNIT_ASSERT_SUCCESS(
                    avs_condvar_wait(cv, mutex, AVS_TIME_MONOTONIC_INVALID));
        }
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(mutex));

    // make sure all threads are finished
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_lock(mutex));
    for (ssize_t i = AVS_ARRAY_SIZE(threads) - 1; i >= 0; --i) {
        AVS_UNIT_ASSERT_FALSE(threads[i].running);
        AVS_UNIT_ASSERT_TRUE(threads[i].finished);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_unlock(mutex));

    // join all threads
    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        void *status = NULL;
        AVS_UNIT_ASSERT_SUCCESS(pthread_join(threads[i].thread, &status));
    }

    avs_mutex_cleanup(&mutex);
    avs_condvar_cleanup(&cv);
}

typedef struct {
    pthread_t thread;
    int rem;
    int *counter;
    int limit;
    int thread_count;
    avs_condvar_t *cv;
    avs_mutex_t *mutex;
} loop_increment_thread_t;

static void *loop_increment_thread_func(void *self_) {
    loop_increment_thread_t *self = (loop_increment_thread_t *) self_;
    // we are using plain assert()s in this function instead of AVS_UNIT calls
    // because AVS_UNIT_ASSERT_* calls longjmp() to somewhere that does not
    // exist in the context of this thread
    assert(self->rem < self->thread_count);
    assert(self->limit % self->thread_count == 0);

    int last_count = -1;
    avs_mutex_lock(self->mutex);
    while (true) {
        int count = *self->counter;
        while (count % self->thread_count != self->rem && count < self->limit) {
            avs_condvar_wait(self->cv, self->mutex, AVS_TIME_MONOTONIC_INVALID);
            count = *self->counter;
        }
        if (count >= self->limit) {
            break;
        }
        assert(*self->counter == count);
        if (last_count != -1) {
            assert(last_count + (self->thread_count - 1) == count);
        }
        ++count;
        *self->counter = count;
        last_count = count;
        avs_condvar_notify_all(self->cv);
    }
    avs_mutex_unlock(self->mutex);
    return NULL;
}

AVS_UNIT_TEST(condvar, loop_increment) {
    avs_mutex_t *mutex = NULL;
    avs_condvar_t *cv = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_mutex_create(&mutex));
    AVS_UNIT_ASSERT_SUCCESS(avs_condvar_create(&cv));

    for (int thread_count = 1; thread_count < 8; ++thread_count) {
        const int limit = thread_count * 10;
        int counter = 0;

        // setup the threads
        loop_increment_thread_t threads[thread_count];
        for (int i = 0; i < thread_count; ++i) {
            threads[i].rem = i;
            threads[i].counter = &counter;
            threads[i].limit = limit;
            threads[i].thread_count = thread_count;
            threads[i].cv = cv;
            threads[i].mutex = mutex;
        }

        // start all threads
        for (int i = thread_count - 1; i >= 0; --i) {
            AVS_UNIT_ASSERT_SUCCESS(pthread_create(&threads[i].thread,
                                                   NULL,
                                                   loop_increment_thread_func,
                                                   &threads[i]));
        }

        // join and cleanup all threads
        for (int i = 0; i < thread_count; ++i) {
            void *status = NULL;
            AVS_UNIT_ASSERT_SUCCESS(pthread_join(threads[i].thread, &status));
        }

        AVS_UNIT_ASSERT_EQUAL(counter, limit);
    }

    avs_condvar_cleanup(&cv);
    avs_mutex_cleanup(&mutex);
}
