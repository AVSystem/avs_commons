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

#define _GNU_SOURCE // for RTLD_NEXT
#include <avs_commons_posix_init.h>

#include <time.h>

#include <dlfcn.h>

#include <avsystem/commons/avs_sched.h>
#include <avsystem/commons/avs_time.h>
#include <avsystem/commons/avs_unit_test.h>

#define MODULE_NAME sched_test
#include <avs_x_log_config.h>

static avs_time_monotonic_t MOCK_CLOCK = { { 0, -1 } };

static void mock_clock_start(const avs_time_monotonic_t t) {
    MOCK_CLOCK = AVS_TIME_MONOTONIC_INVALID;
    AVS_UNIT_ASSERT_TRUE(avs_time_monotonic_valid(t));
    MOCK_CLOCK = t;
}

static void mock_clock_advance(const avs_time_duration_t t) {
    AVS_UNIT_ASSERT_TRUE(avs_time_monotonic_valid(MOCK_CLOCK));
    AVS_UNIT_ASSERT_TRUE(avs_time_duration_valid(t));
    MOCK_CLOCK = avs_time_monotonic_add(MOCK_CLOCK, t);
}

static void mock_clock_finish(void) {
    AVS_UNIT_ASSERT_TRUE(avs_time_monotonic_valid(MOCK_CLOCK));
}

static int (*orig_clock_gettime)(clockid_t, struct timespec *);

int clock_gettime(clockid_t clock, struct timespec *t) {
    if (avs_time_monotonic_valid(MOCK_CLOCK)) {
        // all clocks are equivalent for our purposes, so ignore clock
        t->tv_sec = (time_t) MOCK_CLOCK.since_monotonic_epoch.seconds;
        t->tv_nsec = MOCK_CLOCK.since_monotonic_epoch.nanoseconds;
        MOCK_CLOCK = avs_time_monotonic_add(
                MOCK_CLOCK, avs_time_duration_from_scalar(1, AVS_TIME_NS));
        return 0;
    } else {
        return orig_clock_gettime(clock, t);
    }
}

AVS_UNIT_GLOBAL_INIT(verbose) {
    if (!verbose) {
        avs_log_set_default_level(AVS_LOG_QUIET);
    }
    typedef int (*clock_gettime_t)(clockid_t, struct timespec *);
    orig_clock_gettime =
            (clock_gettime_t) (intptr_t) dlsym(RTLD_NEXT, "clock_gettime");
}

static void increment_task(avs_sched_t *sched, const void *counter_ptr_ptr) {
    (void) sched;
    ++**(int *const *) counter_ptr_ptr;
}

typedef struct {
    avs_sched_t *sched;
} sched_test_env_t;

static sched_test_env_t setup_test(void) {
    mock_clock_start(avs_time_monotonic_from_scalar(0, AVS_TIME_S));
    return (sched_test_env_t) { avs_sched_new("test", NULL) };
}

static void teardown_test(sched_test_env_t *env) {
    mock_clock_finish();
    avs_sched_cleanup(&env->sched);
}

AVS_UNIT_TEST(sched, sched_now) {
    sched_test_env_t env = setup_test();

    int counter = 0;
    avs_sched_handle_t task = NULL;
    AVS_UNIT_ASSERT_SUCCESS(AVS_SCHED_NOW(env.sched, &task, increment_task,
                                          &(int *) { &counter },
                                          sizeof(int *)));
    AVS_UNIT_ASSERT_NOT_NULL(task);
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_EQUAL(1, counter);
    AVS_UNIT_ASSERT_NULL(task);

    teardown_test(&env);
}

AVS_UNIT_TEST(sched, sched_delayed) {
    sched_test_env_t env = setup_test();

    const avs_time_duration_t delay =
            avs_time_duration_from_scalar(1, AVS_TIME_S);
    int counter = 0;
    avs_sched_handle_t task = NULL;
    AVS_UNIT_ASSERT_SUCCESS(
            AVS_SCHED_DELAYED(env.sched, &task, delay, increment_task,
                              &(int *) { &counter }, sizeof(int *)));
    AVS_UNIT_ASSERT_NOT_NULL(task);
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_EQUAL(0, counter);
    AVS_UNIT_ASSERT_NOT_NULL(task);

    mock_clock_advance(delay);
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_EQUAL(1, counter);
    AVS_UNIT_ASSERT_NULL(task);

    teardown_test(&env);
}

AVS_UNIT_TEST(sched, sched_del) {
    sched_test_env_t env = setup_test();

    const avs_time_duration_t delay =
            avs_time_duration_from_scalar(1, AVS_TIME_S);
    int counter = 0;
    avs_sched_handle_t task = NULL;
    AVS_UNIT_ASSERT_SUCCESS(
            AVS_SCHED_DELAYED(env.sched, &task, delay, increment_task,
                              &(int *) { &counter }, sizeof(int *)));
    AVS_UNIT_ASSERT_NOT_NULL(task);
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_EQUAL(0, counter);

    avs_sched_del(&task);
    AVS_UNIT_ASSERT_NULL(task);

    mock_clock_advance(delay);
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_EQUAL(0, counter);

    teardown_test(&env);
}

typedef struct {
    avs_sched_handle_t task;
    int n;
} global_t;

static void assert_task_null_oneshot_job(avs_sched_t *sched,
                                         const void *context) {
    (void) sched;
    global_t *global = *(global_t *const *) context;
    AVS_UNIT_ASSERT_NULL(global->task);
}

AVS_UNIT_TEST(sched, oneshot_job_handle_nullification) {
    sched_test_env_t env = setup_test();

    global_t global = { NULL, 0 };
    AVS_UNIT_ASSERT_SUCCESS(
            AVS_SCHED_NOW(env.sched, &global.task, assert_task_null_oneshot_job,
                          &(global_t *) { &global }, sizeof(global_t *)));
    AVS_UNIT_ASSERT_NOT_NULL(global.task);
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_NULL(global.task);
    teardown_test(&env);
}

static int GLOBAL_VALUE = 0;
static int SETTER_CALLS = 0;

static void global_value_setter(avs_sched_t *sched, const void *value_) {
    (void) sched;
    GLOBAL_VALUE = *(const int *) value_;
    SETTER_CALLS++;
}

AVS_UNIT_TEST(sched, reschedule_policy) {
    sched_test_env_t env = setup_test();
    GLOBAL_VALUE = 0;
    SETTER_CALLS = 0;

    avs_sched_handle_t task = NULL;
    AVS_UNIT_ASSERT_SUCCESS(AVS_SCHED_NOW(env.sched, &task, global_value_setter,
                                          &(int) { 42 }, sizeof(int)));
    AVS_UNIT_ASSERT_SUCCESS(AVS_SCHED_NOW(env.sched, &task, global_value_setter,
                                          &(int) { 514 }, sizeof(int)));
    AVS_UNIT_ASSERT_NOT_NULL(task);
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_NULL(task);
    AVS_UNIT_ASSERT_EQUAL(GLOBAL_VALUE, 514);
    AVS_UNIT_ASSERT_EQUAL(SETTER_CALLS, 1);
    teardown_test(&env);
}

AVS_UNIT_TEST(sched, reschedule_job) {
    sched_test_env_t env = setup_test();
    GLOBAL_VALUE = 0;
    SETTER_CALLS = 0;

    avs_sched_handle_t task = NULL;
    AVS_UNIT_ASSERT_SUCCESS(AVS_SCHED_NOW(env.sched, &task, global_value_setter,
                                          &(int) { 7 }, sizeof(int)));
    AVS_UNIT_ASSERT_NOT_NULL(task);

    AVS_RESCHED_DELAYED(&task, avs_time_duration_from_scalar(1, AVS_TIME_S));
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_NOT_NULL(task);

    mock_clock_advance(avs_time_duration_from_scalar(1, AVS_TIME_S));
    avs_sched_run(env.sched);

    AVS_UNIT_ASSERT_NULL(task);
    AVS_UNIT_ASSERT_EQUAL(GLOBAL_VALUE, 7);
    AVS_UNIT_ASSERT_EQUAL(SETTER_CALLS, 1);

    teardown_test(&env);
}

AVS_UNIT_TEST(sched, reschedule_job_reordering) {
    sched_test_env_t env = setup_test();
    GLOBAL_VALUE = 0;
    SETTER_CALLS = 0;

    avs_sched_handle_t task1 = NULL;
    avs_sched_handle_t task2 = NULL;
    AVS_UNIT_ASSERT_SUCCESS(AVS_SCHED_NOW(
            env.sched, &task1, global_value_setter, &(int) { 7 }, sizeof(int)));
    AVS_UNIT_ASSERT_NOT_NULL(task1);

    AVS_UNIT_ASSERT_SUCCESS(AVS_SCHED_DELAYED(
            env.sched, &task2, avs_time_duration_from_scalar(1, AVS_TIME_S),
            global_value_setter, &(int) { 12 }, sizeof(int)));
    AVS_UNIT_ASSERT_NOT_NULL(task2);

    AVS_RESCHED_DELAYED(&task1, avs_time_duration_from_scalar(2, AVS_TIME_S));

    mock_clock_advance(avs_time_duration_from_scalar(1, AVS_TIME_S));
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_NULL(task2);
    AVS_UNIT_ASSERT_NOT_NULL(task1);
    AVS_UNIT_ASSERT_EQUAL(GLOBAL_VALUE, 12);

    mock_clock_advance(avs_time_duration_from_scalar(1, AVS_TIME_S));
    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_NULL(task1);
    AVS_UNIT_ASSERT_EQUAL(GLOBAL_VALUE, 7);

    AVS_UNIT_ASSERT_EQUAL(SETTER_CALLS, 2);

    teardown_test(&env);
}

static void rescheduler(avs_sched_t *sched, const void *ptr) {
    (void) sched;
    AVS_UNIT_ASSERT_NOT_NULL(ptr);

    // It's impossible to get handle to the job here, so user will not be able
    // to reschedule job in callback.
    AVS_UNIT_ASSERT_NULL(*((const avs_sched_handle_t *) ptr));
}

AVS_UNIT_TEST(sched, rescheduling_in_callback) {
    sched_test_env_t env = setup_test();

    avs_sched_handle_t task = NULL;
    AVS_UNIT_ASSERT_SUCCESS(
            AVS_SCHED_NOW(env.sched, &task, rescheduler, &task, sizeof(&task)));
    AVS_UNIT_ASSERT_NOT_NULL(task);

    avs_sched_run(env.sched);
    AVS_UNIT_ASSERT_NULL(task);

    teardown_test(&env);
}

#warning "TODO: More tests"
