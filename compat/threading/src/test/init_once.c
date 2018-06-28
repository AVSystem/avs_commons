/*
 * Copyright 2018 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/init_once.h>

#include <pthread.h>

#include <avsystem/commons/unit/test.h>

/*
 * POSIX barriers are an optional feature, and are not implemented e.g. on OSX.
 * Fortunately, we may simulate them with other primitives.
 *
 * Source: http://blog.albertarmea.com/post/47089939939/using-pthreadbarrier-on-mac-os-x
 */
#ifdef _POSIX_BARRIERS

#include <errno.h>

typedef int pthread_barrierattr_t;
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int count;
    int tripCount;
} pthread_barrier_t;


static int pthread_barrier_init(pthread_barrier_t *barrier,
                                const pthread_barrierattr_t *attr,
                                unsigned int count) {
    (void) attr;

    if (count == 0) {
        errno = EINVAL;
        return -1;
    }
    if (pthread_mutex_init(&barrier->mutex, 0) < 0) {
        return -1;
    }
    if (pthread_cond_init(&barrier->cond, 0) < 0) {
        pthread_mutex_destroy(&barrier->mutex);
        return -1;
    }
    barrier->tripCount = count;
    barrier->count = 0;

    return 0;
}

static int pthread_barrier_destroy(pthread_barrier_t *barrier) {
    pthread_cond_destroy(&barrier->cond);
    pthread_mutex_destroy(&barrier->mutex);
    return 0;
}

static int pthread_barrier_wait(pthread_barrier_t *barrier) {
    pthread_mutex_lock(&barrier->mutex);
    ++barrier->count;
    if (barrier->count >= barrier->tripCount) {
        barrier->count = 0;
        pthread_cond_broadcast(&barrier->cond);
        pthread_mutex_unlock(&barrier->mutex);
        return 1;
    } else {
        pthread_cond_wait(&barrier->cond, &(barrier->mutex));
        pthread_mutex_unlock(&barrier->mutex);
        return 0;
    }
}

#endif // _POSIX_BARRIERS

typedef struct {
    pthread_barrier_t barrier;
    const size_t num_calls_per_thread;
    int counter;
    const int succeed_on_call;

    avs_init_once_handle_t init_once_handle;
} thread_func_args_t;

static int init(void *args_) {
    thread_func_args_t *args = (thread_func_args_t *) args_;
    ++args->counter;
    return args->counter == args->succeed_on_call ? 0 : -1;
}

static void *thread_func(void *args_) {
    thread_func_args_t *args = (thread_func_args_t *) args_;

    // wait until all threads are started
    pthread_barrier_wait(&args->barrier);

    for (size_t i = 0; i < args->num_calls_per_thread; ++i) {
        avs_init_once(&args->init_once_handle, init, args);
    }

    return NULL;
}

AVS_UNIT_TEST(init_once, basic) {
    pthread_t threads[4];

    thread_func_args_t args = {
        .num_calls_per_thread = 1000,
        .counter = 0,
        .succeed_on_call = 200,
        .init_once_handle = NULL
    };

    AVS_UNIT_ASSERT_SUCCESS(pthread_barrier_init(&args.barrier, NULL,
                                                 AVS_ARRAY_SIZE(threads)));

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        AVS_UNIT_ASSERT_SUCCESS(pthread_create(&threads[i], NULL,
                                               thread_func, &args));
    }

    for (size_t i = 0; i < AVS_ARRAY_SIZE(threads); ++i) {
        void *status = NULL;
        AVS_UNIT_ASSERT_SUCCESS(pthread_join(threads[i], &status));
    }

    AVS_UNIT_ASSERT_EQUAL(args.counter, args.succeed_on_call);
}

static int init_recursive(void *handles_) {
    volatile avs_init_once_handle_t **handles =
            (volatile avs_init_once_handle_t **) handles_;
    if (*handles) {
        return avs_init_once(handles[0], init_recursive,
                             (void *) &handles[1]);
    }
    return 0;
}

AVS_UNIT_TEST(init_once, recursive_call_different_handle) {
    volatile avs_init_once_handle_t *handles[] = {
        &(volatile avs_init_once_handle_t){ NULL },
        &(volatile avs_init_once_handle_t){ NULL },
        &(volatile avs_init_once_handle_t){ NULL },
        NULL
    };
    AVS_UNIT_ASSERT_SUCCESS(avs_init_once(handles[0], init_recursive,
                                          (void *) &handles[1]));
}
