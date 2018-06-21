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

#include <avs_commons_config.h>

#define MODULE_NAME init_once_pthread
#include <x_log_config.h>

#include <avsystem/commons/init_once.h>
#include <avsystem/commons/defs.h>

#include <pthread.h>
#include <stdlib.h>

VISIBILITY_SOURCE_BEGIN

static pthread_mutex_t g_mutex;
static volatile bool g_mutex_initialized = false;

/*
 * PTHREAD_RECURSIVE_MUTEX_INITIALIZER is non-portable; the only method of
 * creating a recursive mutex defined by POSIX is to use pthread_mutex_init()
 * with appropriate attributes
 */
static int ensure_mutex_initialized(void) {
    if (g_mutex_initialized) {
        return 0;
    }

    static pthread_mutex_t mutex_init_mutex = PTHREAD_MUTEX_INITIALIZER;
    if (pthread_mutex_lock(&mutex_init_mutex)) {
        return -1;
    }

    int result = 0;

    if (!g_mutex_initialized) {
        pthread_mutexattr_t attr;
        ((void) ((result = pthread_mutexattr_init(&attr))
                 || (result = pthread_mutexattr_settype(
                         &attr, PTHREAD_MUTEX_RECURSIVE))
                 || (result = pthread_mutex_init(&g_mutex, &attr))));

        if (result == 0) {
            g_mutex_initialized = true;
        }

    }

    pthread_mutex_unlock(&mutex_init_mutex);
    return result;
}

int avs_init_once(volatile avs_init_once_handle_t *handle,
                  avs_init_once_func_t *func,
                  void *func_arg) {
    if (ensure_mutex_initialized()
            || pthread_mutex_lock(&g_mutex)) {
        return -1;
    }

    int result = 0;
    if (*handle == NULL) {
        result = func(func_arg);
        if (result == 0) {
            *handle = (avs_init_once_handle_t) ~(intptr_t) *handle;
        }
    }

    pthread_mutex_unlock(&g_mutex);
    return result;
}
