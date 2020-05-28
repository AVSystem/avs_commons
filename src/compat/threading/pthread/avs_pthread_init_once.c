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

/* for PTHREAD_MUTEX_RECURSIVE & pthread_mutexattr_settype */
#define _POSIX_C_SOURCE 200809L

#define AVS_COMPAT_THREADING_PTHREAD_INIT_ONCE
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_COMPAT_THREADING) \
        && defined(AVS_COMMONS_COMPAT_THREADING_WITH_PTHREAD)

#    include <avsystem/commons/avs_defs.h>
#    include <avsystem/commons/avs_init_once.h>

#    include <pthread.h>
#    include <stdlib.h>

#    define MODULE_NAME init_once_pthread
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static pthread_mutex_t g_mutex;

/*
 * PTHREAD_RECURSIVE_MUTEX_INITIALIZER is non-portable; the only method of
 * creating a recursive mutex defined by POSIX is to use pthread_mutex_init()
 * with appropriate attributes
 */
static void init_global_mutex(void) {
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr)
            || pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)
            || pthread_mutex_init(&g_mutex, &attr)) {
        AVS_UNREACHABLE("could not initialize avs_init_once mutex");
        abort();
    }
}

int avs_init_once(volatile avs_init_once_handle_t *handle,
                  avs_init_once_func_t *func,
                  void *func_arg) {
    static pthread_once_t init_global_mutex_handle = PTHREAD_ONCE_INIT;
    pthread_once(&init_global_mutex_handle, init_global_mutex);

    if (pthread_mutex_lock(&g_mutex)) {
        return -1;
    }

    int result = 0;
    if (*handle == NULL) {
        result = func(func_arg);
        if (result == 0) {
            *handle = (avs_init_once_handle_t) ~(intptr_t) NULL;
        }
    }

    pthread_mutex_unlock(&g_mutex);
    return result;
}

#endif // defined(AVS_COMMONS_WITH_AVS_COMPAT_THREADING) &&
       // defined(AVS_COMMONS_COMPAT_THREADING_WITH_PTHREAD)
