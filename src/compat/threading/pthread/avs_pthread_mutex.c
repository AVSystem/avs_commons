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

#if defined(AVS_COMMONS_WITH_AVS_COMPAT_THREADING) \
        && defined(AVS_COMMONS_COMPAT_THREADING_WITH_PTHREAD)

#    include <avsystem/commons/avs_defs.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_mutex.h>

#    include <pthread.h>

#    include "avs_pthread_structs.h"

#    define MODULE_NAME mutex_pthread
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

int avs_mutex_create(avs_mutex_t **out_mutex) {
    AVS_ASSERT(!*out_mutex, "possible attempt to reinitialize a mutex");

    *out_mutex = (avs_mutex_t *) avs_calloc(1, sizeof(avs_mutex_t));
    if (!*out_mutex) {
        return -1;
    }

    if (pthread_mutex_init(&(*out_mutex)->pthread_mutex, NULL)) {
        avs_free(*out_mutex);
        *out_mutex = NULL;
        return -1;
    }

    return 0;
}

int avs_mutex_lock(avs_mutex_t *mutex) {
    return pthread_mutex_lock(&mutex->pthread_mutex);
}

int avs_mutex_try_lock(avs_mutex_t *mutex) {
    return pthread_mutex_trylock(&mutex->pthread_mutex);
}

int avs_mutex_unlock(avs_mutex_t *mutex) {
    return pthread_mutex_unlock(&mutex->pthread_mutex);
}

void avs_mutex_cleanup(avs_mutex_t **mutex) {
    if (!*mutex) {
        return;
    }

    int result = pthread_mutex_destroy(&(*mutex)->pthread_mutex);
    (void) result;
    AVS_ASSERT(result == 0, "pthread_mutex_destroy failed");

    avs_free(*mutex);
    *mutex = NULL;
}

#endif // defined(AVS_COMMONS_WITH_AVS_COMPAT_THREADING) &&
       // defined(AVS_COMMONS_COMPAT_THREADING_WITH_PTHREAD)
