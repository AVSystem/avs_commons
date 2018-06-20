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

#define MODULE_NAME mutex_pthread
#include <x_log_config.h>

#include <avsystem/commons/mutex.h>
#include <avsystem/commons/defs.h>
#include <avsystem/commons/memory.h>

#include <pthread.h>

VISIBILITY_SOURCE_BEGIN

struct avs_mutex {
    pthread_mutex_t pthread_mutex;
};

int avs_mutex_create(avs_mutex_t **out_mutex) {
    AVS_ASSERT(!*out_mutex, "possible attempt to reinitialize a mutex");

    *out_mutex = (struct avs_mutex *) avs_calloc(1, sizeof(struct avs_mutex));
    if (*out_mutex) {
        return pthread_mutex_init(&(*out_mutex)->pthread_mutex, NULL);
    }
    return -1;
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
