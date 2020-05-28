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
        && defined(AVS_COMMONS_COMPAT_THREADING_WITH_ATOMIC_SPINLOCK)

#    include <avsystem/commons/avs_defs.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_mutex.h>

#    include <stdatomic.h>
#    include <stdbool.h>
#    include <stdlib.h>

#    include "avs_atomic_spinlock_structs.h"

#    define MODULE_NAME mutex_atomic_spinlock
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

void _avs_mutex_init(avs_mutex_t *mutex) {
    // While it would make sense that a zero-allocated flag is in "clear"
    // state, the documentation of atomic_flag is not explicit about it.
    // We clear it manually just to be sure.
    avs_mutex_unlock(mutex);
}

int avs_mutex_create(avs_mutex_t **out_mutex) {
    AVS_ASSERT(!*out_mutex, "possible attempt to reinitialize a mutex");

    *out_mutex = (struct avs_mutex *) avs_calloc(1, sizeof(struct avs_mutex));
    if (*out_mutex) {
        _avs_mutex_init(*out_mutex);
        return 0;
    }
    return -1;
}

int avs_mutex_lock(avs_mutex_t *mutex) {
    while (atomic_flag_test_and_set(&mutex->locked) != 0) {
    }
    return 0;
}

int avs_mutex_try_lock(avs_mutex_t *mutex) {
    return atomic_flag_test_and_set(&mutex->locked) == 0 ? 0 : 1;
}

int avs_mutex_unlock(avs_mutex_t *mutex) {
    atomic_flag_clear(&mutex->locked);
    return 0;
}

void _avs_mutex_destroy(avs_mutex_t *mutex) {
    (void) mutex;
    AVS_ASSERT(atomic_flag_test_and_set(&mutex->locked) == 0,
               "attempted to cleanup a locked mutex");
}

void avs_mutex_cleanup(avs_mutex_t **mutex) {
    if (!*mutex) {
        return;
    }

    _avs_mutex_destroy(*mutex);
    avs_free(*mutex);
    *mutex = NULL;
}

#endif // defined(AVS_COMMONS_WITH_AVS_COMPAT_THREADING) &&
       // defined(AVS_COMMONS_COMPAT_THREADING_WITH_ATOMIC_SPINLOCK)
