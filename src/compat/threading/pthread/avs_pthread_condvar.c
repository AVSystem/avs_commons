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

#include <avsystem/commons/avs_commons_config.h>

#if defined(AVS_COMMONS_WITH_AVS_COMPAT_THREADING) \
        && defined(AVS_COMMONS_COMPAT_THREADING_WITH_PTHREAD)

#    include <avs_commons_posix_init.h>

#    include <avsystem/commons/avs_condvar.h>
#    include <avsystem/commons/avs_defs.h>
#    include <avsystem/commons/avs_memory.h>

#    include <errno.h>
#    include <pthread.h>

#    include "avs_pthread_structs.h"

#    define MODULE_NAME condvar_pthread
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#    if defined(CLOCK_MONOTONIC) \
            && defined(AVS_COMMONS_COMPAT_THREADING_PTHREAD_HAVE_PTHREAD_CONDATTR_SETCLOCK)
#        define USE_CLOCK_MONOTONIC
#    endif

int avs_condvar_create(avs_condvar_t **out_condvar) {
    AVS_ASSERT(!*out_condvar,
               "possible attempt to reinitialize a condition variable");

    *out_condvar = (avs_condvar_t *) avs_calloc(1, sizeof(avs_condvar_t));
    if (!*out_condvar) {
        return -1;
    }

    int result = 0;
    pthread_condattr_t *attr_ptr = NULL;
#    ifdef USE_CLOCK_MONOTONIC
    pthread_condattr_t attr;
    if (!(result = pthread_condattr_init(&attr))) {
        attr_ptr = &attr;
        result = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    }
#    endif // USE_CLOCK_MONOTONIC

    if (!result) {
        result = pthread_cond_init(&(*out_condvar)->pthread_cond, attr_ptr);
    }
    if (attr_ptr) {
        pthread_condattr_destroy(attr_ptr);
    }
    if (result) {
        avs_free(*out_condvar);
        *out_condvar = NULL;
    }
    return result;
}

int avs_condvar_notify_all(avs_condvar_t *condvar) {
    return pthread_cond_broadcast(&condvar->pthread_cond);
}

static inline int as_timespec(struct timespec *out_result,
                              avs_time_duration_t duration) {
    out_result->tv_sec = (time_t) duration.seconds;
    out_result->tv_nsec = duration.nanoseconds;
    return ((int64_t) out_result->tv_sec == duration.seconds
            && out_result->tv_nsec == (int32_t) duration.nanoseconds)
                   ? 0
                   : -1;
}

static int convert_deadline(struct timespec *out_result,
                            avs_time_monotonic_t deadline) {
#    ifdef USE_CLOCK_MONOTONIC
    return as_timespec(out_result, deadline.since_monotonic_epoch);
#    else  // USE_CLOCK_MONOTONIC
    return as_timespec(
            out_result,
            avs_time_duration_add(avs_time_real_now().since_real_epoch,
                                  avs_time_monotonic_diff(
                                          deadline, avs_time_monotonic_now())));
#    endif // USE_CLOCK_MONOTONIC
}

int avs_condvar_wait(avs_condvar_t *condvar,
                     avs_mutex_t *mutex,
                     avs_time_monotonic_t deadline) {
    int retval = -1;
    if (avs_time_monotonic_valid(deadline)) {
        struct timespec posix_deadline;
        (void) ((retval = convert_deadline(&posix_deadline, deadline))
                || (retval = pthread_cond_timedwait(&condvar->pthread_cond,
                                                    &mutex->pthread_mutex,
                                                    &posix_deadline)));
    } else {
        retval = pthread_cond_wait(&condvar->pthread_cond,
                                   &mutex->pthread_mutex);
    }
    if (retval) {
        if (retval == ETIMEDOUT) {
            retval = 1;
        } else {
            retval = -1;
        }
    }
    return retval;
}

void avs_condvar_cleanup(avs_condvar_t **condvar) {
    if (!*condvar) {
        return;
    }

    int result = pthread_cond_destroy(&(*condvar)->pthread_cond);
    (void) result;
    AVS_ASSERT(result == 0, "pthread_cond_destroy failed");

    avs_free(*condvar);
    *condvar = NULL;
}

#endif // defined(AVS_COMMONS_WITH_AVS_COMPAT_THREADING) &&
       // defined(AVS_COMMONS_COMPAT_THREADING_WITH_PTHREAD)
