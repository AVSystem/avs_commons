/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

/* for struct timespec and ssize_t */
#define _GNU_SOURCE

#include <config.h>

#include <time.h>
#include <assert.h>

#include <avsystem/commons/time.h>

#define NS_IN_S (1L * 1000L * 1000L * 1000L)

const struct timespec AVS_TIME_INVALID = {
    .tv_sec = 0,
    .tv_nsec = -1
};

bool avs_time_before(const struct timespec *a, const struct timespec *b) {
    if (!avs_time_is_valid(a) || !avs_time_is_valid(b)) {
        return false;
    } else {
        return (a->tv_sec < b->tv_sec)
                || (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
    }
}

bool avs_time_is_valid(const struct timespec *t) {
    return (t->tv_nsec >= 0 && t->tv_nsec < NS_IN_S);
}

static inline void normalize(struct timespec *inout) {
    if (inout->tv_nsec < 0) {
        inout->tv_nsec += NS_IN_S;
        inout->tv_sec--;
    } else if (inout->tv_nsec >= NS_IN_S) {
        inout->tv_nsec -= NS_IN_S;
        inout->tv_sec++;
    }
}

void avs_time_add(struct timespec *result, const struct timespec *duration) {
    if (!avs_time_is_valid(result)) {
        return;
    } else if (!avs_time_is_valid(duration)) {
        *result = AVS_TIME_INVALID;
    } else {
        result->tv_sec += duration->tv_sec;
        result->tv_nsec += duration->tv_nsec;
        normalize(result);

        assert(avs_time_is_valid(result));
    }
}

void avs_time_diff(struct timespec *result,
                   const struct timespec *minuend,
                   const struct timespec *subtrahend) {
    if (!avs_time_is_valid(minuend) || !avs_time_is_valid(subtrahend)) {
        *result = AVS_TIME_INVALID;
    } else {
        result->tv_sec = minuend->tv_sec - subtrahend->tv_sec;
        result->tv_nsec = minuend->tv_nsec - subtrahend->tv_nsec;
        normalize(result);

        assert(avs_time_is_valid(result));
    }
}

int avs_time_to_ms(ssize_t *out_ms, const struct timespec *value) {
    if (!avs_time_is_valid(value)) {
        return -1;
    } else {
        *out_ms = (ssize_t)
                (value->tv_sec * 1000L + value->tv_nsec / (1000L * 1000L));
        return 0;
    }
}

int avs_time_diff_ms(ssize_t *out_ms,
                     const struct timespec *minuend,
                     const struct timespec *subtrahend) {
    struct timespec diff;
    avs_time_diff(&diff, minuend, subtrahend);
    return avs_time_to_ms(out_ms, &diff);
}

void avs_time_from_ms(struct timespec *result, int32_t ms) {
    result->tv_sec = (time_t) (ms / 1000);
    result->tv_nsec = (ms % 1000) * 1000000L;
    normalize(result);

    assert(avs_time_is_valid(result));
}

void avs_time_from_s(struct timespec *result, time_t s) {
    result->tv_sec = s;
    result->tv_nsec = 0;
}

void avs_time_add_ms(struct timespec *result, int32_t ms) {
    struct timespec duration;
    avs_time_from_ms(&duration, ms);
    avs_time_add(result, &duration);

    assert(avs_time_is_valid(result));
}

void avs_time_div(struct timespec *result,
                  const struct timespec *dividend,
                  uint32_t divisor) {
    if (!avs_time_is_valid(dividend) || divisor == 0) {
        *result = AVS_TIME_INVALID;
    } else {
        time_t s_rest = (time_t)(dividend->tv_sec % (int64_t) divisor);
        result->tv_sec = (time_t)(dividend->tv_sec / (int64_t) divisor);
        result->tv_nsec = (long)(((double)dividend->tv_nsec
                                    + (double)s_rest * NS_IN_S)
                                 / divisor);

        normalize(result);

        assert(avs_time_is_valid(result));
    }
}

#ifdef AVS_UNIT_TESTING
#include "test/time.c"
#endif // AVS_UNIT_TESTING
