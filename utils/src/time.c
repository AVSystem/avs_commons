/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */
/* for struct timespec and ssize_t */
#define _GNU_SOURCE

#include <config.h>

#include <time.h>
#include <assert.h>

#include <avsystem/commons/time.h>

#define NS_IN_S (1L * 1000L * 1000L * 1000L)

bool avs_time_before(const struct timespec *a, const struct timespec *b) {
    return (a->tv_sec < b->tv_sec)
            || (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
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
    if (!avs_time_is_valid(result) || !avs_time_is_valid(duration)) {
        result->tv_sec = 0;
        result->tv_nsec = -1;
    } else {
        result->tv_sec += duration->tv_sec;
        result->tv_nsec += duration->tv_nsec;

        normalize(result);
    }

    assert(avs_time_is_valid(result));
}

void avs_time_diff(struct timespec *result,
                   const struct timespec *minuend,
                   const struct timespec *subtrahend) {
    assert(avs_time_is_valid(result));
    assert(avs_time_is_valid(result));
    result->tv_sec = minuend->tv_sec - subtrahend->tv_sec;
    result->tv_nsec = minuend->tv_nsec - subtrahend->tv_nsec;
    normalize(result);

    assert(avs_time_is_valid(result));
}

ssize_t avs_time_diff_ms(const struct timespec *minuend,
                         const struct timespec *subtrahend) {
    struct timespec diff;
    avs_time_diff(&diff, minuend, subtrahend);
    return (ssize_t)(diff.tv_sec * 1000L + diff.tv_nsec / (1000L * 1000L));
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
    assert(avs_time_is_valid(dividend));
    time_t s_rest = (time_t)(dividend->tv_sec % (int64_t) divisor);
    result->tv_sec = (time_t)(dividend->tv_sec / (int64_t) divisor);
    result->tv_nsec = (long)(((double)dividend->tv_nsec
                                + (double)s_rest * NS_IN_S)
                             / divisor);

    normalize(result);

    assert(avs_time_is_valid(result));
}
