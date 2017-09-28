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

#include <avs_commons_config.h>
#include <avs_commons_posix_config.h>

#include <time.h>
#include <assert.h>

#include <avsystem/commons/time.h>

VISIBILITY_SOURCE_BEGIN

#define NS_IN_S INT32_C(1000000000)

#define AVS_TIME_INVALID_DECL { \
    .seconds = 0, \
    .nanoseconds = -1 \
}

const avs_time_realtime_t AVS_TIME_REALTIME_INVALID = AVS_TIME_INVALID_DECL;
const avs_time_monotonic_t AVS_TIME_MONOTONIC_INVALID = AVS_TIME_INVALID_DECL;
const avs_time_duration_t AVS_TIME_DURATION_INVALID = AVS_TIME_INVALID_DECL;

#define DEFINE_TIME_LESS(Type, Action) \
bool Type##_##Action (const Type##_t *a, const Type##_t *b) { \
    if (!Type##_valid(a) || !Type##_valid(b)) { \
        return false; \
    } else { \
        return (a->seconds < b->seconds) \
                || (a->seconds == b->seconds \
                        && a->nanoseconds < b->nanoseconds); \
    } \
}

DEFINE_TIME_LESS(avs_time_realtime, before)
DEFINE_TIME_LESS(avs_time_monotonic, before)
DEFINE_TIME_LESS(avs_time_duration, less)

#define DEFINE_TIME_VALID(Type) \
bool Type##_valid(const Type##_t *t) { \
    return (t->nanoseconds >= 0 && t->nanoseconds < NS_IN_S); \
}

DEFINE_TIME_VALID(avs_time_realtime)
DEFINE_TIME_VALID(avs_time_monotonic)
DEFINE_TIME_VALID(avs_time_duration)

static inline void normalize(int64_t *inout_seconds,
                             int32_t *inout_nanoseconds) {
    if (*inout_nanoseconds < 0) {
        *inout_nanoseconds += NS_IN_S;
        --*inout_seconds;
    } else if (*inout_nanoseconds >= NS_IN_S) {
        *inout_nanoseconds -= NS_IN_S;
        ++*inout_seconds;
    }
}

#define DEFINE_TIME_ADD(Type) \
Type##_t Type##_add(const Type##_t *a, const avs_time_duration_t *b) { \
    if (!Type##_valid(a) || !avs_time_duration_valid(b)) { \
        return (Type##_t) AVS_TIME_INVALID_DECL; \
    } else { \
        Type##_t result = { \
            .seconds = a->seconds + b->seconds, \
            .nanoseconds = a->nanoseconds + b->nanoseconds \
        }; \
        normalize(&result.seconds, &result.nanoseconds); \
        \
        assert(Type##_valid(&result)); \
        return result; \
    } \
}

DEFINE_TIME_ADD(avs_time_realtime)
DEFINE_TIME_ADD(avs_time_monotonic)
DEFINE_TIME_ADD(avs_time_duration)

#define DEFINE_TIME_DIFF(Type) \
avs_time_duration_t Type##_diff(const Type##_t *minuend, \
                                const Type##_t *subtrahend) { \
    if (!Type##_valid(minuend) || !Type##_valid(subtrahend)) { \
        return AVS_TIME_DURATION_INVALID; \
    } else { \
        avs_time_duration_t result = { \
            .seconds = minuend->seconds - subtrahend->seconds, \
            .nanoseconds = minuend->nanoseconds - subtrahend->nanoseconds \
        }; \
        normalize(&result.seconds, &result.nanoseconds); \
        \
        assert(avs_time_duration_valid(&result)); \
        return result; \
    } \
}

DEFINE_TIME_DIFF(avs_time_realtime)
DEFINE_TIME_DIFF(avs_time_monotonic)
DEFINE_TIME_DIFF(avs_time_duration)

typedef enum {
    UCO_MUL,
    UCO_DIV
} unit_conv_op_t;

typedef struct {
    unit_conv_op_t operation;
    int32_t factor;
} unit_conv_t;

typedef struct {
    unit_conv_t conv_s;
    unit_conv_t conv_ns;
} time_conv_t;

static const time_conv_t CONVERSIONS[] = {
    [AVS_TIME_DAY]  = { { UCO_DIV,      86400 }, { UCO_MUL,       0 } },
    [AVS_TIME_HOUR] = { { UCO_DIV,       3600 }, { UCO_MUL,       0 } },
    [AVS_TIME_MIN]  = { { UCO_DIV,         60 }, { UCO_MUL,       0 } },
    [AVS_TIME_S]    = { { UCO_MUL,          1 }, { UCO_MUL,       0 } },
    [AVS_TIME_MS]   = { { UCO_MUL,       1000 }, { UCO_DIV, 1000000 } },
    [AVS_TIME_US]   = { { UCO_MUL,    1000000 }, { UCO_DIV,    1000 } },
    [AVS_TIME_NS]   = { { UCO_MUL, 1000000000 }, { UCO_MUL,       1 } }
};

static int unit_conv(int64_t *output,
                     int64_t input,
                     unit_conv_op_t operation,
                     int32_t factor) {
    switch (operation) {
    case UCO_MUL:
        if (input > INT64_MAX / factor || input < INT64_MIN / factor) {
            return -1;
        }
        *output = input * factor;
        return 0;
    case UCO_DIV:
        *output = input / factor;
        return 0;
    default:
        assert(0 && "Invalid unit_conv operation");
        return -1;
    }
}

static int unit_conv_forward(int64_t *output,
                             int64_t input,
                             const unit_conv_t *conv) {
    return unit_conv(output, input, conv->operation, conv->factor);
}

static int unit_conv_backward(int64_t *output,
                              int64_t input,
                              const unit_conv_t *conv) {
    return unit_conv(output, input,
                     conv->operation == UCO_DIV ? UCO_MUL : UCO_DIV,
                     conv->factor);
}

static int safe_add(int64_t *out, int64_t a, int64_t b) {
    if (a > 0 && b > 0) {
        uint64_t result = ((uint64_t) a) + ((uint64_t) b);
        if (result > (uint64_t) INT64_MAX) {
            return -1;
        }
        *out = (int64_t) result;
        return 0;
    } else if (a < 0 && b < 0) {
        uint64_t result = ((uint64_t) -a) + ((uint64_t) -b);
        if (result > (uint64_t) INT64_MIN) {
            return -1;
        }
        *out = -(int64_t) result;
        return 0;
    } else {
        *out = a + b;
        return 0;
    }
}

static int time_conv_forward(int64_t *output,
                             int64_t seconds,
                             int32_t nanoseconds,
                             const time_conv_t *conv) {
    int64_t converted_s;
    int64_t converted_ns;
    if (unit_conv_forward(&converted_s, seconds, &conv->conv_s)
            || unit_conv_forward(&converted_ns, nanoseconds, &conv->conv_ns)) {
        return -1;
    }
    return safe_add(output, converted_s, converted_ns);
}

static int time_conv_backward(int64_t *output_s,
                              int32_t *output_ns,
                              int64_t input,
                              const time_conv_t *conv) {
    int64_t seconds_only;
    int64_t output_ns_tmp;
    if (unit_conv_backward(output_s, input, &conv->conv_s)
            || unit_conv_forward(&seconds_only, *output_s, &conv->conv_s)
            || unit_conv_backward(&output_ns_tmp, input - seconds_only,
                                  &conv->conv_ns)
            || output_ns_tmp <= -NS_IN_S || output_ns_tmp >= NS_IN_S) {
        return -1;
    }
    *output_ns = (int32_t) output_ns_tmp;
    normalize(output_s, output_ns);
    return 0;
}

#define DEFINE_TIME_TO_SCALAR(Type) \
int Type##_to_scalar(int64_t *out, avs_time_unit_t unit, \
                     const Type##_t *value) { \
    if (unit < 0 || unit > AVS_ARRAY_SIZE(CONVERSIONS) \
            || !Type##_valid(value)) { \
        return -1; \
    } \
    return time_conv_forward(out, value->seconds, value->nanoseconds, \
                             &CONVERSIONS[unit]); \
}

DEFINE_TIME_TO_SCALAR(avs_time_realtime)
DEFINE_TIME_TO_SCALAR(avs_time_monotonic)
DEFINE_TIME_TO_SCALAR(avs_time_duration)

#define DEFINE_TIME_FROM_SCALAR(Type) \
Type##_t Type##_from_scalar(int64_t value, avs_time_unit_t unit) { \
    assert(unit >= 0 && unit < AVS_ARRAY_SIZE(CONVERSIONS)); \
    Type##_t result; \
    int err = time_conv_backward(&result.seconds, &result.nanoseconds, value, \
                                 &CONVERSIONS[unit]); \
    assert(!err); \
    return result; \
}

DEFINE_TIME_FROM_SCALAR(avs_time_realtime)
DEFINE_TIME_FROM_SCALAR(avs_time_monotonic)
DEFINE_TIME_FROM_SCALAR(avs_time_duration)

avs_time_duration_t avs_time_duration_div(const avs_time_duration_t *dividend,
                                          int32_t divisor) {
    if (!avs_time_duration_valid(dividend) || divisor == 0) {
        return AVS_TIME_DURATION_INVALID;
    } else {
        int64_t s_rest = dividend->seconds % divisor;
        avs_time_duration_t result = {
            .seconds = dividend->seconds / divisor,
            .nanoseconds = (int32_t) (((double) dividend->nanoseconds
                                           + (double) s_rest * NS_IN_S)
                                          / divisor)
        };
        normalize(&result.seconds, &result.nanoseconds);

        assert(avs_time_duration_valid(&result));
        return result;
    }
}

#ifdef AVS_UNIT_TESTING
#include "test/time.c"
#endif // AVS_UNIT_TESTING
