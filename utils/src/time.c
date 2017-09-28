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
bool Type##_##Action (Type##_t a, Type##_t b) { \
    if (!Type##_valid(a) || !Type##_valid(b)) { \
        return false; \
    } else { \
        return (a.seconds < b.seconds) \
                || (a.seconds == b.seconds && a.nanoseconds < b.nanoseconds); \
    } \
}

DEFINE_TIME_LESS(avs_time_realtime, before)
DEFINE_TIME_LESS(avs_time_monotonic, before)
DEFINE_TIME_LESS(avs_time_duration, less)

#define DEFINE_TIME_VALID(Type) \
bool Type##_valid(Type##_t t) { \
    return (t.nanoseconds >= 0 && t.nanoseconds < NS_IN_S); \
}

DEFINE_TIME_VALID(avs_time_realtime)
DEFINE_TIME_VALID(avs_time_monotonic)
DEFINE_TIME_VALID(avs_time_duration)

static int safe_add(int64_t *out, int64_t a, int64_t b) {
    if (a > 0 && b > 0) {
        uint64_t result = ((uint64_t) a) + ((uint64_t) b);
        if (result > (uint64_t) INT64_MAX) {
            return -1;
        }
        *out = (int64_t) result;
        return 0;
    } else if (a < 0 && b < 0) {
        if (a == INT64_MIN && b == INT64_MIN) {
            // this case would result in the addition below being 0
            return -1;
        }
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

static int normalize(int64_t *inout_seconds, int32_t *inout_nanoseconds) {
    assert(*inout_nanoseconds >= -NS_IN_S);
    assert(*inout_nanoseconds < 2 * NS_IN_S);
    if (*inout_nanoseconds < 0) {
        if (*inout_seconds == INT64_MIN) {
            return -1;
        }
        *inout_nanoseconds += NS_IN_S;
        --*inout_seconds;
    } else if (*inout_nanoseconds >= NS_IN_S) {
        if (*inout_seconds == INT64_MAX) {
            return -1;
        }
        *inout_nanoseconds -= NS_IN_S;
        ++*inout_seconds;
    }
    return 0;
}

#define DEFINE_TIME_ADD(Type) \
Type##_t Type##_add(Type##_t a, avs_time_duration_t b) { \
    if (!Type##_valid(a) || !avs_time_duration_valid(b)) { \
        return (Type##_t) AVS_TIME_INVALID_DECL; \
    } else { \
        Type##_t result; \
        result.nanoseconds = a.nanoseconds + b.nanoseconds; \
        if (safe_add(&result.seconds, a.seconds, b.seconds) \
                || normalize(&result.seconds, &result.nanoseconds)) { \
            return (Type##_t) AVS_TIME_INVALID_DECL; \
        } \
        assert(Type##_valid(result)); \
        return result; \
    } \
}

DEFINE_TIME_ADD(avs_time_realtime)
DEFINE_TIME_ADD(avs_time_monotonic)
DEFINE_TIME_ADD(avs_time_duration)

static int negate(int64_t *inout_seconds, int32_t *inout_nanoseconds) {
    if (*inout_seconds < 0) {
        // if *inout_seconds == INT64_MIN on U2 architectures,
        // attempting to negate it will result in erroneous value
        // even though negated time might still be representable
        ++*inout_seconds;
        *inout_nanoseconds -= NS_IN_S;
    }
    *inout_seconds *= -1; // safe, because of the above
    *inout_nanoseconds *= -1; // safe, because the absolute value
                              // is no greater than 10^9
    return normalize(inout_seconds, inout_nanoseconds);
}

#define DEFINE_TIME_DIFF(Type) \
avs_time_duration_t Type##_diff(Type##_t minuend, \
                                Type##_t subtrahend) { \
    if (!Type##_valid(minuend) || !Type##_valid(subtrahend)) { \
        return AVS_TIME_DURATION_INVALID; \
    } else { \
        Type##_t negated_subtrahend = subtrahend; \
        negate(&negated_subtrahend.seconds, &negated_subtrahend.nanoseconds); \
        avs_time_duration_t result; \
        result.nanoseconds = minuend.nanoseconds \
                + negated_subtrahend.nanoseconds; \
        if (safe_add(&result.seconds, \
                     minuend.seconds, negated_subtrahend.seconds) \
                || normalize(&result.seconds, &result.nanoseconds)) { \
            return AVS_TIME_DURATION_INVALID; \
        } \
        assert(avs_time_duration_valid(result)); \
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
    assert(factor >= 0);
    switch (operation) {
    case UCO_MUL:
        if (factor != 0
                && (input > INT64_MAX / factor || input < INT64_MIN / factor)) {
            return -1;
        }
        *output = input * factor;
        return 0;
    case UCO_DIV:
        if (factor == 0) {
            *output = 0;
        } else {
            *output = input / factor;
        }
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

static int time_conv_forward(int64_t *output,
                             int64_t seconds,
                             int32_t nanoseconds,
                             const time_conv_t *conv) {
    int64_t converted_s;
    int64_t converted_ns;
    if (seconds < 0 && nanoseconds > 0) {
        // if the time is near the range limit,
        // the negative value of seconds alone might be actually _out_ of range
        ++seconds;
        nanoseconds -= NS_IN_S;
    }
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
    return normalize(output_s, output_ns);
}

#define DEFINE_TIME_TO_SCALAR(Type) \
int Type##_to_scalar(int64_t *out, avs_time_unit_t unit, \
                     const Type##_t value) { \
    if (unit < 0 || unit > AVS_ARRAY_SIZE(CONVERSIONS) \
            || !Type##_valid(value)) { \
        return -1; \
    } \
    return time_conv_forward(out, value.seconds, value.nanoseconds, \
                             &CONVERSIONS[unit]); \
}

DEFINE_TIME_TO_SCALAR(avs_time_realtime)
DEFINE_TIME_TO_SCALAR(avs_time_monotonic)
DEFINE_TIME_TO_SCALAR(avs_time_duration)

#define DEFINE_TIME_FROM_SCALAR(Type) \
Type##_t Type##_from_scalar(int64_t value, avs_time_unit_t unit) { \
    if (unit < 0 && unit >= AVS_ARRAY_SIZE(CONVERSIONS)) { \
        return (Type##_t) AVS_TIME_INVALID_DECL; \
    } \
    Type##_t result; \
    if (time_conv_backward(&result.seconds, &result.nanoseconds, value, \
                           &CONVERSIONS[unit])) { \
        return (Type##_t) AVS_TIME_INVALID_DECL; \
    } \
    return result; \
}

DEFINE_TIME_FROM_SCALAR(avs_time_realtime)
DEFINE_TIME_FROM_SCALAR(avs_time_monotonic)
DEFINE_TIME_FROM_SCALAR(avs_time_duration)

static int safe_mul(int64_t *out, int64_t input, int64_t multiplier) {
    if (input == 0 || multiplier == 0) {
        *out = 0;
        return 0;
    } else if ((input == INT64_MIN && multiplier == 1)
            || (input == 1 && multiplier == INT64_MIN)) {
        *out = INT64_MIN;
        return 0;
    } else if (input == INT64_MIN || multiplier == INT64_MIN) {
        return -1;
    } else if (multiplier < 0) {
        return safe_mul(out, -input, -multiplier);
    } else {
        assert(multiplier > 0);
        if (input > INT64_MAX / multiplier || input < INT64_MIN / multiplier) {
            return -1;
        }
        *out = input * multiplier;
        return 0;
    }
}

avs_time_duration_t avs_time_duration_mul(avs_time_duration_t input,
                                          int32_t multiplier) {
    if (!avs_time_duration_valid(input)) {
        return AVS_TIME_DURATION_INVALID;
    } else {
        // multiplying two int32_t's into int64_t is always safe
        int64_t nanoseconds =
                (int64_t) input.nanoseconds * (int64_t) multiplier;
        int64_t seconds_rest = nanoseconds / NS_IN_S;
        avs_time_duration_t result;
        result.nanoseconds = (int32_t) (nanoseconds % NS_IN_S);
        if (safe_mul(&result.seconds, input.seconds, multiplier)
                || safe_add(&result.seconds, result.seconds, seconds_rest)
                || normalize(&result.seconds, &result.nanoseconds)) {
            return AVS_TIME_DURATION_INVALID;
        }

        assert(avs_time_duration_valid(result));
        return result;
    }
}

avs_time_duration_t avs_time_duration_div(avs_time_duration_t dividend,
                                          int32_t divisor) {
    if (!avs_time_duration_valid(dividend) || divisor == 0) {
        return AVS_TIME_DURATION_INVALID;
    } else {
        int64_t s_rest = dividend.seconds % divisor;
        avs_time_duration_t result = {
            .seconds = dividend.seconds / divisor,
            .nanoseconds = (int32_t) (((double) dividend.nanoseconds
                                           + (double) s_rest * NS_IN_S)
                                          / divisor)
        };
        normalize(&result.seconds, &result.nanoseconds);

        assert(avs_time_duration_valid(result));
        return result;
    }
}

avs_time_realtime_t avs_time_realtime_now(void) {
    struct timespec system_value;
    avs_time_realtime_t result;
    clock_gettime(CLOCK_REALTIME, &system_value);
    result.seconds = system_value.tv_sec;
    result.nanoseconds = (int32_t) system_value.tv_nsec;
    return result;
}

avs_time_monotonic_t avs_time_monotonic_now(void) {
    struct timespec system_value;
    avs_time_monotonic_t result;
    clock_gettime(CLOCK_MONOTONIC, &system_value);
    result.seconds = system_value.tv_sec;
    result.nanoseconds = (int32_t) system_value.tv_nsec;
    return result;
}

#ifdef AVS_UNIT_TESTING
#include "test/time.c"
#endif // AVS_UNIT_TESTING
