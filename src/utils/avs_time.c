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

#ifdef AVS_COMMONS_WITH_AVS_UTILS

#    include <assert.h>
#    include <inttypes.h>
#    include <math.h>

#    include <avsystem/commons/avs_time.h>
#    include <avsystem/commons/avs_utils.h>

VISIBILITY_SOURCE_BEGIN

#    define NS_IN_S INT32_C(1000000000)

#    define AVS_TIME_INVALID_DECL \
        {                         \
            .seconds = 0,         \
            .nanoseconds = -1     \
        }

const avs_time_real_t AVS_TIME_REAL_INVALID = {
    .since_real_epoch = AVS_TIME_INVALID_DECL
};
const avs_time_monotonic_t AVS_TIME_MONOTONIC_INVALID = {
    .since_monotonic_epoch = AVS_TIME_INVALID_DECL
};
const avs_time_duration_t AVS_TIME_DURATION_INVALID = AVS_TIME_INVALID_DECL;
const avs_time_duration_t AVS_TIME_DURATION_ZERO = { 0, 0 };

bool avs_time_duration_less(avs_time_duration_t a, avs_time_duration_t b) {
    if (!avs_time_duration_valid(a) || !avs_time_duration_valid(b)) {
        return false;
    } else {
        return (a.seconds < b.seconds)
               || (a.seconds == b.seconds && a.nanoseconds < b.nanoseconds);
    }
}

bool avs_time_duration_equal(avs_time_duration_t a, avs_time_duration_t b) {
    if (!avs_time_duration_valid(a) || !avs_time_duration_valid(b)) {
        return false;
    } else {
        return a.seconds == b.seconds && a.nanoseconds == b.nanoseconds;
    }
}

bool avs_time_duration_valid(avs_time_duration_t t) {
    return (t.nanoseconds >= 0 && t.nanoseconds < NS_IN_S);
}

#    ifdef AVS_COMMONS_HAVE_BUILTIN_ADD_OVERFLOW
__attribute__((optimize("-fno-trapv"))) static inline int
safe_add_int64_t(int64_t *out, int64_t a, int64_t b) {
    return __builtin_add_overflow(a, b, out) ? -1 : 0;
}
#    else  // AVS_COMMONS_HAVE_BUILTIN_ADD_OVERFLOW
static int safe_add_int64_t(int64_t *out, int64_t a, int64_t b) {
    if (a > 0 && b > 0) {
        uint64_t result = ((uint64_t) a) + ((uint64_t) b);
        if (result > (uint64_t) INT64_MAX) {
            return -1;
        }
        *out = (int64_t) result;
    } else if (a < 0 && b < 0) {
        if (a == INT64_MIN || b == INT64_MIN) {
            // this case would result in the addition below being 0
            return -1;
        }
        uint64_t result = ((uint64_t) -a) + ((uint64_t) -b);
        AVS_STATIC_ASSERT(-INT64_MAX - 1 == INT64_MIN,
                          standard_enforces_u2_for_intN_t);
        if (result > (uint64_t) INT64_MAX + 1) {
            return -1;
        } else if (result == (uint64_t) INT64_MAX + 1) {
            *out = INT64_MIN;
        } else {
            *out = -(int64_t) result;
        }
    } else {
        *out = a + b;
    }
    return 0;
}
#    endif // AVS_COMMONS_HAVE_BUILTIN_ADD_OVERFLOW

static inline int safe_add_double(double *out, double a, double b) {
    *out = a + b;
    return isfinite(*out) ? 0 : -1;
}

#    ifdef AVS_COMMONS_HAVE_BUILTIN_MUL_OVERFLOW
__attribute__((optimize("-fno-trapv"))) static inline int
safe_mul_int64_t(int64_t *out, int64_t input, int64_t multiplier) {
    return __builtin_mul_overflow(input, multiplier, out) ? -1 : 0;
}
#    else  // AVS_COMMONS_HAVE_BUILTIN_MUL_OVERFLOW
static int safe_mul_int64_t(int64_t *out, int64_t input, int64_t multiplier) {
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
        return safe_mul_int64_t(out, -input, -multiplier);
    } else {
        assert(multiplier > 0);
        if (input > INT64_MAX / multiplier || input < INT64_MIN / multiplier) {
            return -1;
        }
        *out = input * multiplier;
        return 0;
    }
}
#    endif // AVS_COMMONS_HAVE_BUILTIN_MUL_OVERFLOW

static inline int
safe_mul_double(double *out, double input, double multiplier) {
    *out = input * multiplier;
    return isfinite(*out) ? 0 : -1;
}

static int normalize(avs_time_duration_t *inout) {
    assert(inout->nanoseconds >= -NS_IN_S);
    assert(inout->nanoseconds < 2 * NS_IN_S);
    if (inout->nanoseconds < 0) {
        if (inout->seconds == INT64_MIN) {
            return -1;
        }
        inout->nanoseconds += NS_IN_S;
        --inout->seconds;
    } else if (inout->nanoseconds >= NS_IN_S) {
        if (inout->seconds == INT64_MAX) {
            return -1;
        }
        inout->nanoseconds -= NS_IN_S;
        ++inout->seconds;
    }
    return 0;
}

avs_time_duration_t avs_time_duration_add(avs_time_duration_t a,
                                          avs_time_duration_t b) {
    if (!avs_time_duration_valid(a) || !avs_time_duration_valid(b)) {
        return AVS_TIME_DURATION_INVALID;
    } else {
        avs_time_duration_t result;
        result.nanoseconds = a.nanoseconds + b.nanoseconds;
        if (safe_add_int64_t(&result.seconds, a.seconds, b.seconds)
                || normalize(&result)) {
            return AVS_TIME_DURATION_INVALID;
        }
        assert(avs_time_duration_valid(result));
        return result;
    }
}

static int negate(avs_time_duration_t *inout) {
    if (inout->seconds < 0) {
        // if inout->seconds == INT64_MIN on U2 architectures,
        // attempting to negate it will result in erroneous value
        // even though negated time might still be representable
        ++inout->seconds;
        inout->nanoseconds -= NS_IN_S;
    }
    inout->seconds *= -1;     // safe, because of the above
    inout->nanoseconds *= -1; // safe, because the absolute value
                              // is no greater than 10^9
    return normalize(inout);
}

avs_time_duration_t avs_time_duration_diff(avs_time_duration_t minuend,
                                           avs_time_duration_t subtrahend) {
    if (!avs_time_duration_valid(minuend)
            || !avs_time_duration_valid(subtrahend)) {
        return AVS_TIME_DURATION_INVALID;
    } else {
        avs_time_duration_t negated_subtrahend = subtrahend;
        negate(&negated_subtrahend);
        avs_time_duration_t result;
        result.nanoseconds =
                minuend.nanoseconds + negated_subtrahend.nanoseconds;
        if (safe_add_int64_t(&result.seconds, minuend.seconds,
                             negated_subtrahend.seconds)
                || normalize(&result)) {
            return AVS_TIME_DURATION_INVALID;
        }
        assert(avs_time_duration_valid(result));
        return result;
    }
}

typedef enum { UCO_MUL, UCO_DIV } unit_conv_op_t;

typedef struct {
    unit_conv_op_t operation;
    int64_t factor;
} unit_conv_t;

typedef struct {
    unit_conv_t conv_s;
    unit_conv_t conv_ns;
} time_conv_t;

static const time_conv_t CONVERSIONS[] = {
    [AVS_TIME_DAY] = { { UCO_DIV, 86400 }, { UCO_DIV, 86400000000000LL } },
    [AVS_TIME_HOUR] = { { UCO_DIV, 3600 }, { UCO_DIV, 3600000000000LL } },
    [AVS_TIME_MIN] = { { UCO_DIV, 60 }, { UCO_DIV, 60000000000LL } },
    [AVS_TIME_S] = { { UCO_MUL, 1 }, { UCO_DIV, 1000000000LL } },
    [AVS_TIME_MS] = { { UCO_MUL, 1000 }, { UCO_DIV, 1000000LL } },
    [AVS_TIME_US] = { { UCO_MUL, 1000000 }, { UCO_DIV, 1000LL } },
    [AVS_TIME_NS] = { { UCO_MUL, 1000000000 }, { UCO_MUL, 1LL } }
};

/**
 * Implementation the same as of is_double_within_int64_range() from numbers.c.
 * We don't have internal headers and this function shouldn't be in public API,
 * so it's duplicated instead.
 *
 * We don't want to use avs_double_convertible_to_int64() because it's preferred
 * to lose some precision during conversion from scalar to avs_time instead of
 * failing.
 */
static bool double_is_int64(double value) {
    AVS_STATIC_ASSERT(INT64_MIN != -INT64_MAX, standard_enforces_u2_for_intN_t);
    static const double DOUBLE_2_63 = (double) (((uint64_t) 1) << 63);
    // max == 2^63 - 1; min == -2^63
    return value >= -DOUBLE_2_63 && value < DOUBLE_2_63;
    // note that the largest value representable as IEEE 754 double that is
    // smaller than 2^63 is actually 2^63 - 1024
}

static int unit_conv_backward_int64_t_double(int64_t *output,
                                             double input,
                                             const unit_conv_t *conv) {
    assert(conv->factor > 0);
    double tmp = NAN;
    switch (conv->operation) {
    case UCO_DIV: // multiplication (because we're operating backwards)
        tmp = input * (double) conv->factor;
        break;
    case UCO_MUL: // division (because we're operating backwards)
        tmp = input / (double) conv->factor;
        break;
    default:
        AVS_UNREACHABLE("Invalid unit_conv operation");
    }
    if (!double_is_int64(tmp)) {
        return -1;
    }
    *output = (int64_t) tmp;
    return 0;
}

// unit_conv_int64_t_int64_t
// unit_conv_forward_int64_t_int64_t
// unit_conv_backward_int64_t_int64_t
// time_conv_forward_int64_t
// time_conv_backward_int64_t
#    define SCALAR_TYPE int64_t
#    include "avs_x_time_conv.h"

// unit_conv_double_int64_t
// unit_conv_forward_double_int64_t
// unit_conv_backward_double_int64_t
// time_conv_forward_double
// time_conv_backward_double
#    define SCALAR_TYPE double
#    include "avs_x_time_conv.h"

static bool unit_valid(avs_time_unit_t unit) {
    /* Some compilers implement avs_time_unit_t as unsigned int, causing
     * warning of pointless comparison. The solution is to make a temporary
     * int32_t variable with value of unit. */
    const int32_t s_unit = (int32_t) unit;
    return s_unit >= 0 && unit < AVS_ARRAY_SIZE(CONVERSIONS);
}

int avs_time_duration_to_scalar(int64_t *out,
                                avs_time_unit_t unit,
                                avs_time_duration_t value) {
    if (!unit_valid(unit) || !avs_time_duration_valid(value)) {
        return -1;
    }
    return time_conv_forward_int64_t(out, value.seconds, value.nanoseconds,
                                     &CONVERSIONS[unit]);
}

double avs_time_duration_to_fscalar(avs_time_duration_t value,
                                    avs_time_unit_t unit) {
    double out;
    if (!unit_valid(unit) || !avs_time_duration_valid(value)
            || time_conv_forward_double(&out, value.seconds, value.nanoseconds,
                                        &CONVERSIONS[unit])) {
        return NAN;
    }
    return out;
}

avs_time_duration_t avs_time_duration_from_scalar(int64_t value,
                                                  avs_time_unit_t unit) {
    if (!unit_valid(unit)) {
        return AVS_TIME_DURATION_INVALID;
    }
    avs_time_duration_t result;
    if (time_conv_backward_int64_t(&result, value, &CONVERSIONS[unit])) {
        return AVS_TIME_DURATION_INVALID;
    }
    return result;
}

avs_time_duration_t avs_time_duration_from_fscalar(double value,
                                                   avs_time_unit_t unit) {
    if (!unit_valid(unit) || !isfinite(value)) {
        return AVS_TIME_DURATION_INVALID;
    }
    avs_time_duration_t result;
    if (time_conv_backward_double(&result, value, &CONVERSIONS[unit])) {
        return AVS_TIME_DURATION_INVALID;
    }
    return result;
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
        if (safe_mul_int64_t(&result.seconds, input.seconds, multiplier)
                || safe_add_int64_t(&result.seconds, result.seconds,
                                    seconds_rest)
                || normalize(&result)) {
            return AVS_TIME_DURATION_INVALID;
        }

        assert(avs_time_duration_valid(result));
        return result;
    }
}

avs_time_duration_t avs_time_duration_fmul(avs_time_duration_t input,
                                           double multiplier) {
    if (!avs_time_duration_valid(input) || !isfinite(multiplier)) {
        return AVS_TIME_DURATION_INVALID;
    } else {
        double smul = (double) input.seconds * multiplier;
        double nsmul = (double) input.nanoseconds * multiplier;
        if (!isfinite(smul) || !isfinite(nsmul)) {
            return AVS_TIME_DURATION_INVALID;
        }

        double smul_ns = fmod(smul, 1.0) * NS_IN_S;
        smul = trunc(smul);

        double nsmul_s = trunc(nsmul / NS_IN_S);
        nsmul = fmod(nsmul, NS_IN_S);

        double seconds = smul + nsmul_s;
        if (!isfinite(seconds) || !double_is_int64(seconds)) {
            return AVS_TIME_DURATION_INVALID;
        }
        avs_time_duration_t result = {
            .seconds = (int64_t) seconds,
            .nanoseconds = (int32_t) round(smul_ns + nsmul)
        };
        // result.nanoseconds is in [-2*10^9, 2*10^9]
        // so we cannot use normalize(), which only works for [-10^9, 10^9 - 1]
        while (result.nanoseconds < 0) {
            if (result.seconds == INT64_MIN) {
                return AVS_TIME_DURATION_INVALID;
            }
            result.nanoseconds += NS_IN_S;
            --result.seconds;
        }
        while (result.nanoseconds >= NS_IN_S) {
            if (result.seconds == INT64_MAX) {
                return AVS_TIME_DURATION_INVALID;
            }
            result.nanoseconds -= NS_IN_S;
            ++result.seconds;
        }
        assert(avs_time_duration_valid(result));
        return result;
    }
}

avs_time_duration_t avs_time_duration_div(avs_time_duration_t dividend,
                                          int32_t divisor) {
    if (!avs_time_duration_valid(dividend) || divisor == 0
            || (INT64_MIN + INT64_MAX != 0 && dividend.seconds == INT64_MIN
                && divisor == -1)) {
        return AVS_TIME_DURATION_INVALID;
    } else {
        int64_t s_rest = dividend.seconds % divisor;
        avs_time_duration_t result = {
            .seconds = dividend.seconds / divisor,
            .nanoseconds = (int32_t) (((double) dividend.nanoseconds
                                       + (double) s_rest * NS_IN_S)
                                      / divisor)
        };
        normalize(&result);

        assert(avs_time_duration_valid(result));
        return result;
    }
}

const char *avs_time_duration_as_string_impl__(
        char (*buf)[AVS_TIME_DURATION_AS_STRING_MAX_LENGTH],
        avs_time_duration_t time) {
    int result;

    if (avs_time_duration_valid(time)) {
        if (time.seconds < 0 && time.nanoseconds > 0) {
            ++time.seconds;
            time.nanoseconds = 1000000000 - time.nanoseconds;
        }
        result = avs_simple_snprintf(
                *buf, AVS_TIME_DURATION_AS_STRING_MAX_LENGTH, "%s.%09" PRId32,
                AVS_INT64_AS_STRING(time.seconds), time.nanoseconds);
    } else {
        result = avs_simple_snprintf(
                *buf, AVS_TIME_DURATION_AS_STRING_MAX_LENGTH, "TIME_INVALID");
    }

    assert(result >= 0);
    (void) result;

    return *buf;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/utils/time.c"
#    endif // AVS_UNIT_TESTING

#endif // AVS_COMMONS_WITH_AVS_UTILS
