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

#ifndef AVS_COMMONS_UTILS_TIME_H
#define AVS_COMMONS_UTILS_TIME_H

#include <avsystem/commons/avs_defs.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Relative duration in time.
 */
typedef struct {
    /**
     * Number of seconds.
     */
    int64_t seconds;

    /**
     * A number between 0 and 999999999, inclusive, is treated as nanosecond
     * part of the time.
     *
     * Otherwise, the whole value is treated as invalid.
     */
    int32_t nanoseconds;
} avs_time_duration_t;

/**
 * Instant in real, calendar time.
 */
typedef struct {
    /**
     * Duration since January 1, 1970, midnight UTC.
     */
    avs_time_duration_t since_real_epoch;
} avs_time_real_t;

/**
 * Instant in CPU time.
 */
typedef struct {
    /**
     * Duration since some unspecified epoch that is guaranteed to be consistent
     * until reboot.
     */
    avs_time_duration_t since_monotonic_epoch;
} avs_time_monotonic_t;

/**
 * Time unit of a scalar value.
 */
typedef enum {
    /**
     * Days (24 hours).
     */
    AVS_TIME_DAY,

    /**
     * Hours (60 minutes).
     */
    AVS_TIME_HOUR,

    /**
     * Minutes (60 seconds).
     */
    AVS_TIME_MIN,

    /**
     * Seconds (durations of 9192631770 periods of the radiation corresponding
     * to the transition between the two hyperfine levels of the ground state of
     * the caesium 133 atom).
     */
    AVS_TIME_S,

    /**
     * Milliseconds (thousandths of a second).
     */
    AVS_TIME_MS,

    /**
     * Microseconds (thousandths of a millisecond).
     */
    AVS_TIME_US,

    /**
     * Nanoseconds (thousandths of a microsecond).
     */
    AVS_TIME_NS
} avs_time_unit_t;

/**
 * Exemplary value for which @ref avs_time_real_valid will return false.
 */
extern const avs_time_real_t AVS_TIME_REAL_INVALID;

/**
 * Exemplary value for which @ref avs_time_monotonic_valid will return false.
 */
extern const avs_time_monotonic_t AVS_TIME_MONOTONIC_INVALID;

/**
 * Exemplary value for which @ref avs_time_duration_valid will return false.
 */
extern const avs_time_duration_t AVS_TIME_DURATION_INVALID;

/**
 * Duration of zero length;
 */
extern const avs_time_duration_t AVS_TIME_DURATION_ZERO;

/**
 * @return True if <c>a</c> is a smaller duration than <c>b</c>, false
 *         otherwise. Note that if for either of the arguments
 *         @ref avs_time_duration_valid returns false, the result is always
 *         false.
 */
bool avs_time_duration_less(avs_time_duration_t a, avs_time_duration_t b);

/**
 * @return True if <c>a</c> is an earlier point in time than <c>b</c>, false
 *         otherwise. Note that if for either of the arguments
 *         @ref avs_time_real_valid returns false, the result is always false.
 */
static inline bool avs_time_real_before(avs_time_real_t a, avs_time_real_t b) {
    return avs_time_duration_less(a.since_real_epoch, b.since_real_epoch);
}

/**
 * @return True if <c>a</c> is an earlier point in time than <c>b</c>, false
 *         otherwise. Note that if for either of the arguments
 *         @ref avs_time_monotonic_valid returns false, the result is always
 *         false.
 */
static inline bool avs_time_monotonic_before(avs_time_monotonic_t a,
                                             avs_time_monotonic_t b) {
    return avs_time_duration_less(a.since_monotonic_epoch,
                                  b.since_monotonic_epoch);
}

/**
 * @return True if <c>a</c> is exactly the same duration as <c>b</c>, false
 *         otherwise. Note that if for either of the arguments
 *         @ref avs_time_duration_valid returns false, the result is always
 *         false.
 */
bool avs_time_duration_equal(avs_time_duration_t a, avs_time_duration_t b);

/**
 * @return True if <c>a</c> is an exactly the same point in time as <c>b</c>,
 *         false otherwise. Note that if for either of the arguments
 *         @ref avs_time_real_valid returns false, the result is always false.
 */
static inline bool avs_time_real_equal(avs_time_real_t a, avs_time_real_t b) {
    return avs_time_duration_equal(a.since_real_epoch, b.since_real_epoch);
}

/**
 * @return True if <c>a</c> is an exactly the same point in time as <c>b</c>,
 *         false otherwise. Note that if for either of the arguments
 *         @ref avs_time_monotonic_valid returns false, the result is always
 *         false.
 */
static inline bool avs_time_monotonic_equal(avs_time_monotonic_t a,
                                            avs_time_monotonic_t b) {
    return avs_time_duration_equal(a.since_monotonic_epoch,
                                   b.since_monotonic_epoch);
}

/**
 * Checks whether the argument specifies a valid duration. Any value that has
 * out-of-range nanoseconds component is treated as invalid time, with semantics
 * similar to the handling of NaN in floating-point arithmetic.
 */
bool avs_time_duration_valid(avs_time_duration_t t);

/**
 * Checks whether the argument specifies a valid point in time. Any value that
 * has out-of-range nanoseconds component is treated as invalid time, with
 * semantics similar to the handling of NaN in floating-point arithmetic.
 */
static inline bool avs_time_real_valid(avs_time_real_t t) {
    return avs_time_duration_valid(t.since_real_epoch);
}

/**
 * Checks whether the argument specifies a valid point in time. Any value that
 * has out-of-range nanoseconds component is treated as invalid time, with
 * semantics similar to the handling of NaN in floating-point arithmetic.
 */
static inline bool avs_time_monotonic_valid(avs_time_monotonic_t t) {
    return avs_time_duration_valid(t.since_monotonic_epoch);
}

/**
 * Adds two time durations.
 *
 * @param a The first duration to add.
 * @param b The second duration to add.
 *
 * @return Sum value, or an invalid time value if any of the terms is an invalid
 *         time value.
 */
avs_time_duration_t avs_time_duration_add(avs_time_duration_t a,
                                          avs_time_duration_t b);

/**
 * Adds a duration to a realtime instant.
 *
 * @param a The instant to add to.
 * @param b The time duration to add.
 *
 * @return Sum value, or an invalid time value if any of the terms is an invalid
 *         time value.
 */
static inline avs_time_real_t avs_time_real_add(avs_time_real_t a,
                                                avs_time_duration_t b) {
    avs_time_real_t result = { avs_time_duration_add(a.since_real_epoch, b) };
    return result;
}

/**
 * Adds a duration to a monotonic instant.
 *
 * @param a The instant to add to.
 * @param b The time duration to add.
 *
 * @return Sum value, or an invalid time value if any of the terms is an invalid
 *         time value.
 */
static inline avs_time_monotonic_t
avs_time_monotonic_add(avs_time_monotonic_t a, avs_time_duration_t b) {
    avs_time_monotonic_t result = {
        avs_time_duration_add(a.since_monotonic_epoch, b)
    };
    return result;
}

/**
 * Calculates a difference between two durations.
 *
 * @param minuend    The value to subtract from.
 * @param subtrahend The duration to subtract.
 *
 * @return Difference value, or an invalid time value if any of the input
 *         arguments is an invalid time value.
 */
avs_time_duration_t avs_time_duration_diff(avs_time_duration_t minuend,
                                           avs_time_duration_t subtrahend);

/**
 * Calculates a duration between two realtime instants.
 *
 * @param minuend    The end of the duration to calculate.
 * @param subtrahend The start of the duration to calculate.
 *
 * @return Difference value, or an invalid time value if any of the input
 *         arguments is an invalid time value.
 */
static inline avs_time_duration_t
avs_time_real_diff(avs_time_real_t minuend, avs_time_real_t subtrahend) {
    return avs_time_duration_diff(minuend.since_real_epoch,
                                  subtrahend.since_real_epoch);
}

/**
 * Calculates a duration between two monotonic instants.
 *
 * @param minuend    The end of the duration to calculate.
 * @param subtrahend The start of the duration to calculate.
 *
 * @return Difference value, or an invalid time value if any of the input
 *         arguments is an invalid time value.
 */
static inline avs_time_duration_t
avs_time_monotonic_diff(avs_time_monotonic_t minuend,
                        avs_time_monotonic_t subtrahend) {
    return avs_time_duration_diff(minuend.since_monotonic_epoch,
                                  subtrahend.since_monotonic_epoch);
}

/**
 * Converts a time duration into an integer value.
 *
 * @param out   Pointer to a variable to store the result in.
 * @param unit  Time unit to express the result in.
 * @param value Input value to convert.
 *
 * @return 0 for success, or -1 if <c>value</c> is not a valid time value.
 */
int avs_time_duration_to_scalar(int64_t *out,
                                avs_time_unit_t unit,
                                avs_time_duration_t value);

/**
 * Converts a realtime instant into an integer value relative to January 1,
 * 1970, midnight UTC.
 *
 * @param out   Pointer to a variable to store the result in.
 * @param unit  Time unit to express the result in.
 * @param value Input value to convert.
 *
 * @return 0 for success, or -1 if <c>value</c> is not a valid time value.
 */
static inline int avs_time_real_to_scalar(int64_t *out,
                                          avs_time_unit_t unit,
                                          avs_time_real_t value) {
    return avs_time_duration_to_scalar(out, unit, value.since_real_epoch);
}

/**
 * Converts a monotonic instant into an integer value relative to some
 * unspecified epoch that is guaranteed to be consistent until reboot.
 *
 * @param out   Pointer to a variable to store the result in.
 * @param unit  Time unit to express the result in.
 * @param value Input value to convert.
 *
 * @return 0 for success, or -1 if <c>value</c> is not a valid time value.
 */
static inline int avs_time_monotonic_to_scalar(int64_t *out,
                                               avs_time_unit_t unit,
                                               avs_time_monotonic_t value) {
    return avs_time_duration_to_scalar(out, unit, value.since_monotonic_epoch);
}

/**
 * Converts a time duration into a floating-point value.
 *
 * @param value Input value to convert.
 * @param unit  Time unit to express the result in.
 *
 * @return The converted value, or NaN if <c>value</c> is not a valid time
 *         value.
 */
double avs_time_duration_to_fscalar(avs_time_duration_t value,
                                    avs_time_unit_t unit);

/**
 * Converts a realtime instant into an integer value relative to January 1,
 * 1970, midnight UTC.
 *
 * @param value Input value to convert.
 * @param unit  Time unit to express the result in.
 *
 * @return The converted value, or NaN if <c>value</c> is not a valid time
 *         value.
 */
static inline double avs_time_real_to_fscalar(avs_time_real_t value,
                                              avs_time_unit_t unit) {
    return avs_time_duration_to_fscalar(value.since_real_epoch, unit);
}

/**
 * Converts a monotonic instant into a floating-point value relative to some
 * unspecified epoch that is guaranteed to be consistent until reboot.
 *
 * @param value Input value to convert.
 * @param unit  Time unit to express the result in.
 *
 * @return The converted value, or NaN if <c>value</c> is not a valid time
 *         value.
 */
static inline double avs_time_monotonic_to_fscalar(avs_time_monotonic_t value,
                                                   avs_time_unit_t unit) {
    return avs_time_duration_to_fscalar(value.since_monotonic_epoch, unit);
}

/**
 * Creates a time duration based on an integer value.
 *
 * @param value Number of <c>unit</c>s in the duration.
 * @param unit  Time unit the <c>value</c> is expressed in.
 *
 * @return Converted value. or an invalid time value if <c>value</c> is out of
 *         range for a given <c>unit</c>.
 */
avs_time_duration_t avs_time_duration_from_scalar(int64_t value,
                                                  avs_time_unit_t unit);

/**
 * Creates a realtime instant based on an integer value.
 *
 * @param value Number of <c>unit</c>s since January 1, 1970, midnight UTC.
 * @param unit  Time unit the <c>value</c> is expressed in.
 *
 * @return Converted value. or an invalid time value if <c>value</c> is out of
 *         range for a given <c>unit</c>.
 */
static inline avs_time_real_t avs_time_real_from_scalar(int64_t value,
                                                        avs_time_unit_t unit) {
    avs_time_real_t result = { avs_time_duration_from_scalar(value, unit) };
    return result;
}

/**
 * Creates a monotonic instant based on an integer value.
 *
 * @param value Number of <c>unit</c>s since the system monotonic clock epoch,
 *              which is unspecified but guaranteed to be consistent until
 *              reboot.
 * @param unit  Time unit the <c>value</c> is expressed in.
 *
 * @return Converted value. or an invalid time value if <c>value</c> is out of
 *         range for a given <c>unit</c>.
 */
static inline avs_time_monotonic_t
avs_time_monotonic_from_scalar(int64_t value, avs_time_unit_t unit) {
    avs_time_monotonic_t result = { avs_time_duration_from_scalar(value,
                                                                  unit) };
    return result;
}

/**
 * Creates a time duration based on a floating-point value.
 *
 * @param value Number of <c>unit</c>s in the duration.
 * @param unit  Time unit the <c>value</c> is expressed in.
 *
 * @return Converted value. or an invalid time value if <c>value</c> is out of
 *         range for a given <c>unit</c>.
 */
avs_time_duration_t avs_time_duration_from_fscalar(double value,
                                                   avs_time_unit_t unit);

/**
 * Creates a realtime instant based on a floating-point value.
 *
 * @param value Number of <c>unit</c>s since January 1, 1970, midnight UTC.
 * @param unit  Time unit the <c>value</c> is expressed in.
 *
 * @return Converted value. or an invalid time value if <c>value</c> is out of
 *         range for a given <c>unit</c>.
 */
static inline avs_time_real_t avs_time_real_from_fscalar(double value,
                                                         avs_time_unit_t unit) {
    avs_time_real_t result = { avs_time_duration_from_fscalar(value, unit) };
    return result;
}

/**
 * Creates a monotonic instant based on a floating-point value.
 *
 * @param value Number of <c>unit</c>s since the system monotonic clock epoch,
 *              which is unspecified but guaranteed to be consistent until
 *              reboot.
 * @param unit  Time unit the <c>value</c> is expressed in.
 *
 * @return Converted value. or an invalid time value if <c>value</c> is out of
 *         range for a given <c>unit</c>.
 */
static inline avs_time_monotonic_t
avs_time_monotonic_from_fscalar(double value, avs_time_unit_t unit) {
    avs_time_monotonic_t result = { avs_time_duration_from_fscalar(value,
                                                                   unit) };
    return result;
}

/**
 * Multiplies a time duration by an integer scalar value.
 *
 * @param input      The time duration to multiply.
 * @param multiplier The multiplier.
 *
 * @return Multiplication result, or an invalid time value if <c>input</c> is an
 *         invalid time value.
 */
avs_time_duration_t avs_time_duration_mul(avs_time_duration_t input,
                                          int32_t multiplier);

/**
 * Multiplies a time duration by a floating-point scalar value.
 *
 * @param input      The time duration to multiply.
 * @param multiplier The multiplier.
 *
 * @return Multiplication result, or an invalid time value if <c>input</c> is an
 *         invalid time value.
 */
avs_time_duration_t avs_time_duration_fmul(avs_time_duration_t input,
                                           double multiplier);

/**
 * Creates a time duration that is an integer fraction of another.
 *
 * @param input   The time duration to divide.
 * @param divisor Denominator of the fraction to calculate.
 *
 * @return Division result, or an invalid time value if either <c>input</c> is
 *         an invalid time value, or <c>divisor</c> is 0.
 */
avs_time_duration_t avs_time_duration_div(avs_time_duration_t input,
                                          int32_t divisor);

/**
 * @return Current system time expressed as @ref avs_time_real_t
 */
avs_time_real_t avs_time_real_now(void);

/**
 * @return Current system monotonic clock value expressed as
 *         @ref avs_time_monotonic_t
 */
avs_time_monotonic_t avs_time_monotonic_now(void);

/**
 * Length of the internal buffer used by @ref AVS_TIME_DURATION_AS_STRING .
 *
 * Note that the lowest representable time value is
 * -9223372036854775808.000000000, and that as a string is 30 characters long.
 * Including the final null byte, that's 31. We use 32 because it's a nice,
 * round number.
 */
#define AVS_TIME_DURATION_AS_STRING_MAX_LENGTH 32

/**
 * Internal implementation for @ref AVS_TIME_DURATION_AS_STRING.
 */
const char *avs_time_duration_as_string_impl__(
        char (*buf)[AVS_TIME_DURATION_AS_STRING_MAX_LENGTH],
        avs_time_duration_t time);

/**
 * Converts an @ref avs_time_duration_t value to string. The time is rendered as
 * a decimal number of seconds with fixed 9 digits after the decimal point, or
 * <c>"TIME_INVALID"</c> for an invalid time value.
 *
 * @param Time The @ref avs_time_duration_t value to stringify
 *
 * @returns Pointer to a temporary (stack-allocated, valid until the end of the
 *          enclosing code block) string representation of @p Time .
 */
#define AVS_TIME_DURATION_AS_STRING(Time) \
    avs_time_duration_as_string_impl__(   \
            &(char[AVS_TIME_DURATION_AS_STRING_MAX_LENGTH]){ "" }, (Time))

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_UTILS_TIME_H */
