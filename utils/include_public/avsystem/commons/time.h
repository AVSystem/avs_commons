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

#ifndef AVS_COMMONS_UTILS_TIME_H
#define AVS_COMMONS_UTILS_TIME_H

#include <avsystem/commons/defs.h>

#include <stdbool.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct timespec;

/**
 * Exemplary value for which @ref avs_time_is_valid will return false.
 */
extern const struct timespec AVS_TIME_INVALID;

/**
 * @return True if <c>a</c> is an earlier point in time than <c>b</c>, false
 *         otherwise. Note that if for either of the arguments
 *         @ref avs_time_is_valid returns false, the result is always false.
 */
bool avs_time_before(const struct timespec *a, const struct timespec *b);

/**
 * Checks whether the argument specifies a valid point in time. Any
 * <c>timespec</c> value that has out-of-range nanoseconds component is treated
 * as invalid time, with semantics similar to the handling of NaN in
 * floating-point arithmetic.
 */
bool avs_time_is_valid(const struct timespec *t);

/**
 * Adds one time value into another, much like the <c>+=</c> operator.
 *
 * Note that if for any of the terms @ref avs_time_is_valid returns false, the
 * result will be an invalid time value as well.
 *
 * @param result   Pointer to one of the terms on input, that the result will be
 *                 stored in on output.
 * @param duration Pointer to the other term.
 */
void avs_time_add(struct timespec *result, const struct timespec *duration);

/**
 * Subtracts one time value from another, calculating the difference.
 *
 * Note that if for any of the input arguments @ref avs_time_is_valid returns
 * false, the result will be an invalid time value as well.
 *
 * @param minuend    The value to subtract from.
 * @param subtrahend The duration to subtract.
 */
struct timespec avs_time_diff(const struct timespec *minuend,
                              const struct timespec *subtrahend);

/**
 * Converts a <c>timespec</c> value into a numeric count of milliseconds.
 *
 * @param out_ms Pointer to a variable to store the result in.
 * @param value  Input value to convert.
 *
 * @return 0 for success, or -1 if <c>value</c> is not a valid time value.
 */
int avs_time_to_ms(ssize_t *out_ms, const struct timespec *value);

/**
 * Subtracts one time value from another, calculating the difference, and stores
 * it as a count of milliseconds.
 *
 * @param out_ms     Pointer to the variable that the result will be stored in.
 * @param minuend    The value to subtract from.
 * @param subtrahend The duration to subtract.
 *
 * @return 0 for success, or -1 if either of input arguments is not a valid time
 *         value.
 */
int avs_time_diff_ms(ssize_t *out_ms,
                     const struct timespec *minuend,
                     const struct timespec *subtrahend);

/**
 * Converts a count of milliseconds into a <c>timespec</c> value.
 *
 * @param ms     Count of milliseconds to convert.
 */
struct timespec avs_time_from_ms(int32_t ms);

/**
 * Converts a count of seconds into a <c>timespec</c> value.
 *
 * @param result Pointer to a variable to store the result in.
 * @param ms     Count of seconds to convert.
 */
struct timespec avs_time_from_s(time_t s);

/**
 * Increases a <c>timespec</c> value by a specified count of milliseconds.
 *
 * Addition will not be performed if <c>result</c> is not a valid time value.
 *
 * @param result Pointer to the variable that holds the initial value and the
 *               result will be stored in.
 * @param ms     Number of milliseconds to add.
 */
void avs_time_add_ms(struct timespec *result, int32_t ms);

/**
 * Creates a time value that is an integer fraction of another.
 *
 * Note that if the dividend is not a valid time value, the result will be an
 * invalid time value as well.
 *
 * @param dividend Duration to divide.
 * @param divisor  Denominator of the fraction to calculate.
 */
struct timespec avs_time_div(const struct timespec *dividend,
                             uint32_t divisor);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_UTILS_TIME_H */
