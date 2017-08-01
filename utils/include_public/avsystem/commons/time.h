/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_UTILS_TIME_H
#define AVS_COMMONS_UTILS_TIME_H

#include <avsystem/commons/defs.h>

#include <stdbool.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct timespec;

bool avs_time_before(const struct timespec *a, const struct timespec *b);
bool avs_time_is_valid(const struct timespec *t);
void avs_time_add(struct timespec *result, const struct timespec *duration);
void avs_time_diff(struct timespec *result,
                   const struct timespec *minuend,
                   const struct timespec *subtrahend);
ssize_t avs_time_diff_ms(const struct timespec *minuend,
                         const struct timespec *subtrahend);
void avs_time_from_ms(struct timespec *result, int32_t ms);
void avs_time_from_s(struct timespec *result, time_t s);
void avs_time_add_ms(struct timespec *result, int32_t ms);
void avs_time_div(struct timespec *result,
                  const struct timespec *dividend,
                  uint32_t divisor);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_UTILS_TIME_H */
