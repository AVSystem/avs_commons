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
