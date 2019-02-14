/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_posix_config.h>

#include <time.h>

#include <avsystem/commons/time.h>

VISIBILITY_SOURCE_BEGIN

avs_time_real_t avs_time_real_now(void) {
    struct timespec system_value;
    avs_time_real_t result;
    clock_gettime(CLOCK_REALTIME, &system_value);
    result.since_real_epoch.seconds = system_value.tv_sec;
    result.since_real_epoch.nanoseconds = (int32_t) system_value.tv_nsec;
    return result;
}

avs_time_monotonic_t avs_time_monotonic_now(void) {
    struct timespec system_value;
    avs_time_monotonic_t result;
#ifdef CLOCK_MONOTONIC
    if (clock_gettime(CLOCK_MONOTONIC, &system_value))
#endif
    {
        // CLOCK_MONOTONIC is not mandatory in POSIX;
        // fallback to REALTIME if we don't have it
        clock_gettime(CLOCK_REALTIME, &system_value);
    }
    result.since_monotonic_epoch.seconds = system_value.tv_sec;
    result.since_monotonic_epoch.nanoseconds = (int32_t) system_value.tv_nsec;
    return result;
}
