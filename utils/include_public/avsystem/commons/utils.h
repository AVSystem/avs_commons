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

#ifndef AVS_COMMONS_UTILS_UTILS_H
#define AVS_COMMONS_UTILS_UTILS_H

#include <avsystem/commons/defs.h>

#include <stdbool.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Standard guarantees RAND_MAX to be at least 0x7fff so let's
 * use it as a base for random number generators.
 */
#define AVS_RAND_MAX 0x7fff

/**
 * Returns a pseudo-random integer from range [0, AVS_RAND_MAX]. It is
 * thread-safe.
 */
int avs_rand_r(unsigned int *seed);

/** Tests whether @p value is a power of two */
static inline bool avs_is_power_of_2(size_t value) {
    return value > 0 && !(value & (value - 1));
}

/**
 * Wrapper around snprintf(), which always return a negative in case of
 * an error (which is the only thing differentiating it from snprintf()).
 *
 * @returns 0 on success, negative value on error.
 */
int avs_simple_snprintf(char *out, size_t out_size, const char *format, ...)
        AVS_F_PRINTF(3, 4);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_UTILS_UTILS_H */
