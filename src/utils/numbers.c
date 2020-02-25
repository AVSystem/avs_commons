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

#    include <avsystem/commons/avs_utils.h>

#    include <math.h>
#    include <stdlib.h>

VISIBILITY_SOURCE_BEGIN

int avs_rand_r(avs_rand_seed_t *seed) {
    return (*seed = *seed * 1103515245u + 12345u)
           % (avs_rand_seed_t) (AVS_RAND_MAX + 1);
}

#    if AVS_RAND_MAX >= UINT32_MAX
#        define RAND32_ITERATIONS 1
#    elif AVS_RAND_MAX >= UINT16_MAX
#        define RAND32_ITERATIONS 2
#    else
/* standard guarantees RAND_MAX to be at least 32767 */
#        define RAND32_ITERATIONS 3
#    endif

uint32_t avs_rand32_r(avs_rand_seed_t *seed) {
    uint32_t result = 0;
    int i;
    for (i = 0; i < RAND32_ITERATIONS; ++i) {
        result *= (uint32_t) AVS_RAND_MAX + 1;
        result += (uint32_t) avs_rand_r(seed);
    }
    return result;
}

#    ifdef AVS_COMMONS_BIG_ENDIAN
uint16_t avs_convert_be16(uint16_t value) {
    return value;
}

uint32_t avs_convert_be32(uint32_t value) {
    return value;
}

uint64_t avs_convert_be64(uint64_t value) {
    return value;
}
#    else  // AVS_COMMONS_BIG_ENDIAN
uint16_t avs_convert_be16(uint16_t value) {
    return (uint16_t) ((value >> 8) | (value << 8));
}

uint32_t avs_convert_be32(uint32_t value) {
    return (uint32_t) ((value >> 24) | ((value & 0xFF0000) >> 8)
                       | ((value & 0xFF00) << 8) | (value << 24));
}

uint64_t avs_convert_be64(uint64_t value) {
    return (uint64_t) ((value >> 56)
                       | ((value & UINT64_C(0xFF000000000000)) >> 40)
                       | ((value & UINT64_C(0xFF0000000000)) >> 24)
                       | ((value & UINT64_C(0xFF00000000)) >> 8)
                       | ((value & UINT64_C(0xFF000000)) << 8)
                       | ((value & UINT64_C(0xFF0000)) << 24)
                       | ((value & UINT64_C(0xFF00)) << 40) | (value << 56));
}
#    endif // AVS_COMMONS_BIG_ENDIAN

uint32_t avs_htonf(float f) {
    AVS_STATIC_ASSERT(sizeof(float) == sizeof(uint32_t), float_sane);
    union {
        float f;
        uint32_t ieee;
    } conv;
    conv.f = f;
    return avs_convert_be32(conv.ieee);
}

uint64_t avs_htond(double d) {
    AVS_STATIC_ASSERT(sizeof(double) == sizeof(uint64_t), float_sane);
    union {
        double d;
        uint64_t ieee;
    } conv;
    conv.d = d;
    return avs_convert_be64(conv.ieee);
}

float avs_ntohf(uint32_t v) {
    union {
        float f;
        uint32_t ieee;
    } conv;
    conv.ieee = avs_convert_be32(v);
    return conv.f;
}

double avs_ntohd(uint64_t v) {
    union {
        double d;
        uint64_t ieee;
    } conv;
    conv.ieee = avs_convert_be64(v);
    return conv.d;
}

static bool is_double_within_int64_range(double value) {
    AVS_STATIC_ASSERT(INT64_MIN != -INT64_MAX, standard_enforces_u2_for_intN_t);
    static const double DOUBLE_2_63 = (double) (((uint64_t) 1) << 63);
    // max == 2^63 - 1; min == -2^63
    return value >= -DOUBLE_2_63 && value < DOUBLE_2_63;
    // note that the largest value representable as IEEE 754 double that is
    // smaller than 2^63 is actually 2^63 - 1024
}

bool avs_double_convertible_to_int64(double value) {
    return nearbyint(value) == value && is_double_within_int64_range(value);
}

static bool is_double_within_uint64_range(double value) {
    static const double DOUBLE_2_64 = 2.0 * (double) (((uint64_t) 1) << 63);
    // max == 2^64 - 1; min == 0
    return value >= 0 && value < DOUBLE_2_64;
    // note that the largest value representable as IEEE 754 double that is
    // smaller than 2^64 is actually 2^64 - 2048
}

bool avs_double_convertible_to_uint64(double value) {
    return nearbyint(value) == value && is_double_within_uint64_range(value);
}

#endif // AVS_COMMONS_WITH_AVS_UTILS
