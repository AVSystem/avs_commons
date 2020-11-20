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
#    include <ctype.h>
#    include <inttypes.h>
#    include <stdarg.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    if defined(AVS_COMMONS_WITHOUT_FLOAT_FORMAT_SPECIFIERS) \
            || defined(AVS_UNIT_TESTING)
#        include <float.h>
#        include <math.h>
#    endif // defined(AVS_COMMONS_WITHOUT_FLOAT_FORMAT_SPECIFIERS) ||
           // defined(AVS_UNIT_TESTING)

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_utils.h>

VISIBILITY_SOURCE_BEGIN

int avs_simple_vsnprintf(char *out,
                         size_t out_size,
                         const char *format,
                         va_list args) {
    assert(out || !out_size);
    int result = vsnprintf(out, out_size, format, args);
    return (result < 0 || (size_t) result >= out_size) ? -1 : result;
}

int avs_simple_snprintf(char *out, size_t out_size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int result = avs_simple_vsnprintf(out, out_size, format, args);
    va_end(args);
    return result;
}

int avs_strcasecmp(const char *s1, const char *s2) {
    int c1;
    int c2;
    do {
        c1 = toupper(*(const unsigned char *) s1++);
        c2 = toupper(*(const unsigned char *) s2++);
    } while (c1 && c2 && c1 == c2);
    return c1 - c2;
}

int avs_strncasecmp(const char *s1, const char *s2, size_t n) {
    int c1 = 0;
    int c2 = 0;
    do {
        if (!n--) {
            break;
        }
        c1 = toupper(*(const unsigned char *) s1++);
        c2 = toupper(*(const unsigned char *) s2++);
    } while (c1 && c2 && c1 == c2);
    return c1 - c2;
}

char *avs_strtok(char *str, const char *delim, char **saveptr) {
    // adapted from
    // https://git.musl-libc.org/cgit/musl/tree/src/string/strtok_r.c
    if (!str && !(str = *saveptr)) {
        return NULL;
    }
    str += strspn(str, delim);
    if (!*str) {
        *saveptr = NULL;
        return NULL;
    }
    *saveptr = str + strcspn(str, delim);
    if (**saveptr) {
        *(*saveptr)++ = '\0';
    } else {
        *saveptr = NULL;
    }
    return str;
}

char *avs_strdup(const char *str) {
    size_t len = strlen(str);
    char *retval = (char *) avs_malloc(len + 1);
    if (!retval) {
        return NULL;
    }
    memcpy(retval, str, len + 1);
    return retval;
}

void avs_memswap(void *memptr1, void *memptr2, size_t n) {
    char *const ptr1 = (char *) memptr1;
    char *const ptr2 = (char *) memptr2;
    AVS_ASSERT(ptr1 >= ptr2 + n || ptr2 >= ptr1 + n,
               "memory fragments must not intersect");
    for (size_t i = 0; i < n; i++) {
        char tmp = ptr1[i];
        ptr1[i] = ptr2[i];
        ptr2[i] = tmp;
    }
}

#    if defined(AVS_COMMONS_WITHOUT_64BIT_FORMAT_SPECIFIERS) \
            || defined(AVS_UNIT_TESTING)

static const char *
uint64_as_string_custom(char (*buf)[AVS_UINT_STR_BUF_SIZE(uint64_t)],
                        uint64_t value) {
    char *ptr = *buf + AVS_UINT_STR_BUF_SIZE(uint64_t) - 1;
    *ptr = '\0';
    do {
        ptr--;
        *ptr = (char) (value % 10 + '0');
        value /= 10;
    } while (value);

    assert(ptr >= *buf);
    return ptr;
}

static const char *
int64_as_string_custom(char (*buf)[AVS_INT_STR_BUF_SIZE(int64_t)],
                       int64_t value) {
    uint64_t absolute_value;
    bool negative = false;
    if (value < 0) {
        absolute_value = (uint64_t) - (value + 1) + 1;
        negative = true;
    } else {
        absolute_value = (uint64_t) value;
    }

    char *ptr =
            (char *) (intptr_t) uint64_as_string_custom(buf, absolute_value);

    if (negative) {
        ptr--;
        *ptr = '-';
    }

    assert(ptr >= *buf);
    return ptr;
}

#    endif // defined(AVS_COMMONS_WITHOUT_64BIT_FORMAT_SPECIFIERS) ||
           // defined(AVS_UNIT_TESTING)

const char *
avs_uint64_as_string_impl__(char (*buf)[AVS_UINT_STR_BUF_SIZE(uint64_t)],
                            uint64_t value) {
#    ifdef AVS_COMMONS_WITHOUT_64BIT_FORMAT_SPECIFIERS
    return uint64_as_string_custom(buf, value);
#    else  // AVS_COMMONS_WITHOUT_64BIT_FORMAT_SPECIFIERS
    snprintf(*buf, AVS_UINT_STR_BUF_SIZE(uint64_t), "%" PRIu64, value);
    return *buf;
#    endif // AVS_COMMONS_WITHOUT_64BIT_FORMAT_SPECIFIERS
}

const char *
avs_int64_as_string_impl__(char (*buf)[AVS_INT_STR_BUF_SIZE(int64_t)],
                           int64_t value) {
#    ifdef AVS_COMMONS_WITHOUT_64BIT_FORMAT_SPECIFIERS
    return int64_as_string_custom(buf, value);
#    else  // AVS_COMMONS_WITHOUT_64BIT_FORMAT_SPECIFIERS
    snprintf(*buf, AVS_INT_STR_BUF_SIZE(int64_t), "%" PRId64, value);
    return *buf;
#    endif // AVS_COMMONS_WITHOUT_64BIT_FORMAT_SPECIFIERS
}

#    if defined(AVS_COMMONS_WITHOUT_FLOAT_FORMAT_SPECIFIERS) \
            || defined(AVS_UNIT_TESTING)

static int double_as_string_custom_impl(char *buf,
                                        size_t buf_size,
                                        double value,
                                        int16_t actual_e10,
                                        int16_t target_e10,
                                        uint8_t precision) {
    assert(buf_size >= AVS_UINT_STR_BUF_SIZE(uint64_t));
    assert(precision >= 1);
    assert(precision <= 18);
    int multiplier_e10 = precision - actual_e10 - 1;
    // For very small values there might be a need to do the multiplication in
    // multiple stages to avoid overflow of the multiplier.
    while (multiplier_e10 != 0) {
        int stage_multiplier_e10 =
                AVS_MIN(AVS_MAX(multiplier_e10, DBL_MIN_10_EXP),
                        DBL_MAX_10_EXP);
        value *= pow(10.0, stage_multiplier_e10);
        multiplier_e10 -= stage_multiplier_e10;
    }
    // value shall now be in the [0, 10^precision] range
    // although usually it'll be in [10^(precision-1), 10^precision)
    // NOTE: The "+ 0.5" term ensures proper rounding.
    char *decimal = (char *) (intptr_t) avs_uint64_as_string_impl__(
            (char(*)[AVS_UINT_STR_BUF_SIZE(uint64_t)]) buf,
            (uint64_t) (value + 0.5));
    assert(decimal >= buf && decimal < buf + buf_size);
    int16_t decimal_len = (int16_t) strlen(decimal);
    assert((size_t) decimal_len + 1 < buf_size);
    int16_t decimal_point_pos =
            (int16_t) (1 + actual_e10 + decimal_len - target_e10 - precision);
    assert(decimal_point_pos <= decimal_len);
    int16_t trailing_zeros = 0;
    while (trailing_zeros < decimal_len
           && decimal[decimal_len - 1 - trailing_zeros] == '0') {
        ++trailing_zeros;
    }
    assert(trailing_zeros <= decimal_len);
    if (trailing_zeros == decimal_len) {
        return avs_simple_snprintf(buf, buf_size, "0");
    } else if (decimal_point_pos <= 0) {
        assert((size_t) (decimal_len - trailing_zeros - decimal_point_pos + 2)
               < buf_size);
        memmove(buf + 2 - decimal_point_pos, decimal,
                (size_t) (decimal_len - trailing_zeros));
        buf[0] = '0';
        buf[1] = '.';
        for (int i = 2; i < 2 - decimal_point_pos; ++i) {
            buf[i] = '0';
        }
        buf[decimal_len - trailing_zeros - decimal_point_pos + 2] = '\0';
        return decimal_len - trailing_zeros - decimal_point_pos + 2;
    } else {
        memmove(buf, decimal, (size_t) decimal_point_pos);
        if (decimal_point_pos >= decimal_len - trailing_zeros) {
            buf[decimal_point_pos] = '\0';
            return decimal_point_pos;
        } else {
            memmove(buf + decimal_point_pos + 1, decimal + decimal_point_pos,
                    (size_t) (decimal_len - decimal_point_pos
                              - trailing_zeros));
            buf[decimal_point_pos] = '.';
            buf[decimal_len + 1 - trailing_zeros] = '\0';
            return decimal_len + 1 - trailing_zeros;
        }
    }
}

static int double_as_string_custom(char *buf,
                                   size_t buf_size,
                                   double value,
                                   uint8_t precision) {
    assert(precision >= 1);
    assert(precision <= 18);
    if (isnan(value)) {
        return avs_simple_snprintf(buf, buf_size, "nan");
    } else if (value == 0.0) {
        return avs_simple_snprintf(buf, buf_size, "0");
    } else if (value < 0.0) {
        assert(buf_size >= 2);
        buf[0] = '-';
        int result = double_as_string_custom(buf + 1, buf_size - 1, -value,
                                             precision);
        return result >= 0 ? result + 1 : result;
    } else if (isinf(value)) {
        // NOTE: With conjunction with the above case, this covers -inf as well
        return avs_simple_snprintf(buf, buf_size, "inf");
    } else {
        assert(value > 0.0);
        assert(isfinite(value));
        // For IEEE 754-compliant double, this shall be in the [-308, 308] range
        int16_t e10 = (int16_t) floor(log10(value));
        if (value <= 0.0001 || e10 >= precision) {
            int result = double_as_string_custom_impl(buf, buf_size, value, e10,
                                                      e10, precision);
            if (result < 0) {
                return result;
            }
            int result2 = avs_simple_snprintf(buf + result,
                                              buf_size - (size_t) result,
                                              "e%+" PRId16, e10);
            if (result2 < 0) {
                return result2;
            }
            return result + result2;
        } else {
            return double_as_string_custom_impl(buf, buf_size, value, e10, 0,
                                                precision);
        }
    }
}

#    endif // defined(AVS_COMMONS_WITHOUT_FLOAT_FORMAT_SPECIFIERS) ||
           // defined(AVS_UNIT_TESTING)

const char *
avs_double_as_string_impl__(char (*buf)[32], double value, uint8_t precision) {
    assert(precision >= 1);
    assert(precision <= 18);
    int result =
#    ifdef AVS_COMMONS_WITHOUT_FLOAT_FORMAT_SPECIFIERS
            double_as_string_custom(*buf, sizeof(*buf), value, precision);
#    else  // AVS_COMMONS_WITHOUT_FLOAT_FORMAT_SPECIFIERS
            avs_simple_snprintf(*buf, sizeof(*buf), "%.*g", precision, value);
#    endif // AVS_COMMONS_WITHOUT_FLOAT_FORMAT_SPECIFIERS
    assert(result >= 0);
    (void) result;
    return *buf;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/utils/strings.c"
#    endif // AVS_UNIT_TESTING

#endif // AVS_COMMONS_WITH_AVS_UTILS
