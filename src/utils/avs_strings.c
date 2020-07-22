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
        *ptr = value % 10 + '0';
        value /= 10;
    } while (value);
    return ptr;
}

static const char *
int64_as_string_custom(char (*buf)[AVS_INT_STR_BUF_SIZE(int64_t)],
                       int64_t value) {
    if (value < 0) {
        char *ptr =
                (char *) (intptr_t) uint64_as_string_custom(buf,
                                                            (uint64_t) -value);
        ptr--;
        *ptr = '-';
        return ptr;
    }

    return uint64_as_string_custom(buf, (uint64_t) value);
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

#    ifdef AVS_UNIT_TESTING
#        include "tests/utils/strings.c"
#    endif // AVS_UNIT_TESTING

#endif // AVS_COMMONS_WITH_AVS_UTILS
