/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_config.h>

#include <ctype.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/memory.h>
#include <avsystem/commons/utils.h>

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
    // adapted from https://git.musl-libc.org/cgit/musl/tree/src/string/strtok_r.c
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
