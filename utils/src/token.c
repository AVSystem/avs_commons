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

#include <avs_commons_config.h>

#include <ctype.h>
#include <string.h>

#include <avsystem/commons/utils.h>

VISIBILITY_SOURCE_BEGIN

int avs_match_token(const char **src, const char *token,
                    const char *delims) {
    size_t len = strlen(token);
    int result;
    /* skip leading whitespace, if any */
    while (**src && strchr(AVS_SPACES, (unsigned char) **src)) {
        ++*src;
    }
    result = avs_strncasecmp(*src, token, len);
    if (result == 0) {
        if ((*src)[len] && !strchr(delims, (unsigned char) (*src)[len])) {
            return 1;
        }
        *src += len;
        if (**src) {
            ++*src; // skip the (first) delimiter character
        }
    }
    return result;
}

void avs_consume_quotable_token(const char **src,
                                char *dest,
                                size_t dest_size,
                                const char *delims) {
    char quote = 0;

    if (dest_size == 0) {
        dest = NULL;
    }
    for (char value; (value = **src); ++*src) {
        if (value == '"') {
            quote = !quote;
            continue;
        } else if (quote && value == '\\') {
            value = *++*src;
        }
        if (!value || (!quote && strchr(delims, (unsigned char) value))) {
            break;
        }
        if (dest_size) {
            *dest++ = value;
            --dest_size;
        }
    }
    if (**src) {
        ++*src; // skip the (first) delimiter character
    }
    if (dest) {
        if (dest_size) {
            *dest = '\0';
        } else {
            *--dest = '\0';
        }
    }
}

#ifdef AVS_UNIT_TESTING
#include "test/token.c"
#endif // AVS_UNIT_TESTING
