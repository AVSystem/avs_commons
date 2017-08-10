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

#include <config.h>

#include <ctype.h>
#include <string.h>
#include <strings.h>

#include <avsystem/commons/utils.h>

int avs_match_token(const char **stream, const char *token,
                    const char *delims) {
    size_t len = strlen(token);
    int result;
    /* skip leading whitespace, if any */
    while (**stream && isspace((unsigned char) **stream)) {
        ++*stream;
    }
    result = strncasecmp(*stream, token, len);
    if (result == 0) {
        if ((*stream)[len] && !strchr(delims, (unsigned char) (*stream)[len])) {
            return 1;
        }
        *stream += len;
        if (**stream) {
            ++*stream; // skip the (first) delimiter character
        }
    }
    return result;
}
