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

#include <stdio.h>
#include <assert.h>
#include <stdarg.h>

#include <avsystem/commons/utils.h>

int avs_simple_snprintf(char *out, size_t out_size, const char *format, ...) {
    assert(out || !out_size);
    va_list args;
    va_start(args, format);
    int result = vsnprintf(out, out_size, format, args);
    va_end(args);
    return (result < 0 || (size_t) result >= out_size) ? -1 : result;
}
