/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <stdio.h>
#include <assert.h>

#include <avsystem/commons/utils.h>

int avs_simple_snprintf(char *out, size_t out_size, const char *format, ...) {
    assert(out || !out_size);
    va_list args;
    va_start(args, format);
    int result = vsnprintf(out, out_size, format, args);
    va_end(args);
    return (result < 0 || (size_t) result >= out_size) ? -1 : 0;
}
