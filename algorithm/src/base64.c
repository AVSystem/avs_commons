/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */
#include <config.h>

#include <ctype.h>

#include <avsystem/commons/base64.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789+/";

AVS_STATIC_ASSERT(sizeof(base64_chars) == 65, /* 64 chars + NULL terminator */
                  missing_base64_chars);

static int check_base64_out_buffer_size(size_t buffer_size,
                                        size_t data_length) {
    size_t needed_size = (data_length / 3) * 4;
    needed_size += (data_length % 3) ? 4 : 0;
    needed_size += 1; /* NULL terminator */
    return buffer_size >= needed_size ? 0 : -1;
}

int avs_base64_encode(const uint8_t *input,
                      size_t input_length,
                      char *out,
                      size_t out_length) {
    char *const out_begin = (char *) out;
    uint8_t num;
    size_t i;
    unsigned long sh = 0;

    if (check_base64_out_buffer_size(out_length, input_length)) {
        return -1;
    }

    for (i = 0; i < input_length; ++i) {
        num = input[i];
        if (i % 3 == 0) {
            *out++ = base64_chars[num >> 2];
            sh = num & 0x03;
        } else if (i % 3 == 1) {
            *out++ = base64_chars[(sh << 4) + (num >> 4)];
            sh = num & 0x0F;
        } else {
            *out++ = base64_chars[(sh << 2) + (num >> 6)];
            *out++ = base64_chars[num & 0x3F];
        }
    }

    if (i % 3 == 1) {
        *out++ = base64_chars[sh << 4];
    } else if (i % 3 == 2) {
        *out++ = base64_chars[sh << 2];
    }

    /* '=' padding */
    for (i = (size_t) (out - out_begin); i % 4 ; ++i) {
        *out++ = '=';
    }

    *out = '\0';
    return 0;
}

static const uint8_t base64_chars_reversed[128] = {
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
   64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
   64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
};

ssize_t avs_base64_decode(const char *b64_data, uint8_t *out, size_t out_size) {
    uint32_t accumulator = 0;
    uint8_t bits = 0;
    const char *current = b64_data;
    ssize_t out_length = 0;

    while (*current) {
        int idx = (uint8_t) *current++;

        if ((size_t)out_length >= out_size) {
            return -1;
        }
        if (isspace(idx) || idx == '=') {
            continue;
        }
        if (((size_t)idx >= sizeof(base64_chars_reversed))
                || (base64_chars_reversed[idx] > 63)) {
            return -1;
        }
        accumulator <<= 6;
        bits = (uint8_t) (bits + 6);
        accumulator |= base64_chars_reversed[idx];
        if (bits >= 8) {
            bits = (uint8_t) (bits - 8u);
            out[out_length++] = (uint8_t) ((accumulator >> bits) & 0xffu);
        }
    }

    return out_length;
}

#ifdef AVS_UNIT_TESTING
#include "test/base64.c"
#endif
