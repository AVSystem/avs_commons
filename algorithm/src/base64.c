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

#include <assert.h>
#include <ctype.h>
#include <string.h>

#include <avsystem/commons/base64.h>

VISIBILITY_SOURCE_BEGIN

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789+/";

AVS_STATIC_ASSERT(sizeof(base64_chars) == 65, /* 64 chars + NULL terminator */
                  missing_base64_chars);

static int check_base64_out_buffer_size(size_t buffer_size,
                                        size_t data_length) {
    return buffer_size >= avs_base64_encoded_size(data_length) ? 0 : -1;
}

size_t avs_base64_encoded_size(size_t input_length) {
    size_t needed_size = (input_length / 3) * 4;
    needed_size += (input_length % 3) ? 4 : 0;
    needed_size += 1; /* NULL terminator */
    return needed_size;
}

size_t avs_base64_estimate_decoded_size(size_t input_length) {
    return 3 * ((input_length + 3) / 4);
}

int avs_base64_encode(char *out,
                      size_t out_length,
                      const uint8_t *input,
                      size_t input_length) {
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

typedef int base64_validator_t(const char *current, void *args);

static int base64_decode_validator(const char *current, void *args) {
    int index = (uint8_t) *current;
    (void) args;
    if (isspace(index) || index == '=') {
        return 0;
    }
    if (((size_t) index >= sizeof(base64_chars_reversed))
            || (base64_chars_reversed[index] > 63)) {
        return -1;
    }
    return 0;
}

static ssize_t base64_decode_impl(uint8_t *out,
                                  size_t out_size,
                                  const char *b64_data,
                                  base64_validator_t *validator,
                                  void *validator_args) {
    uint32_t accumulator = 0;
    uint8_t bits = 0;
    const char *current = b64_data;
    ssize_t out_length = 0;

    while (*current) {
        int idx = (uint8_t) *current++;

        if ((size_t)out_length >= out_size) {
            return -1;
        }
        if (validator(current - 1, validator_args)) {
            return -1;
        }
        if (isspace(idx) || idx == '=') {
            continue;
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

ssize_t avs_base64_decode(uint8_t *out, size_t out_size, const char *b64_data) {
    return base64_decode_impl(out, out_size, b64_data, base64_decode_validator,
                              NULL);
}

typedef struct {
    size_t padding;
    const char *last;
} base64_strict_validator_ctx_t;

static int base64_decode_strict_validator(const char *current, void *args) {
    base64_strict_validator_ctx_t *ctx = (base64_strict_validator_ctx_t *) args;
    ctx->last = current;
    if (base64_decode_validator(current, NULL)
            || isspace((unsigned char)*current)) {
        return -1;
    }
    if (*current == '=') {
        if (++ctx->padding > 2) {
            return -1;
        }
    } else if (ctx->padding) {
        /* padding in the middle of input */
        return -1;
    }
    return 0;
}

ssize_t avs_base64_decode_strict(uint8_t *out,
                                 size_t out_size,
                                 const char *b64_data) {
    base64_strict_validator_ctx_t ctx;
    ssize_t retval;
    ctx.padding = 0;
    ctx.last = b64_data;
    if (*b64_data == '\0') {
        return 0;
    }
    retval = base64_decode_impl(out, out_size, b64_data,
                                base64_decode_strict_validator, &ctx);
    if (retval >= 0) {
        assert(*ctx.last != '\0');
        /* Point at NULL terminator. */
        ++ctx.last;

        assert(*ctx.last == '\0');
        assert(ctx.last > b64_data);
        if ((ctx.last - b64_data) % 4 != 0) {
            return -1;
        }
    }
    return retval;
}

#ifdef AVS_UNIT_TESTING
#include "test/base64.c"
#endif
