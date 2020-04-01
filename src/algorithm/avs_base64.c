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

#ifdef AVS_COMMONS_WITH_AVS_ALGORITHM

#    include <assert.h>
#    include <ctype.h>
#    include <string.h>

#    include <avsystem/commons/avs_base64.h>

VISIBILITY_SOURCE_BEGIN

const char AVS_BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "abcdefghijklmnopqrstuvwxyz"
                                "0123456789+/";

const char AVS_BASE64_URL_SAFE_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                         "abcdefghijklmnopqrstuvwxyz"
                                         "0123456789-_";

const avs_base64_config_t AVS_BASE64_DEFAULT_LOOSE_CONFIG = {
    .alphabet = AVS_BASE64_CHARS,
    .padding_char = '=',
    .allow_whitespace = true,
    .require_padding = false
};

const avs_base64_config_t AVS_BASE64_DEFAULT_STRICT_CONFIG = {
    .alphabet = AVS_BASE64_CHARS,
    .padding_char = '=',
    .allow_whitespace = false,
    .require_padding = true
};

AVS_STATIC_ASSERT(sizeof(AVS_BASE64_CHARS) == 65, // 64 chars + NULL terminator
                  missing_base64_chars);

static int check_base64_out_buffer_size(size_t buffer_size,
                                        size_t data_length,
                                        bool use_padding) {
    size_t encoded_size;
    if (use_padding) {
        encoded_size = avs_base64_encoded_size(data_length);
    } else {
        encoded_size = avs_base64_encoded_size_without_padding(data_length);
    }
    return buffer_size >= encoded_size ? 0 : -1;
}

size_t avs_base64_encoded_size(size_t input_length) {
    size_t needed_size = (input_length / 3) * 4;
    needed_size += (input_length % 3) ? 4 : 0;
    needed_size += 1; /* NULL terminator */
    return needed_size;
}

size_t avs_base64_encoded_size_without_padding(size_t input_length) {
    size_t needed_size = (input_length / 3) * 4;
    size_t rest = input_length % 3;
    if (rest) {
        needed_size += rest + 1;
    }
    needed_size += 1; /* NULL terminator */
    return needed_size;
}

size_t avs_base64_estimate_decoded_size(size_t input_length) {
    return 3 * ((input_length + 3) / 4);
}

int avs_base64_encode_custom(char *out,
                             size_t out_length,
                             const uint8_t *input,
                             size_t input_length,
                             avs_base64_config_t config) {
    char *const out_begin = (char *) out;
    uint8_t num;
    size_t i;
    unsigned long sh = 0;

    if (check_base64_out_buffer_size(out_length, input_length,
                                     !!config.padding_char)) {
        return -1;
    }

    for (i = 0; i < input_length; ++i) {
        num = input[i];
        if (i % 3 == 0) {
            *out++ = config.alphabet[num >> 2];
            sh = num & 0x03;
        } else if (i % 3 == 1) {
            *out++ = config.alphabet[(sh << 4) + (num >> 4)];
            sh = num & 0x0F;
        } else {
            *out++ = config.alphabet[(sh << 2) + (num >> 6)];
            *out++ = config.alphabet[num & 0x3F];
        }
    }

    if (i % 3 == 1) {
        *out++ = config.alphabet[sh << 4];
    } else if (i % 3 == 2) {
        *out++ = config.alphabet[sh << 2];
    }

    if (config.padding_char) {
        for (i = (size_t) (out - out_begin); i % 4; ++i) {
            *out++ = config.padding_char;
        }
    }

    *out = '\0';
    return 0;
}

int avs_base64_decode_custom(size_t *out_bytes_decoded,
                             uint8_t *out,
                             size_t out_size,
                             const char *b64_data,
                             avs_base64_config_t config) {

    uint32_t accumulator = 0;
    uint8_t bits = 0;
    const uint8_t *current = (const uint8_t *) b64_data;
    size_t out_length = 0;
    size_t padding = 0;

    while (*current) {
        int ch = *current++;

        if (out_length >= out_size) {
            return -1;
        }
        if (isspace(ch)) {
            if (config.allow_whitespace) {
                continue;
            } else {
                return -1;
            }
        } else if (ch == *(const char *) &config.padding_char) {
            if (config.require_padding && ++padding > 2) {
                return -1;
            }
            continue;
        } else if (padding) {
            // padding in the middle of input
            return -1;
        }
        const char *ptr = (const char *) memchr(config.alphabet, ch, 64);
        if (!ptr) {
            return -1;
        }
        assert(ptr >= config.alphabet);
        assert(ptr - config.alphabet < 64);
        accumulator <<= 6;
        bits = (uint8_t) (bits + 6);
        accumulator |= (uint8_t) (ptr - config.alphabet);
        if (bits >= 8) {
            bits = (uint8_t) (bits - 8u);
            out[out_length++] = (uint8_t) ((accumulator >> bits) & 0xffu);
        }
    }

    if (config.padding_char && config.require_padding
            && padding != (3 - (out_length % 3)) % 3) {

        return -1;
    }

    if (out_bytes_decoded) {
        *out_bytes_decoded = out_length;
    }
    return 0;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/algorithm/base64.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_ALGORITHM
