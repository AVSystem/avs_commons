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
#include <limits.h>

#include <avsystem/commons/utils.h>

VISIBILITY_SOURCE_BEGIN

ssize_t avs_hexlify(char *out_hex,
                    size_t out_size,
                    const void *input,
                    size_t input_size) {
    static const char HEX[] = "0123456789abcdef";
    if (!out_hex || !out_size) {
        return -1;
    }
    *out_hex = '\0';
    if (!input || !input_size) {
        return 0;
    }
    const size_t bytes_to_hexlify = AVS_MIN(input_size, (out_size - 1) / 2);
    assert(bytes_to_hexlify < SIZE_MAX / 2u);
    for (size_t i = 0; i < bytes_to_hexlify; ++i) {
        out_hex[2 * i + 0] = HEX[((const uint8_t *) input)[i] / 16];
        out_hex[2 * i + 1] = HEX[((const uint8_t *) input)[i] % 16];
    }
    out_hex[2 * bytes_to_hexlify] = '\0';
    return (ssize_t) bytes_to_hexlify;
}

static int char_to_value(char c, uint8_t *out_value) {
    if (c >= '0' && c <= '9') {
        *out_value = (uint8_t) (c - '0');
    } else if (c >= 'a' && c <= 'f') {
        *out_value = (uint8_t) (c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
        *out_value = (uint8_t) (c - 'A' + 10);
    } else {
        return -1;
    }
    return 0;
}

static int hex_to_uint8(const char *hex, uint8_t *out_value) {
    uint8_t first_char_value;
    uint8_t second_char_value;
    if (char_to_value(*hex, &first_char_value)
            || char_to_value(*(hex + 1), &second_char_value)) {
        return -1;
    }
    *out_value = (uint8_t) (first_char_value << 4) | second_char_value;
    return 0;
}

ssize_t avs_unhexlify(uint8_t *output, size_t out_size, const char *input) {
    size_t hex_length = strlen(input);
    if (hex_length % 2) {
        return -1;
    }

    size_t data_size = hex_length / 2;
    if (data_size > out_size) {
        return -1;
    }

    size_t bytes_written = 0;
    while (bytes_written < data_size) {
        if (hex_to_uint8(input + 2 * bytes_written, output + bytes_written)) {
            return -1;
        }
        ++bytes_written;
    }
    return (ssize_t) bytes_written;
}

#ifdef AVS_UNIT_TESTING
#    include "test/hexlify.c"
#endif // AVS_UNIT_TESTING
