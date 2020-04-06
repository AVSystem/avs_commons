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
#    include <limits.h>

#    include <avsystem/commons/avs_utils.h>

VISIBILITY_SOURCE_BEGIN

int avs_hexlify(char *out_hex,
                size_t out_size,
                size_t *out_bytes_hexlified,
                const void *input,
                size_t input_size) {
    static const char HEX[] = "0123456789abcdef";
    if (!out_hex || !out_size) {
        return -1;
    }
    *out_hex = '\0';
    size_t bytes_to_hexlify = 0;
    if (input && input_size) {
        bytes_to_hexlify = AVS_MIN(input_size, (out_size - 1) / 2);
        assert(bytes_to_hexlify < SIZE_MAX / 2u);
        for (size_t i = 0; i < bytes_to_hexlify; ++i) {
            out_hex[2 * i + 0] = HEX[((const uint8_t *) input)[i] / 16];
            out_hex[2 * i + 1] = HEX[((const uint8_t *) input)[i] % 16];
        }
        out_hex[2 * bytes_to_hexlify] = '\0';
    }
    if (out_bytes_hexlified) {
        *out_bytes_hexlified = bytes_to_hexlify;
    }
    return 0;
}

static int8_t char_to_value(char c) {
    if (c >= '0' && c <= '9') {
        return (int8_t) (c - '0');
    } else if (c >= 'a' && c <= 'f') {
        return (int8_t) (c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
        return (int8_t) (c - 'A' + 10);
    } else {
        return -1;
    }
}

static int hex_to_uint8(const char *hex, uint8_t *out_value) {
    int8_t first_char_value = char_to_value(*hex);
    int8_t second_char_value = char_to_value(*(hex + 1));

    if (first_char_value < 0 || second_char_value < 0) {
        return -1;
    }
    *out_value = (uint8_t) ((first_char_value << 4) | second_char_value);
    return 0;
}

int avs_unhexlify(size_t *out_bytes_written,
                  uint8_t *output,
                  size_t out_size,
                  const char *input,
                  size_t in_size) {
    if (in_size % 2) {
        return -1;
    }

    const size_t data_size = in_size / 2;
    const size_t bytes_to_convert = AVS_MIN(data_size, out_size);

    size_t bytes_written = 0;
    while (bytes_written < bytes_to_convert) {
        if (hex_to_uint8(input + 2 * bytes_written, output + bytes_written)) {
            return -1;
        }
        ++bytes_written;
    }
    if (out_bytes_written) {
        *out_bytes_written = bytes_written;
    }
    return 0;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/utils/hexlify.c"
#    endif // AVS_UNIT_TESTING

#endif // AVS_COMMONS_WITH_AVS_UTILS
