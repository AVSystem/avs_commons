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

#include <avsystem/commons/coap/opt.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#include <avsystem/commons/coap/block_utils.h>
#include <avsystem/commons/utils.h>

#include "coap_log.h"
#include "msg_internal.h"
#include "parse_utils.h"

VISIBILITY_SOURCE_BEGIN

static inline size_t get_ext_field_size(uint8_t base_value) {
    assert(base_value < AVS_COAP_EXT_RESERVED);

    switch (base_value) {
    case AVS_COAP_EXT_U8:
        return sizeof(uint8_t);
    case AVS_COAP_EXT_U16:
        return sizeof(uint16_t);
    default:
        return 0;
    }
}

static inline uint32_t decode_ext_value(uint8_t base_value,
                                        const uint8_t *ext_value_ptr) {
    assert(base_value < AVS_COAP_EXT_RESERVED);

    switch (base_value) {
    case AVS_COAP_EXT_U8:
        return (uint32_t) * (const uint8_t *) ext_value_ptr
               + AVS_COAP_EXT_U8_BASE;
    case AVS_COAP_EXT_U16:
        return (uint32_t) extract_u16(ext_value_ptr) + AVS_COAP_EXT_U16_BASE;
    default:
        return base_value;
    }
}

static inline bool ext_value_overflows(uint8_t base_value,
                                       const uint8_t *ext_value_ptr) {
    return base_value == AVS_COAP_EXT_U16
           && extract_u16(ext_value_ptr) > UINT16_MAX - AVS_COAP_EXT_U16_BASE;
}

static inline const uint8_t *ext_delta_ptr(const avs_coap_opt_t *opt) {
    return opt->content;
}

static inline const uint8_t *ext_length_ptr(const avs_coap_opt_t *opt) {
    return opt->content
           + get_ext_field_size(_avs_coap_opt_get_short_delta(opt));
}

const uint8_t *avs_coap_opt_value(const avs_coap_opt_t *opt) {
    return ext_length_ptr(opt)
           + get_ext_field_size(_avs_coap_opt_get_short_length(opt));
}

int avs_coap_opt_u16_value(const avs_coap_opt_t *opt, uint16_t *out_value) {
    const uint8_t *value_data = avs_coap_opt_value(opt);
    uint32_t length = avs_coap_opt_content_length(opt);
    if (length > sizeof(*out_value)) {
        return -1;
    }
    *out_value = 0;
    for (size_t i = 0; i < length; ++i) {
        *out_value = (uint16_t) (*out_value << 8);
        *out_value = (uint16_t) (*out_value | value_data[i]);
    }
    return 0;
}

int avs_coap_opt_u32_value(const avs_coap_opt_t *opt, uint32_t *out_value) {
    const uint8_t *value_data = avs_coap_opt_value(opt);
    uint32_t length = avs_coap_opt_content_length(opt);
    if (length > sizeof(*out_value)) {
        return -1;
    }
    *out_value = 0;
    for (size_t i = 0; i < length; ++i) {
        *out_value = (uint32_t) (*out_value << 8);
        *out_value = (uint32_t) (*out_value | value_data[i]);
    }
    return 0;
}

int avs_coap_opt_string_value(const avs_coap_opt_t *opt,
                              size_t *out_bytes_read,
                              char *buffer,
                              size_t buffer_size) {
    size_t str_length = avs_coap_opt_content_length(opt);
    if (buffer_size <= str_length) {
        return -1;
    }
    memcpy(buffer, avs_coap_opt_value(opt), str_length);
    buffer[str_length] = '\0';
    *out_bytes_read = str_length + 1;
    return 0;
}

int avs_coap_opt_block_seq_number(const avs_coap_opt_t *opt,
                                  uint32_t *out_seq_num) {
    uint32_t value;
    if (avs_coap_opt_u32_value(opt, &value) || value >= (1 << 24)) {
        return -1;
    }

    *out_seq_num = (value >> 4);
    return 0;
}

int avs_coap_opt_block_has_more(const avs_coap_opt_t *opt, bool *out_has_more) {
    uint32_t value;
    if (avs_coap_opt_u32_value(opt, &value) || value >= (1 << 24)) {
        return -1;
    }

    *out_has_more = !!(value & 0x08);
    return 0;
}

int avs_coap_opt_block_size(const avs_coap_opt_t *opt, uint16_t *out_size) {
    uint32_t value = 0;
    if (avs_coap_opt_u32_value(opt, &value) || value >= (1 << 24)) {
        return -1;
    }

    *out_size = (uint16_t) (1 << ((value & 0x07) + 4));
    if (!avs_coap_is_valid_block_size(*out_size)) {
        return -1;
    }
    return 0;
}

uint32_t avs_coap_opt_delta(const avs_coap_opt_t *opt) {
    uint32_t delta = decode_ext_value(_avs_coap_opt_get_short_delta(opt),
                                      ext_delta_ptr(opt));
    assert(delta <= UINT16_MAX + AVS_COAP_EXT_U16_BASE);
    return delta;
}

uint32_t avs_coap_opt_content_length(const avs_coap_opt_t *opt) {
    uint32_t length = decode_ext_value(_avs_coap_opt_get_short_length(opt),
                                       ext_length_ptr(opt));
    assert(length <= UINT16_MAX + AVS_COAP_EXT_U16_BASE);
    return length;
}

static inline bool is_delta_valid(const avs_coap_opt_t *opt,
                                  size_t max_opt_bytes) {
    uint8_t short_delta = _avs_coap_opt_get_short_delta(opt);
    if (short_delta == AVS_COAP_EXT_RESERVED) {
        return false;
    }

    size_t required_bytes = 1 + get_ext_field_size(short_delta);
    return required_bytes <= max_opt_bytes
           && !ext_value_overflows(short_delta, ext_delta_ptr(opt));
}

static inline bool is_length_valid(const avs_coap_opt_t *opt,
                                   size_t max_opt_bytes) {
    uint8_t short_length = _avs_coap_opt_get_short_length(opt);
    if (short_length == AVS_COAP_EXT_RESERVED) {
        return false;
    }

    uint8_t short_delta = _avs_coap_opt_get_short_delta(opt);
    size_t required_bytes = 1 + get_ext_field_size(short_delta)
                            + get_ext_field_size(short_length);
    return required_bytes <= max_opt_bytes
           && !ext_value_overflows(short_length, ext_length_ptr(opt));
}

bool avs_coap_opt_is_valid(const avs_coap_opt_t *opt, size_t max_opt_bytes) {
    if (max_opt_bytes == 0 || !is_delta_valid(opt, max_opt_bytes)
            || !is_length_valid(opt, max_opt_bytes)) {
        return false;
    }

    uint32_t length = (uint32_t) avs_coap_opt_sizeof(opt);
    return (uintptr_t) opt->content + length >= (uintptr_t) opt->content
           && length <= max_opt_bytes;
}

size_t avs_coap_opt_sizeof(const avs_coap_opt_t *opt) {
    const uint8_t *endptr =
            avs_coap_opt_value(opt) + avs_coap_opt_content_length(opt);

    assert((const uint8_t *) opt < endptr);
    return (size_t) (endptr - (const uint8_t *) opt);
}

void avs_coap_opt_debug_print(const avs_coap_opt_t *opt) {
    LOG(DEBUG, _("opt: delta ") "%" PRIu32 _(", length ") "%" PRIu32 _(", content:"),
        avs_coap_opt_delta(opt), avs_coap_opt_content_length(opt));

    const uint8_t *value = avs_coap_opt_value(opt);
    for (size_t i = 0; i < avs_coap_opt_content_length(opt); ++i) {
        LOG(DEBUG,  "%02x" , value[i]);
    }
}

#ifdef AVS_UNIT_TESTING
#    include "test/opt.c"
#endif // AVS_UNIT_TESTING
