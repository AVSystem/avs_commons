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

#include <avs_commons_config.h>

#include <avsystem/commons/coap/msg_info.h>
#include <avsystem/commons/coap/msg_builder.h>
#include <avsystem/commons/utils.h>

#include "coap_log.h"
#include "msg_internal.h"

VISIBILITY_SOURCE_BEGIN

void
avs_coap_msg_info_reset(avs_coap_msg_info_t *info) {
    AVS_LIST_CLEAR(&info->options_);

    *info = avs_coap_msg_info_init();
}

static size_t
get_options_size_bytes(const AVS_LIST(avs_coap_msg_info_opt_t) opts) {
    size_t size = 0;
    uint16_t prev_opt_num = 0;

    const avs_coap_msg_info_opt_t *opt;
    AVS_LIST_FOREACH(opt, opts) {
        assert(opt->number >= prev_opt_num);

        uint16_t delta = (uint16_t)(opt->number - prev_opt_num);
        size += _avs_coap_get_opt_header_size(delta, opt->data_size)
                + opt->data_size;
        prev_opt_num = opt->number;
    }

    return size;
}

size_t
avs_coap_msg_info_get_headers_size(const avs_coap_msg_info_t *info) {
    return AVS_COAP_MAX_HEADER_SIZE
           + info->identity.token.size
           + get_options_size_bytes(info->options_);
}

size_t
avs_coap_msg_info_get_storage_size(const avs_coap_msg_info_t *info) {
    return offsetof(avs_coap_msg_t, content)
           + AVS_COAP_MAX_HEADER_SIZE
           + AVS_COAP_MAX_TOKEN_LENGTH
           + get_options_size_bytes(info->options_);
}

size_t
avs_coap_msg_info_get_packet_storage_size(const avs_coap_msg_info_t *info,
                                          size_t payload_size) {
    return avs_coap_msg_info_get_storage_size(info)
           + (payload_size ? sizeof(AVS_COAP_PAYLOAD_MARKER) + payload_size
                           : 0);
}

void avs_coap_msg_info_opt_remove_by_number(avs_coap_msg_info_t *info,
                                            uint16_t option_number) {
    avs_coap_msg_info_opt_t **opt;
    avs_coap_msg_info_opt_t *helper;
    AVS_LIST_DELETABLE_FOREACH_PTR(opt, helper, &info->options_) {
        if ((*opt)->number == option_number) {
            AVS_LIST_DELETE(opt);
        } else if ((*opt)->number > option_number) {
            return;
        }
    }
}

int avs_coap_msg_info_opt_content_format(avs_coap_msg_info_t *info,
                                         uint16_t format) {
    if (format == AVS_COAP_FORMAT_NONE) {
        return 0;
    }

    return avs_coap_msg_info_opt_u16(info, AVS_COAP_OPT_CONTENT_FORMAT, format);
}

static int encode_block_size(uint16_t size,
                             uint8_t *out_size_exponent) {
    switch (size) {
    case 16:   *out_size_exponent = 0; break;
    case 32:   *out_size_exponent = 1; break;
    case 64:   *out_size_exponent = 2; break;
    case 128:  *out_size_exponent = 3; break;
    case 256:  *out_size_exponent = 4; break;
    case 512:  *out_size_exponent = 5; break;
    case 1024: *out_size_exponent = 6; break;
    default:
       LOG(ERROR, "invalid block size: %d, expected power of 2 between 16 "
                "and 1024 (inclusive)", (int)size);
       return -1;
    }

    return 0;
}

static int add_block_opt(avs_coap_msg_info_t *info,
                         uint16_t option_number,
                         uint32_t seq_number,
                         bool is_last_chunk,
                         uint16_t size) {
    uint8_t size_exponent;
    if (encode_block_size(size, &size_exponent)) {
        return -1;
    }

    AVS_STATIC_ASSERT(sizeof(int) >= sizeof(int32_t), int_type_too_small);
    if (seq_number >= (1 << 20)) {
        LOG(ERROR, "block sequence number must be less than 2^20");
        return -1;
    }

    uint32_t value = ((seq_number & 0x000fffff) << 4)
                   | ((uint32_t)is_last_chunk << 3)
                   | (uint32_t)size_exponent;
    return avs_coap_msg_info_opt_u32(info, option_number, value);
}

int avs_coap_msg_info_opt_block(avs_coap_msg_info_t *info,
                                const avs_coap_block_info_t *block) {
    if (!block->valid) {
        LOG(ERROR, "could not add invalid BLOCK option");
        return -1;
    }

    return add_block_opt(info, avs_coap_opt_num_from_block_type(block->type),
                         block->seq_num, block->has_more, block->size);
}

int avs_coap_msg_info_opt_opaque(avs_coap_msg_info_t *info,
                                 uint16_t opt_number,
                                 const void *opt_data,
                                 uint16_t opt_data_size) {
    avs_coap_msg_info_opt_t *opt = (avs_coap_msg_info_opt_t*)
            AVS_LIST_NEW_BUFFER(sizeof(*opt) + opt_data_size);
    if (!opt) {
        LOG(ERROR, "out of memory");
        return -1;
    }

    opt->number = opt_number;
    opt->data_size = opt_data_size;
    memcpy(opt->data, opt_data, opt_data_size);

    avs_coap_msg_info_opt_t **insert_ptr = NULL;
    AVS_LIST_FOREACH_PTR(insert_ptr, &info->options_) {
        if ((*insert_ptr)->number > opt->number) {
            break;
        }
    }

    AVS_LIST_INSERT(insert_ptr, opt);
    return 0;
}

int avs_coap_msg_info_opt_string(avs_coap_msg_info_t *info,
                                 uint16_t opt_number,
                                 const char *opt_data) {
    size_t size = strlen(opt_data);
    if (size > UINT16_MAX) {
        return -1;
    }

    return avs_coap_msg_info_opt_opaque(info, opt_number, opt_data,
                                        (uint16_t) size);
}

int avs_coap_msg_info_opt_empty(avs_coap_msg_info_t *info,
                                uint16_t opt_number) {
    return avs_coap_msg_info_opt_opaque(info, opt_number, "", 0);
}

int avs_coap_msg_info_opt_uint(avs_coap_msg_info_t *info,
                               uint16_t opt_number,
                               const void *value,
                               size_t value_size) {
#ifdef AVS_COMMONS_BIG_ENDIAN
    const uint8_t *converted = (const uint8_t *) value;
#else
    uint8_t converted[value_size];
    for (size_t i = 0; i < value_size; ++i) {
        converted[value_size - 1 - i] = ((const uint8_t *) value)[i];
    }
#endif
    size_t start = 0;
    while (start < value_size && !converted[start]) {
        ++start;
    }
    return avs_coap_msg_info_opt_opaque(info, opt_number, &converted[start],
                                        (uint16_t)(value_size - start));
}
