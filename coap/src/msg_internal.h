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

#ifndef AVS_COAP_MSG_INTERNAL_H
#define AVS_COAP_MSG_INTERNAL_H

#include <avsystem/commons/coap/msg.h>

#pragma GCC visibility push(hidden)

#define AVS_COAP_HEADER_VERSION_MASK 0xC0
#define AVS_COAP_HEADER_VERSION_SHIFT 6
#define AVS_COAP_HEADER_TOKEN_LENGTH_MASK 0x0F
#define AVS_COAP_HEADER_TOKEN_LENGTH_SHIFT 0

static inline uint8_t
_avs_coap_msg_header_get_version(const avs_coap_msg_header_t *hdr) {
    int val = AVS_FIELD_GET(hdr->version_type_token_length,
                              AVS_COAP_HEADER_VERSION_MASK,
                              AVS_COAP_HEADER_VERSION_SHIFT);
    assert(val >= 0 && val <= 3);
    return (uint8_t)val;
}
static inline void
_avs_coap_msg_header_set_version(avs_coap_msg_header_t *hdr,
                                   uint8_t version) {
    assert(version <= 3);
    AVS_FIELD_SET(hdr->version_type_token_length,
                    AVS_COAP_HEADER_VERSION_MASK,
                    AVS_COAP_HEADER_VERSION_SHIFT, version);
}

static inline void
_avs_coap_msg_header_set_token_length(avs_coap_msg_header_t *hdr,
                                        uint8_t token_length) {
    assert(token_length <= AVS_COAP_MAX_TOKEN_LENGTH);
    AVS_FIELD_SET(hdr->version_type_token_length,
                    AVS_COAP_HEADER_TOKEN_LENGTH_MASK,
                    AVS_COAP_HEADER_TOKEN_LENGTH_SHIFT, token_length);
}

#define AVS_COAP_OPT_DELTA_MASK 0xF0
#define AVS_COAP_OPT_DELTA_SHIFT 4
#define AVS_COAP_OPT_LENGTH_MASK 0x0F
#define AVS_COAP_OPT_LENGTH_SHIFT 0

static inline uint8_t _avs_coap_opt_get_short_delta(const avs_coap_opt_t *opt) {
    return AVS_FIELD_GET(opt->delta_length,
                           AVS_COAP_OPT_DELTA_MASK,
                           AVS_COAP_OPT_DELTA_SHIFT);
}

static inline void _avs_coap_opt_set_short_delta(avs_coap_opt_t *opt,
                                                   uint8_t delta) {
    assert(delta <= AVS_COAP_EXT_RESERVED);
    AVS_FIELD_SET(opt->delta_length,
                    AVS_COAP_OPT_DELTA_MASK,
                    AVS_COAP_OPT_DELTA_SHIFT, delta);
}

static inline uint8_t _avs_coap_opt_get_short_length(const avs_coap_opt_t *opt) {
    return AVS_FIELD_GET(opt->delta_length,
                           AVS_COAP_OPT_LENGTH_MASK,
                           AVS_COAP_OPT_LENGTH_SHIFT);
}

static inline void _avs_coap_opt_set_short_length(avs_coap_opt_t *opt,
                                                    uint8_t length) {
    assert(length <= AVS_COAP_EXT_RESERVED);
    AVS_FIELD_SET(opt->delta_length,
                    AVS_COAP_OPT_LENGTH_MASK,
                    AVS_COAP_OPT_LENGTH_SHIFT, length);
}

static inline size_t _avs_coap_get_opt_header_size(uint16_t opt_number_delta,
                                                     uint16_t opt_data_size) {
    size_t header_size = 1;

    if (opt_number_delta >= AVS_COAP_EXT_U16_BASE) {
        header_size += 2;
    } else if (opt_number_delta >= AVS_COAP_EXT_U8_BASE) {
        header_size += 1;
    }

    if (opt_data_size >= AVS_COAP_EXT_U16_BASE) {
        header_size += 2;
    } else if (opt_data_size >= AVS_COAP_EXT_U8_BASE) {
        header_size += 1;
    }

    return header_size;
}

struct avs_coap_msg_info_opt {
    uint16_t number;
    uint16_t data_size;
    uint8_t data[];
};

#pragma GCC visibility pop

#endif // AVS_COAP_MSG_INTERNAL_H