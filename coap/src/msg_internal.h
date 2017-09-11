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

#include "parse_utils.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

/** Serialized CoAP message header. For internal use only. */
typedef struct coap_header {
    uint8_t version_type_token_length;
    uint8_t code;
    uint8_t message_id[2];
} coap_header_t;

AVS_STATIC_ASSERT(AVS_ALIGNOF(coap_header_t) == 1,
                  coap_header_must_always_be_properly_aligned_t);

/** @{
 * Sanity checks that ensure no padding is inserted anywhere inside
 * @ref coap_header_t .
 */
AVS_STATIC_ASSERT(offsetof(coap_header_t, version_type_token_length) == 0,
                  vttl_field_is_at_start_of_coap_header_t);
AVS_STATIC_ASSERT(offsetof(coap_header_t, code) == 1,
                  no_padding_before_code_field_of_coap_header_t);
AVS_STATIC_ASSERT(offsetof(coap_header_t, message_id) == 2,
                  no_padding_before_message_id_field_of_coap_header_t);
AVS_STATIC_ASSERT(sizeof(coap_header_t) == 4,
                  no_padding_in_coap_header_t);
/** @} */

static inline size_t _avs_coap_header_size(const avs_coap_msg_t *msg) {
    (void) msg;
    return sizeof(coap_header_t);
}

static inline const uint8_t *
_avs_coap_header_end_const(const avs_coap_msg_t *msg) {
    return msg->content + _avs_coap_header_size(msg);
}

static inline uint8_t *_avs_coap_header_end(avs_coap_msg_t *msg) {
    return msg->content + _avs_coap_header_size(msg);
}

#define AVS_COAP_HEADER_VERSION_MASK 0xC0
#define AVS_COAP_HEADER_VERSION_SHIFT 6

static inline uint8_t
_avs_coap_header_get_version(const avs_coap_msg_t *msg) {
    const coap_header_t *hdr = (const coap_header_t *) msg->content;
    int val = AVS_FIELD_GET(hdr->version_type_token_length,
                            AVS_COAP_HEADER_VERSION_MASK,
                            AVS_COAP_HEADER_VERSION_SHIFT);
    assert(val >= 0 && val <= 3);
    return (uint8_t)val;
}

static inline void _avs_coap_header_set_version(avs_coap_msg_t *msg,
                                                uint8_t version) {
    assert(version <= 3);
    coap_header_t *hdr = (coap_header_t *) msg->content;
    AVS_FIELD_SET(hdr->version_type_token_length,
                  AVS_COAP_HEADER_VERSION_MASK,
                  AVS_COAP_HEADER_VERSION_SHIFT, version);
}

#define AVS_COAP_HEADER_TOKEN_LENGTH_MASK 0x0F
#define AVS_COAP_HEADER_TOKEN_LENGTH_SHIFT 0

static inline uint8_t
_avs_coap_header_get_token_length(const avs_coap_msg_t *msg) {
    const coap_header_t *hdr = (const coap_header_t *) msg->content;
    int val = AVS_FIELD_GET(hdr->version_type_token_length,
                            AVS_COAP_HEADER_TOKEN_LENGTH_MASK,
                            AVS_COAP_HEADER_TOKEN_LENGTH_SHIFT);
    assert(val >= 0 && val <= AVS_COAP_HEADER_TOKEN_LENGTH_MASK);
    return (uint8_t)val;
}

static inline void
_avs_coap_header_set_token_length(avs_coap_msg_t *msg,
                                  uint8_t token_length) {
    assert(token_length <= AVS_COAP_MAX_TOKEN_LENGTH);
    coap_header_t *hdr = (coap_header_t *) msg->content;
    AVS_FIELD_SET(hdr->version_type_token_length,
                  AVS_COAP_HEADER_TOKEN_LENGTH_MASK,
                  AVS_COAP_HEADER_TOKEN_LENGTH_SHIFT, token_length);
}

/** @{
 * Internal macros used for retrieving CoAP message type from
 * @ref coap_msg_header_t .
 */
#define AVS_COAP_HEADER_TYPE_MASK 0x30
#define AVS_COAP_HEADER_TYPE_SHIFT 4
/** @} */

static inline avs_coap_msg_type_t
_avs_coap_header_get_type(const avs_coap_msg_t *msg) {
    const coap_header_t *hdr = (const coap_header_t *) msg->content;
    int val = AVS_FIELD_GET(hdr->version_type_token_length,
                            AVS_COAP_HEADER_TYPE_MASK,
                            AVS_COAP_HEADER_TYPE_SHIFT);
    assert(val >= _AVS_COAP_MSG_FIRST && val <= _AVS_COAP_MSG_LAST);
    return (avs_coap_msg_type_t)val;
}

static inline void _avs_coap_header_set_type(avs_coap_msg_t *msg,
                                             avs_coap_msg_type_t type) {
    coap_header_t *hdr = (coap_header_t *) msg->content;
    AVS_FIELD_SET(hdr->version_type_token_length,
                  AVS_COAP_HEADER_TYPE_MASK,
                  AVS_COAP_HEADER_TYPE_SHIFT, type);
}

static inline uint8_t _avs_coap_header_get_code(const avs_coap_msg_t *msg) {
    return ((const coap_header_t *) msg->content)->code;
}

static inline void _avs_coap_header_set_code(avs_coap_msg_t *msg,
                                             uint8_t code) {
    ((coap_header_t *) msg->content)->code = code;
}

static inline uint16_t _avs_coap_header_get_id(const avs_coap_msg_t *msg) {
    return extract_u16(((const coap_header_t *) msg->content)->message_id);
}

static inline void _avs_coap_header_set_id(avs_coap_msg_t *msg,
                                           uint16_t msg_id) {
    uint16_t msg_id_nbo = htons(msg_id);
    memcpy(((coap_header_t *) msg->content)->message_id,
           &msg_id_nbo, sizeof(msg_id_nbo));
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

VISIBILITY_PRIVATE_HEADER_END

#endif // AVS_COAP_MSG_INTERNAL_H
