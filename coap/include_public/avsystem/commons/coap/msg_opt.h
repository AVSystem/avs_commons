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

#ifndef AVS_COMMONS_COAP_MSG_OPT_H
#define AVS_COMMONS_COAP_MSG_OPT_H

#include <avsystem/commons/coap/msg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVS_COAP_OPTION_MISSING 1

typedef bool avs_coap_critical_option_validator_t(uint8_t msg_code,
                                                           uint32_t optnum);

int avs_coap_msg_find_unique_opt(const avs_coap_msg_t *msg,
                                    uint16_t opt_number,
                                    const avs_coap_opt_t **out_opt);

int avs_coap_msg_get_option_uint(const avs_coap_msg_t *msg,
                                    uint16_t option_number,
                                    void *out_fmt,
                                    size_t out_fmt_size);

static inline int avs_coap_msg_get_option_u16(const avs_coap_msg_t *msg,
                                                 uint16_t option_number,
                                                 uint16_t *out_value) {
    return avs_coap_msg_get_option_uint(msg, option_number,
                                           out_value, sizeof(*out_value));
}

static inline int avs_coap_msg_get_option_u32(const avs_coap_msg_t *msg,
                                                 uint16_t option_number,
                                                 uint32_t *out_value) {
    return avs_coap_msg_get_option_uint(msg, option_number,
                                           out_value, sizeof(*out_value));
}

int avs_coap_msg_get_option_string_it(const avs_coap_msg_t *msg,
                                         uint16_t option_number,
                                         avs_coap_opt_iterator_t *it,
                                         size_t *out_bytes_read,
                                         char *buffer,
                                         size_t buffer_size);

int avs_coap_msg_get_content_format(const avs_coap_msg_t *msg,
                                       uint16_t *out_value);

int avs_coap_msg_validate_critical_options(
        const avs_coap_msg_t *msg,
        avs_coap_critical_option_validator_t validator);

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_MSG_OPT_H
