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

#include "../msg_internal.h"

#define PAYLOAD_MARKER "\xFF"

static inline void setup_msg(avs_coap_msg_t *msg,
                             const uint8_t *content,
                             size_t content_length) {
    memset(msg, 0, sizeof(*msg) + content_length);

    _avs_coap_header_set_version(msg, 1);
    _avs_coap_header_set_type(msg, AVS_COAP_MSG_ACKNOWLEDGEMENT);
    _avs_coap_header_set_token_length(msg, 0);
    _avs_coap_header_set_code(msg, AVS_COAP_CODE(3, 4));
    _avs_coap_header_set_id(msg, 0x0506);

    assert(content || content_length == 0);
    if (content_length) {
        memcpy(msg->content + _avs_coap_header_size(msg),
               content, content_length);
    }
    msg->length = (uint32_t)(_avs_coap_header_size(msg) + content_length);
}

static void free_msg(avs_coap_msg_t **msg) {
    avs_free(*msg);
}

static inline void free_msg_array(avs_coap_msg_t *(*arr)[]) {
    for (size_t i = 0; (*arr)[i]; ++i) {
        avs_free((*arr)[i]);
    }
}
