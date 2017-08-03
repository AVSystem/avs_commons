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

#ifndef AVS_COMMONS_COAP_MSG_IDENTITY_H
#define AVS_COMMONS_COAP_MSG_IDENTITY_H

#ifdef __cplusplus
extern "C" {
#endif

#define AVS_COAP_MAX_TOKEN_LENGTH 8

typedef struct {
    char bytes[AVS_COAP_MAX_TOKEN_LENGTH];
} avs_coap_token_t;

#define AVS_COAP_TOKEN_EMPTY ((avs_coap_token_t){{0}})

static inline bool avs_coap_token_equal(const avs_coap_token_t *first,
                                           size_t first_size,
                                           const avs_coap_token_t *second,
                                           size_t second_size) {
    return first_size == second_size
        && !memcmp(first->bytes, second->bytes, first_size);
}

typedef struct avs_coap_msg_identity {
    uint16_t msg_id;
    avs_coap_token_t token;
    size_t token_size;
} avs_coap_msg_identity_t;

#define AVS_COAP_MSG_IDENTITY_EMPTY ((avs_coap_msg_identity_t){0,{{0}},0})

static inline
bool avs_coap_identity_equal(const avs_coap_msg_identity_t *a,
                                const avs_coap_msg_identity_t *b) {
    return a->msg_id == b->msg_id
        && a->token_size == b->token_size
        && !memcmp(&a->token, &b->token, a->token_size);
}

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_MSG_IDENTITY_H
