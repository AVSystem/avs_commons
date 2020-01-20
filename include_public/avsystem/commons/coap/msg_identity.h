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

#ifndef AVS_COMMONS_COAP_MSG_IDENTITY_H
#define AVS_COMMONS_COAP_MSG_IDENTITY_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum size, in bytes, of a CoAP token allowed by RFC7252. */
#define AVS_COAP_MAX_TOKEN_LENGTH 8

/** CoAP token object. */
typedef struct {
    uint8_t size;
    char bytes[AVS_COAP_MAX_TOKEN_LENGTH];
} avs_coap_token_t;

/** All-zeros CoAP token initializer. */
#define AVS_COAP_TOKEN_EMPTY ((avs_coap_token_t) { 0 })

/**
 * @returns true if @p first and @p second CoAP tokens are equal,
 *          false otherwise.
 */
static inline bool avs_coap_token_equal(const avs_coap_token_t *first,
                                        const avs_coap_token_t *second) {
    return first->size == second->size
           && !memcmp(first->bytes, second->bytes, first->size);
}

/** A struct combining CoAP message ID and its token. */
typedef struct avs_coap_msg_identity {
    uint16_t msg_id;
    avs_coap_token_t token;
} avs_coap_msg_identity_t;

/** All-zeros message identity initializer. */
#define AVS_COAP_MSG_IDENTITY_EMPTY ((avs_coap_msg_identity_t) { 0, { 0 } })

/**
 * @returns true if @p a and @p b message identities are equal, false otherwise.
 */
static inline bool avs_coap_identity_equal(const avs_coap_msg_identity_t *a,
                                           const avs_coap_msg_identity_t *b) {
    return a->msg_id == b->msg_id && avs_coap_token_equal(&a->token, &b->token);
}

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_MSG_IDENTITY_H
