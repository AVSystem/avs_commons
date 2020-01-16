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

#ifndef AVS_COMMONS_COAP_BLOCK_UTILS_H
#define AVS_COMMONS_COAP_BLOCK_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include <avsystem/commons/coap/msg.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Minimum size, in bytes, of a CoAP BLOCK message payload. */
#define AVS_COAP_MSG_BLOCK_MIN_SIZE (1 << 4)
/** Maximum size, in bytes, of a CoAP BLOCK message payload. */
#define AVS_COAP_MSG_BLOCK_MAX_SIZE (1 << 10)
/** Maximum value of a BLOCK sequence number (2^20-1) allowed by RFC7959. */
#define AVS_COAP_BLOCK_MAX_SEQ_NUMBER 0xFFFFF

/**
 * Helper enum used to distinguish BLOCK1 and BLOCK2 transfers in BLOCK APIs.
 */
typedef enum { AVS_COAP_BLOCK1, AVS_COAP_BLOCK2 } avs_coap_block_type_t;

/**
 * @returns CoAP option number appropriate for BLOCK transfer of given @p type .
 */
static inline uint16_t
avs_coap_opt_num_from_block_type(avs_coap_block_type_t type) {
    return type == AVS_COAP_BLOCK1 ? AVS_COAP_OPT_BLOCK1 : AVS_COAP_OPT_BLOCK2;
}

/**
 * Parsed CoAP BLOCK option.
 */
typedef struct coap_block_info {
    avs_coap_block_type_t type;
    bool valid;
    uint32_t seq_num;
    bool has_more;
    uint16_t size;
} avs_coap_block_info_t;

/**
 * Attempts to obtain block info of given block @p type. Possible return values
 * along with @p out_info->valid values are shown in the table below.
 *
 * +-----------------------+----------------+-----------------+
 * |        Option         |  Return value  | out_info->valid |
 * +-----------------------+----------------+-----------------+
 * |   Present and valid   |       0        |      true       |
 * +-----------------------+----------------+-----------------+
 * | Present and malformed |      -1        |      false      |
 * +-----------------------+----------------+-----------------+
 * |        Doubled        |      -1        |      false      |
 * +-----------------------+----------------+-----------------+
 * |      Not present      |       0        |      false      |
 * +-----------------------+----------------+-----------------+
 *
 * @param[in]  msg      CoAP message to look for BLOCK option in.
 * @param[in]  type     Type of the BLOCK option to retrieve
 *                      (@ref avs_coap_block_type_t)
 * @param[out] out_info @ref avs_coap_block_info_t struct to store parsed
 *                      BLOCK option in.
 *
 * @returns @li 0 if the BLOCK option was successfully retrieved or was not
 *              present,
 *          @li -1 in case of error.
 *          See table above for details.
 */
int avs_coap_get_block_info(const avs_coap_msg_t *msg,
                            avs_coap_block_type_t type,
                            avs_coap_block_info_t *out_info);

/**
 * @returns true if @p size is an acceptable CoAP BLOCK size (i.e. power of 2
 *          between @ref AVS_COAP_MSG_BLOCK_MIN_SIZE and @ref
 *          AVS_COAP_MSG_BLOCK_MAX_SIZE , inclusive)
 */
bool avs_coap_is_valid_block_size(uint16_t size);

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_BLOCK_UTILS_H
