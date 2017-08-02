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

#ifndef AVS_COMMONS_COAP_BLOCK_UTILS_H
#define AVS_COMMONS_COAP_BLOCK_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include <avsystem/commons/coap/msg.h>


#define AVS_COAP_MSG_BLOCK_MIN_SIZE (1 << 4)
#define AVS_COAP_MSG_BLOCK_MAX_SIZE (1 << 10)

typedef enum {
    AVS_COAP_BLOCK1,
    AVS_COAP_BLOCK2
} avs_coap_block_type_t;

static inline uint16_t
avs_coap_opt_num_from_block_type(avs_coap_block_type_t type) {
    return type == AVS_COAP_BLOCK1 ? AVS_COAP_OPT_BLOCK1 : AVS_COAP_OPT_BLOCK2;
}

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
 */
int avs_coap_get_block_info(const avs_coap_msg_t *msg,
                               avs_coap_block_type_t type,
                               avs_coap_block_info_t *out_info);

bool avs_coap_is_valid_block_size(uint16_t size);


#endif // AVS_COMMONS_COAP_BLOCK_UTILS_H
