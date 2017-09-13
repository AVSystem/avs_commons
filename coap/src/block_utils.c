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

#include <config.h>

#include <avsystem/commons/coap/block_utils.h>
#include <avsystem/commons/coap/msg_opt.h>
// For avs_is_power_of_2
#include <avsystem/commons/utils.h>

#include "log.h"

VISIBILITY_SOURCE_BEGIN

int avs_coap_get_block_info(const avs_coap_msg_t *msg,
                            avs_coap_block_type_t type,
                            avs_coap_block_info_t *out_info) {
    assert(msg);
    assert(out_info);
    uint16_t opt_number = type == AVS_COAP_BLOCK1
            ? AVS_COAP_OPT_BLOCK1
            : AVS_COAP_OPT_BLOCK2;
    const avs_coap_opt_t *opt;
    memset(out_info, 0, sizeof(*out_info));
    if (avs_coap_msg_find_unique_opt(msg, opt_number, &opt)) {
        if (opt) {
            int num = opt_number == AVS_COAP_OPT_BLOCK1 ? 1 : 2;
            LOG(ERROR, "multiple BLOCK%d options found", num);
            return -1;
        }
        return 0;
    }
    out_info->type = type;
    out_info->valid = !avs_coap_opt_block_seq_number(opt, &out_info->seq_num)
            && !avs_coap_opt_block_has_more(opt, &out_info->has_more)
            && !avs_coap_opt_block_size(opt, &out_info->size);

    return out_info->valid ? 0 : -1;
}

bool avs_coap_is_valid_block_size(uint16_t size) {
    return avs_is_power_of_2(size)
            && size <= AVS_COAP_MSG_BLOCK_MAX_SIZE
            && size >= AVS_COAP_MSG_BLOCK_MIN_SIZE;
}
