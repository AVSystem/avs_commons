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

#include <avs_commons_config.h>

#include "coap_log.h"
#include "msg_internal.h"

#include <avsystem/commons/coap/msg_info.h>
#include <avsystem/commons/coap/msg_opt.h>

#include <inttypes.h>

VISIBILITY_SOURCE_BEGIN

int avs_coap_msg_find_unique_opt(const avs_coap_msg_t *msg,
                                 uint16_t opt_number,
                                 const avs_coap_opt_t **out_opt) {
    *out_opt = NULL;

    for (avs_coap_opt_iterator_t it = avs_coap_opt_begin(msg);
         !avs_coap_opt_end(&it);
         avs_coap_opt_next(&it)) {
        uint32_t curr_opt_number = avs_coap_opt_number(&it);

        if (curr_opt_number == opt_number) {
            if (*out_opt) {
                // multiple options with such opt_number
                return -1;
            }

            *out_opt = it.curr_opt;
        } else if (curr_opt_number > opt_number) {
            break;
        }
    }

    return *out_opt ? 0 : -1;
}

int avs_coap_msg_get_option_u16(const avs_coap_msg_t *msg,
                                uint16_t option_number,
                                uint16_t *out_value) {
    const avs_coap_opt_t *opt;
    if (avs_coap_msg_find_unique_opt(msg, option_number, &opt)) {
        if (opt) {
            LOG(DEBUG, _("multiple instances of option ") "%d" _(" found"),
                option_number);
            return -1;
        } else {
            LOG(TRACE, _("option ") "%d" _(" not found"), option_number);
            return AVS_COAP_OPTION_MISSING;
        }
    }
    return avs_coap_opt_u16_value(opt, out_value);
}

int avs_coap_msg_get_option_u32(const avs_coap_msg_t *msg,
                                uint16_t option_number,
                                uint32_t *out_value) {
    const avs_coap_opt_t *opt;
    if (avs_coap_msg_find_unique_opt(msg, option_number, &opt)) {
        if (opt) {
            LOG(DEBUG, _("multiple instances of option ") "%d" _(" found"),
                option_number);
            return -1;
        } else {
            LOG(TRACE, _("option ") "%d" _(" not found"), option_number);
            return AVS_COAP_OPTION_MISSING;
        }
    }
    return avs_coap_opt_u32_value(opt, out_value);
}

int avs_coap_msg_get_option_string_it(const avs_coap_msg_t *msg,
                                      uint16_t option_number,
                                      avs_coap_opt_iterator_t *it,
                                      size_t *out_bytes_read,
                                      char *buffer,
                                      size_t buffer_size) {
    if (!it->msg) {
        avs_coap_opt_iterator_t begin = avs_coap_opt_begin(msg);
        memcpy(it, &begin, sizeof(*it));
    } else {
        assert(it->msg == msg);
        avs_coap_opt_next(it);
    }

    for (; !avs_coap_opt_end(it); avs_coap_opt_next(it)) {
        if (avs_coap_opt_number(it) == option_number) {
            return avs_coap_opt_string_value(it->curr_opt, out_bytes_read,
                                             buffer, buffer_size);
        }
    }

    return AVS_COAP_OPTION_MISSING;
}

int avs_coap_msg_get_content_format(const avs_coap_msg_t *msg,
                                    uint16_t *out_value) {
    int result = avs_coap_msg_get_option_u16(msg, AVS_COAP_OPT_CONTENT_FORMAT,
                                             out_value);

    if (result == AVS_COAP_OPTION_MISSING) {
        *out_value = AVS_COAP_FORMAT_NONE;
        return 0;
    }

    return result;
}

static bool is_opt_critical(uint32_t opt_number) {
    return opt_number % 2;
}

static bool
is_critical_opt_valid(uint8_t msg_code,
                      uint32_t opt_number,
                      avs_coap_critical_option_validator_t fallback_validator) {
    switch (opt_number) {
    case AVS_COAP_OPT_BLOCK1:
        return msg_code == AVS_COAP_CODE_PUT || msg_code == AVS_COAP_CODE_POST
               || msg_code == AVS_COAP_CODE_FETCH
               || msg_code == AVS_COAP_CODE_IPATCH;
    case AVS_COAP_OPT_BLOCK2:
        return msg_code == AVS_COAP_CODE_GET || msg_code == AVS_COAP_CODE_PUT
               || msg_code == AVS_COAP_CODE_POST
               || msg_code == AVS_COAP_CODE_FETCH
               || msg_code == AVS_COAP_CODE_IPATCH;
    default:
        return fallback_validator(msg_code, opt_number);
    }
}

int avs_coap_msg_validate_critical_options(
        const avs_coap_msg_t *msg,
        avs_coap_critical_option_validator_t validator) {
    int result = 0;
    uint8_t code = _avs_coap_header_get_code(msg);

    for (avs_coap_opt_iterator_t it = avs_coap_opt_begin(msg);
         !avs_coap_opt_end(&it);
         avs_coap_opt_next(&it)) {
        if (is_opt_critical(avs_coap_opt_number(&it))) {
            uint32_t opt_number = avs_coap_opt_number(&it);

            if (!is_critical_opt_valid(code, opt_number, validator)) {
                LOG(DEBUG,
                    _("warning: invalid critical option in query ") "%s" _(
                            ": ") "%" PRIu32,
                    AVS_COAP_CODE_STRING(avs_coap_msg_get_code(it.msg)),
                    opt_number);
                result = -1;
            }
        }
    }

    return result;
}
