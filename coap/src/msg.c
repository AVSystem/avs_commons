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

#include "log.h"
#include "msg_internal.h"

#include <avsystem/commons/coap/msg.h>
#include <avsystem/commons/coap/msg_opt.h>

#include <avsystem/commons/utils.h>

#include <string.h>
#include <stdio.h>
#include <assert.h>

#pragma GCC visibility push(hidden)

const char *avs_coap_msg_code_to_string(uint8_t code,
                                           char *buf,
                                           size_t buf_size) {
    static const struct {
        uint8_t code;
        const char *name;
    } CODE_NAMES[] = {
        { AVS_COAP_CODE_GET,                        "Get"                        },
        { AVS_COAP_CODE_POST,                       "Post"                       },
        { AVS_COAP_CODE_PUT,                        "Put"                        },
        { AVS_COAP_CODE_DELETE,                     "Delete"                     },

        { AVS_COAP_CODE_CREATED,                    "Created"                    },
        { AVS_COAP_CODE_DELETED,                    "Deleted"                    },
        { AVS_COAP_CODE_VALID,                      "Valid"                      },
        { AVS_COAP_CODE_CHANGED,                    "Changed"                    },
        { AVS_COAP_CODE_CONTENT,                    "Content"                    },
        { AVS_COAP_CODE_CONTINUE,                   "Continue"                   },

        { AVS_COAP_CODE_BAD_REQUEST,                "Bad Request"                },
        { AVS_COAP_CODE_UNAUTHORIZED,               "Unauthorized"               },
        { AVS_COAP_CODE_BAD_OPTION,                 "Bad Option"                 },
        { AVS_COAP_CODE_FORBIDDEN,                  "Forbidden"                  },
        { AVS_COAP_CODE_NOT_FOUND,                  "Not Found"                  },
        { AVS_COAP_CODE_METHOD_NOT_ALLOWED,         "Method Not Allowed"         },
        { AVS_COAP_CODE_NOT_ACCEPTABLE,             "Not Acceptable"             },
        { AVS_COAP_CODE_REQUEST_ENTITY_INCOMPLETE,  "Request Entity Incomplete"  },
        { AVS_COAP_CODE_PRECONDITION_FAILED,        "Precondition Failed"        },
        { AVS_COAP_CODE_REQUEST_ENTITY_TOO_LARGE,   "Entity Too Large"           },
        { AVS_COAP_CODE_UNSUPPORTED_CONTENT_FORMAT, "Unsupported Content Format" },

        { AVS_COAP_CODE_INTERNAL_SERVER_ERROR,      "Internal Server Error"      },
        { AVS_COAP_CODE_NOT_IMPLEMENTED,            "Not Implemented"            },
        { AVS_COAP_CODE_BAD_GATEWAY,                "Bad Gateway"                },
        { AVS_COAP_CODE_SERVICE_UNAVAILABLE,        "Service Unavailable"        },
        { AVS_COAP_CODE_GATEWAY_TIMEOUT,            "Gateway Timeout"            },
        { AVS_COAP_CODE_PROXYING_NOT_SUPPORTED,     "Proxying Not Supported"     },
    };

    const char *name = "unknown";
    for (size_t i = 0; i < AVS_ARRAY_SIZE(CODE_NAMES); ++i) {
        if (CODE_NAMES[i].code == code) {
            name = CODE_NAMES[i].name;
            break;
        }
    }

    if (avs_simple_snprintf(buf, buf_size, "%u.%02u %s",
                            avs_coap_msg_code_get_class(&code),
                            avs_coap_msg_code_get_detail(&code), name)
            < 0) {
        assert(0 && "buffer too small for CoAP msg code string");
        return "<error>";
    }

    return buf;
}

size_t avs_coap_msg_get_token(const avs_coap_msg_t *msg,
                                 avs_coap_token_t *out_token) {
    size_t token_length = avs_coap_msg_header_get_token_length(&msg->header);
    assert(token_length <= AVS_COAP_MAX_TOKEN_LENGTH);

    memcpy(out_token, msg->content, token_length);
    return token_length;
}

static const avs_coap_opt_t *get_first_opt(const avs_coap_msg_t *msg) {
    size_t token_length = avs_coap_msg_header_get_token_length(&msg->header);
    assert(token_length <= AVS_COAP_MAX_TOKEN_LENGTH);

    return (const avs_coap_opt_t *)(msg->content + token_length);
}

static bool is_payload_marker(const avs_coap_opt_t *ptr) {
    return *(const uint8_t *)ptr == AVS_COAP_PAYLOAD_MARKER;
}

avs_coap_opt_iterator_t avs_coap_opt_begin(const avs_coap_msg_t *msg) {
    avs_coap_opt_iterator_t optit = {
        .msg = msg,
        .curr_opt = get_first_opt(msg),
        .prev_opt_number = 0
    };

    return optit;
}

avs_coap_opt_iterator_t *
avs_coap_opt_next(avs_coap_opt_iterator_t *optit) {
    optit->prev_opt_number += avs_coap_opt_delta(optit->curr_opt);
    optit->curr_opt += avs_coap_opt_sizeof(optit->curr_opt);
    return optit;
}

bool avs_coap_opt_end(const avs_coap_opt_iterator_t *optit) {
    assert((const uint8_t *)optit->curr_opt >= optit->msg->content);

    size_t offset = (size_t)((const uint8_t *)optit->curr_opt
                             - (const uint8_t *)&optit->msg->header);

    assert(offset <= optit->msg->length);
    return offset >= optit->msg->length
           || is_payload_marker(optit->curr_opt);
}

uint32_t avs_coap_opt_number(const avs_coap_opt_iterator_t *optit) {
    return optit->prev_opt_number + avs_coap_opt_delta(optit->curr_opt);
}

static const uint8_t *coap_opt_find_end(const avs_coap_msg_t *msg) {
    avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
    while (!avs_coap_opt_end(&optit)) {
        avs_coap_opt_next(&optit);
    }
    return (const uint8_t *)optit.curr_opt;
}

const void *avs_coap_msg_payload(const avs_coap_msg_t *msg) {
    const uint8_t *end = coap_opt_find_end(msg);

    if (end < (const uint8_t*)&msg->header + msg->length
            && *end == AVS_COAP_PAYLOAD_MARKER) {
        return end + 1;
    } else {
        return end;
    }
}

size_t avs_coap_msg_payload_length(const avs_coap_msg_t *msg) {
    return (size_t)msg->length - (size_t)
           ((const uint8_t *)avs_coap_msg_payload(msg) - (const uint8_t *)&msg->header);
}

static bool is_header_valid(const avs_coap_msg_t *msg) {
    uint8_t version = _avs_coap_msg_header_get_version(&msg->header);
    if (version != 1) {
        LOG(DEBUG, "unsupported CoAP version: %u", version);
        return false;
    }

    uint8_t token_length = avs_coap_msg_header_get_token_length(&msg->header);
    if (token_length > AVS_COAP_MAX_TOKEN_LENGTH) {
        LOG(DEBUG, "token too long (%dB, expected 0 <= size <= %d)",
            token_length, AVS_COAP_MAX_TOKEN_LENGTH);
        return false;
    }

    if (sizeof(msg->header) + token_length > msg->length) {
        LOG(DEBUG, "missing/incomplete token (got %uB, expected %u)",
            msg->length - (uint32_t) sizeof(msg->header), token_length);
        return false;
    }

    return true;
}

static bool are_options_valid(const avs_coap_msg_t *msg) {
    size_t length_so_far = sizeof(msg->header)
            + avs_coap_msg_header_get_token_length(&msg->header);

    if (length_so_far == msg->length) {
        return true;
    }

    avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
    for (; length_so_far != msg->length && !avs_coap_opt_end(&optit);
            avs_coap_opt_next(&optit)) {
        if (!avs_coap_opt_is_valid(optit.curr_opt,
                                      msg->length - length_so_far)) {
            LOG(DEBUG, "option validation failed");
            return false;
        }

        length_so_far += avs_coap_opt_sizeof(optit.curr_opt);

        if (length_so_far > msg->length) {
            LOG(DEBUG,
                "invalid option length (ends %lu bytes after end of message)",
                (unsigned long) (length_so_far - msg->length));
            return false;
        }

        uint32_t opt_number = avs_coap_opt_number(&optit);
        if (opt_number > UINT16_MAX) {
            LOG(DEBUG, "invalid option number (%u)", opt_number);
            return false;
        }
    }

    if (length_so_far + 1 == msg->length
            && is_payload_marker(optit.curr_opt)) {
        // RFC 7252 3.1: The presence of a Payload Marker followed by a
        // zero-length payload MUST be processed as a message format error.
        LOG(DEBUG, "validation failed: payload marker at end of message");
        return false;
    }

    return true;
}

bool avs_coap_msg_is_valid(const avs_coap_msg_t *msg) {
    if (msg->length < AVS_COAP_MSG_MIN_SIZE) {
        LOG(DEBUG, "message too short (%uB, expected >= %u)", msg->length,
            AVS_COAP_MSG_MIN_SIZE);
        return false;
    }

    return is_header_valid(msg)
        && are_options_valid(msg)
        // [RFC 7272, 1.2]
        // Empty Message: A message with a Code of 0.00; neither a request nor
        // a response. An Empty message only contains the 4-byte header.
        && (msg->header.code != AVS_COAP_CODE_EMPTY
                || msg->length == AVS_COAP_MSG_MIN_SIZE);
}

static const char *msg_type_string(avs_coap_msg_type_t type) {
     static const char *TYPES[] = {
         "CONFIRMABLE",
         "NON_CONFIRMABLE",
         "ACKNOWLEDGEMENT",
         "RESET"
     };
     assert((unsigned)type < AVS_ARRAY_SIZE(TYPES));
     return TYPES[type];
}

void avs_coap_msg_debug_print(const avs_coap_msg_t *msg) {
    LOG(DEBUG, "sizeof(*msg) = %lu, sizeof(len) = %lu, sizeof(header) = %lu",
        (unsigned long) sizeof(*msg), (unsigned long) sizeof(msg->length),
        (unsigned long) sizeof(msg->header));
    LOG(DEBUG, "message (length = %u):", msg->length);
    LOG(DEBUG, "type: %u (%s)", avs_coap_msg_header_get_type(&msg->header),
        msg_type_string(avs_coap_msg_header_get_type(&msg->header)));

    LOG(DEBUG, "  version: %u",
        _avs_coap_msg_header_get_version(&msg->header));
    LOG(DEBUG, "  token_length: %u",
        avs_coap_msg_header_get_token_length(&msg->header));
    LOG(DEBUG, "  code: %s", AVS_COAP_CODE_STRING(msg->header.code));
    LOG(DEBUG, "  message_id: %u", avs_coap_msg_get_id(msg));
    LOG(DEBUG, "  content:");

    for (size_t i = 0; i < msg->length - sizeof(msg->header); i += 8) {
        LOG(DEBUG, "%02x", msg->content[i]);
    }

    LOG(DEBUG, "opts:");
    for (avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
            !avs_coap_opt_end(&optit);
            avs_coap_opt_next(&optit)) {
        avs_coap_opt_debug_print(optit.curr_opt);
    }
}

static void fill_block_summary(const avs_coap_msg_t *msg,
                               uint16_t block_opt_num,
                               char *buf,
                               size_t buf_size) {
    assert(block_opt_num == AVS_COAP_OPT_BLOCK1
           || block_opt_num == AVS_COAP_OPT_BLOCK2);

    const int num = block_opt_num == AVS_COAP_OPT_BLOCK1 ? 1 : 2;

    const avs_coap_opt_t *opt;
    if (avs_coap_msg_find_unique_opt(msg, block_opt_num, &opt)) {
        if (opt && avs_simple_snprintf(buf, buf_size,
                                       ", multiple BLOCK%d options", num) < 0) {
           assert(0 && "should never happen");
           *buf = '\0';
        }
        return;
    }

    uint32_t seq_num;
    bool has_more;
    uint16_t block_size;

    if (avs_coap_opt_block_seq_number(opt, &seq_num)
            || avs_coap_opt_block_has_more(opt, &has_more)) {
        if (avs_simple_snprintf(buf, buf_size, ", BLOCK%d (bad content)", num)
                < 0) {
            assert(0 && "should never happen");
            *buf = '\0';
        }
        return;
    }

    if (avs_coap_opt_block_size(opt, &block_size)) {
        if (avs_simple_snprintf(buf, buf_size, ", BLOCK%d (bad size)", num)
                < 0) {
            assert(0 && "should never happen");
            *buf = '\0';
        }
        return;
    }

    if (avs_simple_snprintf(buf, buf_size,
                            ", BLOCK%d (seq %u, size %u, more %d)", num,
                            seq_num, block_size, (int) has_more)
            < 0) {
        assert(0 && "should never happen");
        *buf = '\0';
    }
}

const char *avs_coap_msg_summary(const avs_coap_msg_t *msg,
                                    char *buf,
                                    size_t buf_size) {
    assert(avs_coap_msg_is_valid(msg));

    avs_coap_token_t token;
    size_t token_size = avs_coap_msg_get_token(msg, &token);
    char token_string[sizeof(token) * 2 + 1] = "";
    for (size_t i = 0; i < token_size; ++i) {
        snprintf(token_string + 2 * i, sizeof(token_string) - 2 * i,
                 "%02x", (uint8_t)token.bytes[i]);
    }

    char block1[64] = "";
    fill_block_summary(msg, AVS_COAP_OPT_BLOCK1, block1, sizeof(block1));

    char block2[64] = "";
    fill_block_summary(msg, AVS_COAP_OPT_BLOCK2, block2, sizeof(block2));

    if (avs_simple_snprintf(
             buf, buf_size, "%s, %s, id %u, token %s (%luB)%s%s",
             AVS_COAP_CODE_STRING(msg->header.code),
             msg_type_string(avs_coap_msg_header_get_type(&msg->header)),
             avs_coap_msg_get_id(msg),
             token_string, (unsigned long)token_size,
             block1, block2) < 0) {
        assert(0 && "should never happen");
        return "(cannot create summary)";
    }
    return buf;
}

uint8_t
avs_coap_msg_header_get_token_length(const avs_coap_msg_header_t *hdr) {
    int val = AVS_FIELD_GET(hdr->version_type_token_length,
                              AVS_COAP_HEADER_TOKEN_LENGTH_MASK,
                              AVS_COAP_HEADER_TOKEN_LENGTH_SHIFT);
    assert(val >= 0 && val <= AVS_COAP_HEADER_TOKEN_LENGTH_MASK);
    return (uint8_t)val;
}

#ifdef AVS_UNIT_TESTING
#include "test/msg.c"
#endif // AVS_UNIT_TESTING
