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

#include <avs_commons_config.h>

#include <avsystem/commons/memory.h>
#include <avsystem/commons/unit/test.h>

#include "utils.h"

AVS_UNIT_TEST(coap_msg, header_memory_layout) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + AVS_COAP_MSG_MIN_SIZE);

    _avs_coap_header_set_version(msg, 1);
    _avs_coap_header_set_type(msg, AVS_COAP_MSG_ACKNOWLEDGEMENT);
    _avs_coap_header_set_token_length(msg, 0);
    _avs_coap_header_set_code(msg, AVS_COAP_CODE(3, 4));
    // direct memcpy to avoid endianness problems
    memcpy(((coap_header_t *)msg->content)->message_id, "\x05\x06", 2);
    msg->length = (uint32_t) _avs_coap_header_size(msg);

    //      version
    //      |  type
    //      |  |  token length
    //      v  v  v     .- code .  .-- message id --.
    //      01 10 0000  011 00100  00000101  00000110
    // hex:     6    0      6   4     0   5     0   6
    AVS_UNIT_ASSERT_EQUAL_BYTES(msg->content, "\x60\x64\x05\x06");

    _avs_coap_header_set_version(msg, 3);
    _avs_coap_header_set_type(msg, AVS_COAP_MSG_RESET);
    _avs_coap_header_set_token_length(msg, 7);
    _avs_coap_header_set_code(msg, AVS_COAP_CODE(7, 31));
    _avs_coap_header_set_id(msg, 0xffff);
    msg->length = (uint32_t) _avs_coap_header_size(msg);

    //      version
    //      |  type
    //      |  |  token length
    //      v  v  v     .- code .  .-- message id --.
    //      11 11 0111  111 11111  11111111  11111111
    // hex:     f    7      f   f     f   f     f   f
    AVS_UNIT_ASSERT_EQUAL_BYTES(msg->content, "\xf7\xff\xff\xff");
}

AVS_UNIT_TEST(coap_msg, header_fields) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg));
    setup_msg(msg, NULL, 0);

    AVS_UNIT_ASSERT_EQUAL(_avs_coap_header_get_version(msg), 1);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_msg_get_type(msg), AVS_COAP_MSG_ACKNOWLEDGEMENT);
    AVS_UNIT_ASSERT_EQUAL(_avs_coap_header_get_token_length(msg), 0);

    uint8_t code = avs_coap_msg_get_code(msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_msg_code_get_class(code), 3);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_msg_code_get_detail(code), 4);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_msg_get_id(msg), 0x0506);
}

AVS_UNIT_TEST(coap_msg, no_payload) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg));
    setup_msg(msg, NULL, 0);

    AVS_UNIT_ASSERT_NOT_NULL(avs_coap_msg_payload(msg));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_msg_payload_length(msg), 0);
}

AVS_UNIT_TEST(coap_msg, payload) {
    uint8_t content[] = PAYLOAD_MARKER "http://www.staggeringbeauty.com/";
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content) - 1);
    setup_msg(msg, content, sizeof(content) - 1);

    AVS_UNIT_ASSERT_NOT_NULL(avs_coap_msg_payload(msg));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_msg_payload_length(msg), sizeof(content) - 2);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(avs_coap_msg_payload(msg), content + 1, sizeof(content) - 2);
}

static size_t count_opts(const avs_coap_msg_t *msg) {
    size_t num_opts = 0;

    for (avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
            !avs_coap_opt_end(&optit);
            avs_coap_opt_next(&optit)) {
        ++num_opts;
    }

    return num_opts;
}

AVS_UNIT_TEST(coap_msg, options) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    uint8_t content[] = {
        [0]  = 0x00,                                                  // empty option
        [1]  = 0x10,                                                  // delta = 1
        [2]  = 0xD0, [3]         = 0x00,                              // extended delta (1b)
        [4]  = 0xE0, [5 ... 6]   = 0x00,                              // extended delta (2b)
        [7]  = 0x01, [8]         = 0x00,                              // length = 1
        [9]  = 0x0D, [10]        = 0x00, [11 ... 11+13-1]     = 0x00, // extended length (1b)
        [24] = 0x0E, [25 ... 26] = 0x00, [27 ... 27+13+256-1] = 0x00  // extended length (2b)
    };
#pragma GCC diagnostic pop

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content));
    setup_msg(msg, content, sizeof(content));

    avs_coap_opt_iterator_t it = avs_coap_opt_begin(msg);
    size_t expected_opt_number = 0;
    const uint8_t *expected_opt_ptr = _avs_coap_header_end_const(msg);

    AVS_UNIT_ASSERT_FALSE(avs_coap_opt_end(&it));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&it), expected_opt_number);
    AVS_UNIT_ASSERT_TRUE((const uint8_t*)it.curr_opt == expected_opt_ptr);
    expected_opt_ptr += 1;

    expected_opt_number += 1;
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_next(&it) == &it);
    AVS_UNIT_ASSERT_FALSE(avs_coap_opt_end(&it));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&it), expected_opt_number);
    AVS_UNIT_ASSERT_TRUE((const uint8_t*)it.curr_opt == expected_opt_ptr);
    expected_opt_ptr += 1;

    expected_opt_number += 13;
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_next(&it) == &it);
    AVS_UNIT_ASSERT_FALSE(avs_coap_opt_end(&it));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&it), expected_opt_number);
    AVS_UNIT_ASSERT_TRUE((const uint8_t*)it.curr_opt == expected_opt_ptr);
    expected_opt_ptr += 2;

    expected_opt_number += 13+256;
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_next(&it) == &it);
    AVS_UNIT_ASSERT_FALSE(avs_coap_opt_end(&it));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&it), expected_opt_number);
    AVS_UNIT_ASSERT_TRUE((const uint8_t*)it.curr_opt == expected_opt_ptr);
    expected_opt_ptr += 3;

    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_next(&it) == &it);
    AVS_UNIT_ASSERT_FALSE(avs_coap_opt_end(&it));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&it), expected_opt_number);
    AVS_UNIT_ASSERT_TRUE((const uint8_t*)it.curr_opt == expected_opt_ptr);
    expected_opt_ptr += 1+1;

    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_next(&it) == &it);
    AVS_UNIT_ASSERT_FALSE(avs_coap_opt_end(&it));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&it), expected_opt_number);
    AVS_UNIT_ASSERT_TRUE((const uint8_t*)it.curr_opt == expected_opt_ptr);
    expected_opt_ptr += 1+1+13;

    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_next(&it) == &it);
    AVS_UNIT_ASSERT_FALSE(avs_coap_opt_end(&it));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&it), expected_opt_number);
    AVS_UNIT_ASSERT_TRUE((const uint8_t*)it.curr_opt == expected_opt_ptr);
    expected_opt_ptr += 1+2+13+256;

    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_next(&it) == &it);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_end(&it));
}

AVS_UNIT_TEST(coap_msg, validate_valid) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg));
    setup_msg(msg, NULL, 0);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 0);
}

AVS_UNIT_TEST(coap_msg, validate_empty) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg));
    setup_msg(msg, NULL, 0);
    _avs_coap_header_set_code(msg, AVS_COAP_CODE_EMPTY);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
}

AVS_UNIT_TEST(coap_msg, validate_empty_with_token) {
    uint8_t content[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content));
    setup_msg(msg, content, sizeof(content));
    _avs_coap_header_set_code(msg, AVS_COAP_CODE_EMPTY);
    _avs_coap_header_set_token_length(msg, sizeof(content));

    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
}

AVS_UNIT_TEST(coap_msg, validate_empty_with_payload) {
    uint8_t content[] = PAYLOAD_MARKER "http://doger.io";
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content) - 1);
    setup_msg(msg, content, sizeof(content) - 1);
    _avs_coap_header_set_code(msg, AVS_COAP_CODE_EMPTY);

    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
}

AVS_UNIT_TEST(coap_msg, validate_unrecognized_version) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg));
    setup_msg(msg, NULL, 0);

    _avs_coap_header_set_version(msg, 0);
    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 0);

    _avs_coap_header_set_version(msg, 2);
    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 0);

    _avs_coap_header_set_version(msg, 3);
    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 0);
}

AVS_UNIT_TEST(coap_msg, validate_with_token) {
    uint8_t content[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content));
    setup_msg(msg, content, sizeof(content));

    _avs_coap_header_set_token_length(msg, sizeof(content));

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 0);
}

AVS_UNIT_TEST(coap_msg, validate_invalid_token_length) {
    uint8_t content[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content));
    setup_msg(msg, content, sizeof(content));

    // _avs_coap_header_set_token_length doesn't allow setting an invalid
    // token length; we need to set the value directly
    AVS_FIELD_SET(msg->content[0],
                  AVS_COAP_HEADER_TOKEN_LENGTH_MASK,
                  AVS_COAP_HEADER_TOKEN_LENGTH_SHIFT, sizeof(content));

    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
}

AVS_UNIT_TEST(coap_msg, validate_opt_length_overflow) {
    uint8_t opts[] = "\xe0\xff\xff";

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(opts) - 1);
    setup_msg(msg, opts, sizeof(opts) - 1);

    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
}

AVS_UNIT_TEST(coap_msg, validate_null_opt) {
    uint8_t opts[] = "\x00";

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(opts) - 1);
    setup_msg(msg, opts, sizeof(opts) - 1);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 1);

    avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
    AVS_UNIT_ASSERT_TRUE(optit.msg == msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&optit), 0);
    AVS_UNIT_ASSERT_NOT_NULL(optit.curr_opt);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_delta(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_content_length(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_value(optit.curr_opt) == (const uint8_t*)optit.curr_opt + 1);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_sizeof(optit.curr_opt), 1);

    avs_coap_opt_next(&optit);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_end(&optit));
}

AVS_UNIT_TEST(coap_msg, validate_opt_ext_delta_byte) {
    uint8_t opts[] = "\xd0\x01";

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(opts) - 1);
    setup_msg(msg, opts, sizeof(opts) - 1);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 1);

    avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
    AVS_UNIT_ASSERT_TRUE(optit.msg == msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&optit), 1 + AVS_COAP_EXT_U8_BASE);
    AVS_UNIT_ASSERT_NOT_NULL(optit.curr_opt);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_delta(optit.curr_opt), 1 + AVS_COAP_EXT_U8_BASE);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_content_length(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_value(optit.curr_opt) == (const uint8_t*)optit.curr_opt + 2);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_sizeof(optit.curr_opt), 1 + 1);

    avs_coap_opt_next(&optit);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_end(&optit));
}

AVS_UNIT_TEST(coap_msg, validate_opt_ext_delta_short) {
    uint8_t opts[] = "\xe0\x01\x00";

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(opts) - 1);
    setup_msg(msg, opts, sizeof(opts) - 1);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 1);

    avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
    AVS_UNIT_ASSERT_TRUE(optit.msg == msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&optit), 256 + 269);
    AVS_UNIT_ASSERT_NOT_NULL(optit.curr_opt);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_delta(optit.curr_opt), 256 + 269);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_content_length(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_value(optit.curr_opt) == (const uint8_t*)optit.curr_opt + 3);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_sizeof(optit.curr_opt), 1 + 2);

    avs_coap_opt_next(&optit);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_end(&optit));
}

AVS_UNIT_TEST(coap_msg, validate_opt_ext_length_byte) {
#define OPTS_SIZE (2 + (1 + AVS_COAP_EXT_U8_BASE))
    uint8_t opts[OPTS_SIZE] = "\x0d\x01";
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + OPTS_SIZE);
    setup_msg(msg, opts, OPTS_SIZE);
#undef OPTS_SIZE

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 1);

    avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
    AVS_UNIT_ASSERT_TRUE(optit.msg == msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&optit), 0);
    AVS_UNIT_ASSERT_NOT_NULL(optit.curr_opt);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_delta(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_content_length(optit.curr_opt), 1 + AVS_COAP_EXT_U8_BASE);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_value(optit.curr_opt) == (const uint8_t*)optit.curr_opt + 2);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_sizeof(optit.curr_opt), 1 + 1 + (1 + AVS_COAP_EXT_U8_BASE));

    avs_coap_opt_next(&optit);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_end(&optit));
}

AVS_UNIT_TEST(coap_msg, validate_opt_ext_length_short) {
    uint8_t opts[3 + 256 + AVS_COAP_EXT_U16_BASE] = "\x0e\x01\x00";

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(opts)
                   + (256 + AVS_COAP_EXT_U16_BASE - 1));
    setup_msg(msg, opts, 3 + (256 + AVS_COAP_EXT_U16_BASE));

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 1);

    avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);
    AVS_UNIT_ASSERT_TRUE(optit.msg == msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&optit), 0);
    AVS_UNIT_ASSERT_NOT_NULL(optit.curr_opt);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_delta(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_content_length(optit.curr_opt), 256 + AVS_COAP_EXT_U16_BASE);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_value(optit.curr_opt) == (const uint8_t*)optit.curr_opt + 3);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_sizeof(optit.curr_opt), 1 + 2 + (256 + AVS_COAP_EXT_U16_BASE));

    avs_coap_opt_next(&optit);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_end(&optit));
}

AVS_UNIT_TEST(coap_msg, validate_multiple_opts) {
    uint8_t opts[] = "\x00" "\xd0\x00" "\xe0\x00\x00";

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(opts) - 1);
    setup_msg(msg, opts, sizeof(opts) - 1);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 3);

    avs_coap_opt_iterator_t optit = avs_coap_opt_begin(msg);

    // opt "\x00"
    AVS_UNIT_ASSERT_TRUE(optit.msg == msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&optit), 0);
    AVS_UNIT_ASSERT_NOT_NULL(optit.curr_opt);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_delta(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_content_length(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_value(optit.curr_opt) == (const uint8_t*)optit.curr_opt + 1);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_sizeof(optit.curr_opt), 1);

    avs_coap_opt_next(&optit);

    // opt "\xd0\x00"
    AVS_UNIT_ASSERT_TRUE(optit.msg == msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&optit), 13);
    AVS_UNIT_ASSERT_NOT_NULL(optit.curr_opt);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_delta(optit.curr_opt), 13);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_content_length(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_value(optit.curr_opt) == (const uint8_t*)optit.curr_opt + 2);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_sizeof(optit.curr_opt), 2);

    avs_coap_opt_next(&optit);

    // opt "\xe0\x00"
    AVS_UNIT_ASSERT_TRUE(optit.msg == msg);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_number(&optit), 13 + 269);
    AVS_UNIT_ASSERT_NOT_NULL(optit.curr_opt);

    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_delta(optit.curr_opt), 269);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_content_length(optit.curr_opt), 0);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_value(optit.curr_opt) == (const uint8_t*)optit.curr_opt + 3);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_opt_sizeof(optit.curr_opt), 3);

    avs_coap_opt_next(&optit);
    AVS_UNIT_ASSERT_TRUE(avs_coap_opt_end(&optit));
}

AVS_UNIT_TEST(coap_msg, validate_payload) {
    uint8_t content[] = PAYLOAD_MARKER "http://fuldans.se";
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content) - 1);
    setup_msg(msg, content, sizeof(content) - 1);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 0);
}

AVS_UNIT_TEST(coap_msg, validate_payload_marker_only) {
    uint8_t content[] = PAYLOAD_MARKER;
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content) - 1);
    setup_msg(msg, content, sizeof(content) - 1);

    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 0);
}

AVS_UNIT_TEST(coap_msg, validate_full) {
    uint8_t content[] = "\x01\x02\x03\x04\x05\x06\x07\x08" // token
                        "\x00" "\xd0\x00" "\xe0\x00\x00" // options
                        PAYLOAD_MARKER "foo bar baz"; // content

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content));
    setup_msg(msg, content, sizeof(content));
    _avs_coap_header_set_token_length(msg, 8);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_EQUAL(count_opts(msg), 3);
    AVS_UNIT_ASSERT_EQUAL(avs_coap_msg_payload_length(msg), sizeof("foo bar baz"));
}

AVS_UNIT_TEST(coap_msg, payload_shorter_than_4b) {
    uint8_t content[] = PAYLOAD_MARKER "kek";

    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) = (avs_coap_msg_t *)
            avs_malloc(sizeof(*msg) + sizeof(content) - 1);
    setup_msg(msg, content, sizeof(content) - 1);

    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_is_valid(msg));
    AVS_UNIT_ASSERT_TRUE(avs_coap_msg_payload(msg)
                         == _avs_coap_header_end(msg) + 1);
}

static avs_coap_msg_t *
deserialize_msg(void *out_buffer, const char *raw_data, size_t data_size) {
    avs_coap_msg_t *msg = (avs_coap_msg_t*)out_buffer;
    msg->length = (uint32_t)data_size;
    memcpy(msg->content, raw_data, data_size);
    return msg;
}

#define DESERIALIZE_MSG(Content) \
    deserialize_msg(avs_malloc(sizeof(uint32_t) + sizeof(Content) - 1), \
                    Content, sizeof(Content) - 1)

AVS_UNIT_TEST(coap_msg, fuzz_1_missing_token) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            DESERIALIZE_MSG("\x68\x64\x05\x06\x0a");
    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
}

AVS_UNIT_TEST(coap_msg, fuzz_2_missing_option_ext_length) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            DESERIALIZE_MSG("\x60\x64\x05\x06\xfa");
    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
}

AVS_UNIT_TEST(coap_msg, fuzz_3_token_and_options) {
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            DESERIALIZE_MSG("\x64\x2d\x8d\x20" // header
                            "\x50\x16\xf8\x5b" // token
                            "\x73\x77\x4c\x4f\x03\xe8\x0a");
    AVS_UNIT_ASSERT_FALSE(avs_coap_msg_is_valid(msg));
}

