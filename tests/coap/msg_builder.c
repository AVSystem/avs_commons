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

#include "src/coap/msg_internal.h"

#include <avsystem/commons/coap/msg_info.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/unit/test.h>

#include "utils.h"

#define RANDOM_MSGID ((uint16_t) 4)

static avs_coap_msg_t *make_msg_template(void *buffer, size_t buffer_size) {
    assert(buffer_size
           >= offsetof(avs_coap_msg_t, content) + AVS_COAP_MSG_MIN_SIZE);

    avs_coap_msg_t *msg = (avs_coap_msg_t *) buffer;

    memset(buffer, 0, buffer_size);

    _avs_coap_header_set_version(msg, 1);
    _avs_coap_header_set_type(msg, AVS_COAP_MSG_CONFIRMABLE);
    _avs_coap_header_set_token_length(msg, 0);
    _avs_coap_header_set_code(msg, AVS_COAP_CODE_CONTENT);
    _avs_coap_header_set_id(msg, RANDOM_MSGID);
    msg->length = (uint32_t) (buffer_size - offsetof(avs_coap_msg_t, content));

    return msg;
}

static avs_coap_opt_t *get_first_opt(avs_coap_msg_t *msg, size_t token_size) {
    return (avs_coap_opt_t *) (_avs_coap_header_end(msg) + token_size);
}

static avs_coap_msg_t *make_msg_template_with_data(void *buffer,
                                                   size_t buffer_size,
                                                   const void *data,
                                                   size_t data_size) {
    avs_coap_msg_t *msg = make_msg_template(buffer, buffer_size);
    memcpy(_avs_coap_header_end(msg), data, data_size);
    return msg;
}

#define DECLARE_MSG_TEMPLATE(VarName, SizeVarName, DataSize)            \
    const size_t SizeVarName = offsetof(avs_coap_msg_t, content)        \
                               + AVS_COAP_MAX_HEADER_SIZE + (DataSize); \
    avs_coap_msg_t *VarName __attribute__((cleanup(free_msg))) =        \
            make_msg_template(avs_malloc(SizeVarName), SizeVarName)

#define DECLARE_MSG_TEMPLATE_WITH_DATA(VarName, SizeVarName, Data)            \
    const size_t SizeVarName = offsetof(avs_coap_msg_t, content)              \
                               + AVS_COAP_MAX_HEADER_SIZE + sizeof(Data) - 1; \
    avs_coap_msg_t *VarName __attribute__((cleanup(free_msg))) =              \
            make_msg_template_with_data(avs_malloc(SizeVarName), SizeVarName, \
                                        (Data), sizeof(Data) - 1)

#define INFO_WITH_DUMMY_HEADER            \
    avs_coap_msg_info_init();             \
    info.type = AVS_COAP_MSG_CONFIRMABLE; \
    info.code = AVS_COAP_CODE_CONTENT;    \
    info.identity.msg_id = 0

#define INFO_WITH_HEADER(Msg)               \
    avs_coap_msg_info_init();               \
    info.type = avs_coap_msg_get_type(Msg); \
    info.code = avs_coap_msg_get_code(Msg); \
    info.identity.msg_id = avs_coap_msg_get_id(Msg)

AVS_UNIT_TEST(coap_builder, header_only) {
    DECLARE_MSG_TEMPLATE(msg_tpl, msg_tpl_size, 0);
    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);
    avs_free(storage);
}

AVS_UNIT_TEST(coap_info, token) {
    avs_coap_token_t TOKEN = { sizeof("A Token"), "A Token" };
    static const size_t msg_tpl_size = offsetof(avs_coap_msg_t, content)
                                       + AVS_COAP_MAX_HEADER_SIZE
                                       + AVS_COAP_MAX_TOKEN_LENGTH;
    avs_coap_msg_t *msg_tpl __attribute__((cleanup(free_msg))) =
            make_msg_template_with_data(avs_malloc(msg_tpl_size), msg_tpl_size,
                                        TOKEN.bytes, TOKEN.size);
    _avs_coap_header_set_token_length(msg_tpl, TOKEN.size);

    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);
    info.identity.token = TOKEN;

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(
            msg, msg_tpl, sizeof(msg_tpl->length) + msg_tpl->length);
    avs_free(storage);
}

AVS_UNIT_TEST(coap_builder, option_empty) {
    DECLARE_MSG_TEMPLATE_WITH_DATA(msg_tpl, msg_tpl_size, "\x00");
    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_empty(&info, 0));

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);

    avs_coap_msg_info_reset(&info);
    avs_free(storage);
}

AVS_UNIT_TEST(coap_builder, option_opaque) {
    DECLARE_MSG_TEMPLATE_WITH_DATA(msg_tpl, msg_tpl_size,
                                   "\x00"
                                   "foo");
    _avs_coap_opt_set_short_length(get_first_opt(msg_tpl, 0), 3);

    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_msg_info_opt_opaque(&info, 0, "foo", sizeof("foo") - 1));

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);

    avs_coap_msg_info_reset(&info);
    avs_free(storage);
}

AVS_UNIT_TEST(coap_builder, option_multiple_ints) {
    static const size_t content_length =
            sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t)
            + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint32_t)
            + sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint8_t)
            + sizeof(uint8_t) + sizeof(uint8_t);
    DECLARE_MSG_TEMPLATE(msg_tpl, msg_tpl_size, content_length);

    uint8_t *opts = _avs_coap_header_end(msg_tpl);
    _avs_coap_opt_set_short_length((avs_coap_opt_t *) &opts[0], 1);
    opts[1] = 0x10;
    _avs_coap_opt_set_short_length((avs_coap_opt_t *) &opts[2], 2);
    opts[3] = 0x21;
    opts[4] = 0x20;
    _avs_coap_opt_set_short_length((avs_coap_opt_t *) &opts[5], 4);
    opts[6] = 0x43;
    opts[7] = 0x42;
    opts[8] = 0x41;
    opts[9] = 0x40;
    _avs_coap_opt_set_short_length((avs_coap_opt_t *) &opts[10], 8);
    opts[11] = 0x87;
    opts[12] = 0x86;
    opts[13] = 0x85;
    opts[14] = 0x84;
    opts[15] = 0x83;
    opts[16] = 0x82;
    opts[17] = 0x81;
    opts[18] = 0x80;
    _avs_coap_opt_set_short_length((avs_coap_opt_t *) &opts[19], 1);
    opts[20] = 0xFF;
    _avs_coap_opt_set_short_length((avs_coap_opt_t *) &opts[21], 0);

    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_msg_info_opt_uint(&info, 0, &(uint8_t) { 0x10 }, 1));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_msg_info_opt_uint(&info, 0, &(uint16_t) { 0x2120 }, 2));
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_uint(
            &info, 0, &(uint32_t) { 0x43424140 }, 4));
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_uint(
            &info, 0, &(uint64_t) { 0x8786858483828180 }, 8));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_msg_info_opt_uint(&info, 0, &(uint64_t) { 0xFF }, 8));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_msg_info_opt_uint(&info, 0, &(uint64_t) { 0 }, 8));

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);

    avs_coap_msg_info_reset(&info);
    avs_free(storage);
}

AVS_UNIT_TEST(coap_builder, option_content_format) {
    static const size_t content_length = sizeof(uint8_t) + sizeof(uint16_t);
    DECLARE_MSG_TEMPLATE(msg_tpl, msg_tpl_size, content_length);
    avs_coap_opt_t *opt = get_first_opt(msg_tpl, 0);
    _avs_coap_opt_set_short_length(opt, 2);
    _avs_coap_opt_set_short_delta(opt, AVS_COAP_OPT_CONTENT_FORMAT);
    memcpy(&opt->content[0], &(uint16_t) { avs_convert_be16(11542) }, 2);

    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_content_format(&info, 11542));

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);

    avs_coap_msg_info_reset(&info);
    avs_free(storage);
}

#define PAYLOAD "trololo"

AVS_UNIT_TEST(coap_builder, payload_only) {
    DECLARE_MSG_TEMPLATE_WITH_DATA(msg_tpl, msg_tpl_size, "\xFF" PAYLOAD);
    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info)
                          + sizeof(AVS_COAP_PAYLOAD_MARKER) + sizeof(PAYLOAD)
                          - 1;
    void *storage = avs_malloc(storage_size);

    avs_coap_msg_builder_t builder;
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_builder_init(
            &builder, avs_coap_ensure_aligned_buffer(storage), storage_size,
            &info));

    AVS_UNIT_ASSERT_EQUAL(sizeof(PAYLOAD) - 1,
                          avs_coap_msg_builder_payload(&builder, PAYLOAD,
                                                       sizeof(PAYLOAD) - 1));

    const avs_coap_msg_t *msg = avs_coap_msg_builder_get_msg(&builder);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);
    avs_free(storage);
}

#undef PAYLOAD

#define PAYLOAD1 "I can haz "
#define PAYLOAD2 "payload"
#define PAYLOAD_SIZE (sizeof(PAYLOAD1 PAYLOAD2) - 1)

AVS_UNIT_TEST(coap_builder, incremental_payload) {
    DECLARE_MSG_TEMPLATE_WITH_DATA(msg_tpl, msg_tpl_size,
                                   "\xFF" PAYLOAD1 PAYLOAD2);

    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info)
                          + sizeof(AVS_COAP_PAYLOAD_MARKER) + PAYLOAD_SIZE;
    void *storage = avs_malloc(storage_size);

    avs_coap_msg_builder_t builder;
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_builder_init(
            &builder, avs_coap_ensure_aligned_buffer(storage), storage_size,
            &info));

    AVS_UNIT_ASSERT_EQUAL(sizeof(PAYLOAD1) - 1,
                          avs_coap_msg_builder_payload(&builder, PAYLOAD1,
                                                       sizeof(PAYLOAD1) - 1));
    AVS_UNIT_ASSERT_EQUAL(sizeof(PAYLOAD2) - 1,
                          avs_coap_msg_builder_payload(&builder, PAYLOAD2,
                                                       sizeof(PAYLOAD2) - 1));

    const avs_coap_msg_t *msg = avs_coap_msg_builder_get_msg(&builder);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);
    avs_free(storage);
}

#undef PAYLOAD1
#undef PAYLOAD2
#undef PAYLOAD_SIZE

#define OPT_EXT_DELTA1 "\xD0\x00"
#define OPT_EXT_DELTA2 "\xE0\x00\x00"

AVS_UNIT_TEST(coap_builder, option_ext_number) {
    DECLARE_MSG_TEMPLATE_WITH_DATA(msg_tpl, msg_tpl_size,
                                   OPT_EXT_DELTA1 OPT_EXT_DELTA2);
    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);

    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_empty(&info, 13));
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_empty(&info, 13 + 269));

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);

    avs_coap_msg_info_reset(&info);
    avs_free(storage);
}

#undef OPT_EXT_DELTA1
#undef OPT_EXT_DELTA2

#define ZEROS_8 "\x00\x00\x00\x00\x00\x00\x00\x00"
#define ZEROS_64 ZEROS_8 ZEROS_8 ZEROS_8 ZEROS_8 ZEROS_8 ZEROS_8 ZEROS_8 ZEROS_8
#define ZEROS_256 ZEROS_64 ZEROS_64 ZEROS_64 ZEROS_64

#define ZEROS_13 ZEROS_8 "\x00\x00\x00\x00\x00"
#define ZEROS_269 ZEROS_256 ZEROS_13

#define OPT_EXT_LENGTH1 "\x0D\x00"
#define OPT_EXT_LENGTH2 "\x0E\x00\x00"

AVS_UNIT_TEST(coap_builder, option_ext_length) {
    DECLARE_MSG_TEMPLATE_WITH_DATA(
            msg_tpl, msg_tpl_size,
            OPT_EXT_LENGTH1 ZEROS_13 OPT_EXT_LENGTH2 ZEROS_269);
    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);

    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_opaque(&info, 0, ZEROS_13,
                                                         sizeof(ZEROS_13) - 1));
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_opaque(
            &info, 0, ZEROS_269, sizeof(ZEROS_269) - 1));

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);

    avs_coap_msg_info_reset(&info);
    avs_free(storage);
}

#undef OPT_EXT_LENGTH1
#undef OPT_EXT_LENGTH2

#define STRING "SomeString"

AVS_UNIT_TEST(coap_builder, opt_string) {
    DECLARE_MSG_TEMPLATE_WITH_DATA(msg_tpl, msg_tpl_size, "\x0A" STRING);
    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);

    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_info_opt_string(&info, 0, STRING));

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);

    avs_coap_msg_info_reset(&info);
    avs_free(storage);
}

#undef STRING

#define DATA_16 "0123456789abcdef"
#define DATA_256                                                            \
    DATA_16 DATA_16 DATA_16 DATA_16 DATA_16 DATA_16 DATA_16 DATA_16 DATA_16 \
            DATA_16 DATA_16 DATA_16 DATA_16 DATA_16 DATA_16 DATA_16
#define DATA_8192                                                           \
    DATA_256 DATA_256 DATA_256 DATA_256 DATA_256 DATA_256 DATA_256 DATA_256 \
            DATA_256 DATA_256 DATA_256 DATA_256 DATA_256 DATA_256 DATA_256  \
                    DATA_256
#define DATA_65536                                                        \
    DATA_8192 DATA_8192 DATA_8192 DATA_8192 DATA_8192 DATA_8192 DATA_8192 \
            DATA_8192 DATA_8192 DATA_8192 DATA_8192 DATA_8192 DATA_8192   \
                    DATA_8192 DATA_8192 DATA_8192

AVS_UNIT_TEST(coap_builder, opt_string_too_long) {
    avs_coap_msg_info_t info = INFO_WITH_DUMMY_HEADER;
    AVS_UNIT_ASSERT_FAILED(avs_coap_msg_info_opt_string(&info, 0, DATA_65536));
}

#undef DATA_16
#undef DATA_256
#undef DATA_8192
#undef DATA_65536

AVS_UNIT_TEST(coap_builder, payload_call_with_zero_size) {
    DECLARE_MSG_TEMPLATE(msg_tpl, msg_tpl_size, 0);
    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info);
    void *storage = avs_malloc(storage_size);

    avs_coap_msg_builder_t builder;
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_builder_init(
            &builder, avs_coap_ensure_aligned_buffer(storage), storage_size,
            &info));

    AVS_UNIT_ASSERT_EQUAL(0, avs_coap_msg_builder_payload(&builder, "", 0));
    const avs_coap_msg_t *msg = avs_coap_msg_builder_get_msg(&builder);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);
    avs_free(storage);
}

#define PAYLOAD \
    "And IiiiiiiiiiiiiiiIIIiiiii will alllwayyyyyys crash youuuuUUUUuuu"

AVS_UNIT_TEST(coap_builder, payload_call_with_zero_size_then_nonzero) {
    DECLARE_MSG_TEMPLATE_WITH_DATA(msg_tpl, msg_tpl_size, "\xFF" PAYLOAD);

    avs_coap_msg_info_t info = INFO_WITH_HEADER(msg_tpl);

    size_t storage_size = avs_coap_msg_info_get_storage_size(&info)
                          + sizeof(AVS_COAP_PAYLOAD_MARKER) + sizeof(PAYLOAD);
    void *storage = avs_malloc(storage_size);

    avs_coap_msg_builder_t builder;
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_msg_builder_init(
            &builder, avs_coap_ensure_aligned_buffer(storage), storage_size,
            &info));

    AVS_UNIT_ASSERT_EQUAL(0, avs_coap_msg_builder_payload(&builder, "", 0));
    AVS_UNIT_ASSERT_EQUAL(sizeof(PAYLOAD) - 1,
                          avs_coap_msg_builder_payload(&builder, PAYLOAD,
                                                       sizeof(PAYLOAD) - 1));

    const avs_coap_msg_t *msg = avs_coap_msg_builder_get_msg(&builder);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, msg_tpl, msg_tpl_size);
    avs_free(storage);
}

#undef PAYLOAD
