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

#include <avsystem/commons/avs_unit_test.h>
#include <avsystem/commons/avs_utils.h>

#include <string.h>

AVS_UNIT_TEST(hexlify, bad_input) {
    AVS_UNIT_ASSERT_FAILED(avs_hexlify(NULL, 123, NULL, "foo", 3));
    AVS_UNIT_ASSERT_FAILED(avs_hexlify((char *) -1, 0, NULL, "foo", 3));
}

AVS_UNIT_TEST(hexlify, zero_input) {
    char out[1];
    size_t bytes_hexlified;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_hexlify(out, sizeof(out), &bytes_hexlified, "foo", 0));
    AVS_UNIT_ASSERT_EQUAL(bytes_hexlified, 0);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_hexlify(out, sizeof(out), &bytes_hexlified, NULL, 3));
    AVS_UNIT_ASSERT_EQUAL(bytes_hexlified, 0);
}

AVS_UNIT_TEST(hexlify, truncation) {
    char out1[1] = { 0x7f };
    size_t bytes_hexlified;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_hexlify(out1, sizeof(out1), &bytes_hexlified, "foo", 3));
    AVS_UNIT_ASSERT_EQUAL(bytes_hexlified, 0);
    AVS_UNIT_ASSERT_EQUAL(out1[0], '\0');
    char out2[2] = { 0x7f, 0x7f };
    AVS_UNIT_ASSERT_SUCCESS(
            avs_hexlify(out2, sizeof(out2), &bytes_hexlified, "foo", 3));
    AVS_UNIT_ASSERT_EQUAL(bytes_hexlified, 0);
    AVS_UNIT_ASSERT_EQUAL(out2[0], '\0');
    char out3[3] = { 0x7f, 0x7f, 0x7f };
    AVS_UNIT_ASSERT_SUCCESS(
            avs_hexlify(out3, sizeof(out3), &bytes_hexlified, "foo", 3));
    AVS_UNIT_ASSERT_EQUAL(bytes_hexlified, 1);
    AVS_UNIT_ASSERT_EQUAL_STRING(out3, "66");
}

AVS_UNIT_TEST(hexlify, full) {
    char out7[7];
    memset(out7, 0x7f, sizeof(out7));
    size_t bytes_hexlified;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_hexlify(out7, sizeof(out7), &bytes_hexlified, "fgh", 3));
    AVS_UNIT_ASSERT_EQUAL(bytes_hexlified, 3);
    AVS_UNIT_ASSERT_EQUAL_STRING(out7, "666768");
}

AVS_UNIT_TEST(unhexlify, bad_input) {
    uint8_t out[4];
    AVS_UNIT_ASSERT_FAILED(
            avs_unhexlify(NULL, out, sizeof(out), "aaa", strlen("aaa")));
    AVS_UNIT_ASSERT_FAILED(
            avs_unhexlify(NULL, out, sizeof(out), "xddd", strlen("xddd")));
}

AVS_UNIT_TEST(unhexlify, input_too_long) {
    uint8_t out[4];
    size_t bytes_unhexlified;
    AVS_UNIT_ASSERT_SUCCESS(avs_unhexlify(&bytes_unhexlified, out, sizeof(out),
                                          "1122334455", strlen("1122334455")));
    AVS_UNIT_ASSERT_EQUAL(bytes_unhexlified, sizeof(out));
}

AVS_UNIT_TEST(unhexlify, zero_input) {
    uint8_t out[4];
    size_t bytes_unhexlified;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_unhexlify(&bytes_unhexlified, out, sizeof(out), "", 0));
    AVS_UNIT_ASSERT_EQUAL(bytes_unhexlified, 0);
}

AVS_UNIT_TEST(unhexlify, full) {
    uint8_t out[4];
    size_t bytes_unhexlified;

    memset(out, 0, sizeof(out));
    AVS_UNIT_ASSERT_SUCCESS(avs_unhexlify(&bytes_unhexlified, out, sizeof(out),
                                          "aaff", strlen("aaff")));
    AVS_UNIT_ASSERT_EQUAL(bytes_unhexlified, 2);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(out, "\xaa\xff", 2);

    memset(out, 0, sizeof(out));
    AVS_UNIT_ASSERT_SUCCESS(avs_unhexlify(&bytes_unhexlified, out, sizeof(out),
                                          "0099AAFF", strlen("0099AAFF")));
    AVS_UNIT_ASSERT_EQUAL(bytes_unhexlified, 4);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(out, "\x00\x99\xaa\xff", 4);
}
