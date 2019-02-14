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

#include <avsystem/commons/unit/test.h>
#include <avsystem/commons/utils.h>

#include <string.h>

AVS_UNIT_TEST(hexlify, bad_input) {
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify(NULL, 123, "foo", 3), -1);
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify((char *) -1, 0, "foo", 3), -1);
}

AVS_UNIT_TEST(hexlify, zero_input) {
    char out[1];
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify(out, sizeof(out), "foo", 0), 0);
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify(out, sizeof(out), NULL, 3), 0);
}

AVS_UNIT_TEST(hexlify, truncation) {
    char out1[1] = { 0x7f };
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify(out1, sizeof(out1), "foo", 3), 0);
    AVS_UNIT_ASSERT_EQUAL(out1[0], '\0');
    char out2[2] = { 0x7f, 0x7f };
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify(out2, sizeof(out2), "foo", 3), 0);
    AVS_UNIT_ASSERT_EQUAL(out2[0], '\0');
    char out3[3] = { 0x7f, 0x7f, 0x7f };
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify(out3, sizeof(out3), "foo", 3), 1);
    AVS_UNIT_ASSERT_EQUAL_STRING(out3, "66");
}

AVS_UNIT_TEST(hexlify, full) {
    char out7[7];
    memset(out7, 0x7f, sizeof(out7));
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify(out7, sizeof(out7), "fgh", 3), 3);
    AVS_UNIT_ASSERT_EQUAL_STRING(out7, "666768");
}
