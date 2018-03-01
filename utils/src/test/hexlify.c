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

#include <avsystem/commons/unit/test.h>
#include <avsystem/commons/utils.h>

AVS_UNIT_TEST(hexlify, bad_input) {
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify_some(NULL, 123, "foo", 3), -1);
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify_some((char *) -1, 0, "foo", 3), -1);
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify_some((char *) -1, 32, "foo", 0), -1);
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify_some((char *) -1, 32, NULL, 3), -1);
}

AVS_UNIT_TEST(hexlify, truncation) {
    char out1[1] = { 0x7f };
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify_some(out1, sizeof(out1), "foo", 3), 1);
    AVS_UNIT_ASSERT_EQUAL(out1[0], '\0');
    char out2[2] = { 0x7f, 0x7f };
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify_some(out2, sizeof(out2), "foo", 3), 1);
    AVS_UNIT_ASSERT_EQUAL(out2[0], '\0');
    char out3[3] = { 0x7f, 0x7f, 0x7f };
    AVS_UNIT_ASSERT_EQUAL(avs_hexlify_some(out3, sizeof(out3), "foo", 3), 3);
    AVS_UNIT_ASSERT_EQUAL_STRING(out3, "66");
}
