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

AVS_UNIT_TEST(uint_as_string, some_value) {
    AVS_UNIT_ASSERT_EQUAL_STRING(
            uint64_as_string_custom(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, 123),
            "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            avs_uint64_as_string_impl__(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, 123),
            "123");
}

AVS_UNIT_TEST(uint_as_string, zero) {
    AVS_UNIT_ASSERT_EQUAL_STRING(
            uint64_as_string_custom(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, 0),
            "0");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            avs_uint64_as_string_impl__(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, 0),
            "0");
}

AVS_UNIT_TEST(uint_as_string, uint64_max) {
    AVS_UNIT_ASSERT_EQUAL_STRING(
            uint64_as_string_custom(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, UINT64_MAX),
            "18446744073709551615");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            avs_uint64_as_string_impl__(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, UINT64_MAX),
            "18446744073709551615");
}

AVS_UNIT_TEST(int_as_string, zero) {
    AVS_UNIT_ASSERT_EQUAL_STRING(
            int64_as_string_custom(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, 0),
            "0");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            avs_int64_as_string_impl__(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, 0),
            "0");
}

AVS_UNIT_TEST(int_as_string, int64_min) {
    AVS_UNIT_ASSERT_EQUAL_STRING(
            int64_as_string_custom(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, INT64_MIN),
            "-9223372036854775808");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            avs_int64_as_string_impl__(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, INT64_MIN),
            "-9223372036854775808");
}

AVS_UNIT_TEST(int_as_string, int64_max) {
    AVS_UNIT_ASSERT_EQUAL_STRING(
            int64_as_string_custom(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, INT64_MAX),
            "9223372036854775807");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            avs_int64_as_string_impl__(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, INT64_MAX),
            "9223372036854775807");
}
