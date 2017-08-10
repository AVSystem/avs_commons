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
#define _GNU_SOURCE

#include <avsystem/commons/unit/test.h>

AVS_UNIT_TEST(token, match_token) {
    const char *test_stream1 = "  hello==world";
    const char *test_stream2 = "helloworld=not";
    AVS_UNIT_ASSERT_EQUAL(avs_match_token(&test_stream1, "hello", "="), 0);
    AVS_UNIT_ASSERT_EQUAL_STRING(test_stream1, "=world");

    AVS_UNIT_ASSERT_NOT_EQUAL(avs_match_token(&test_stream2, "hello", "="), 0);
    AVS_UNIT_ASSERT_EQUAL_STRING(test_stream2, "helloworld=not");

    AVS_UNIT_ASSERT_NOT_EQUAL(avs_match_token(&test_stream2,
                                              "kthanksbye", "="), 0);
    AVS_UNIT_ASSERT_EQUAL_STRING(test_stream2, "helloworld=not");
}
