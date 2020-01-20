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

#ifndef AVS_COMMONS_UNIT_SRC_TEST_H
#define AVS_COMMONS_UNIT_SRC_TEST_H

VISIBILITY_PRIVATE_HEADER_BEGIN

void _avs_unit_test_fail_printf(const char *file,
                                int line,
                                const char *format,
                                ...);

void _avs_unit_assert_fail(const char *file, int line, const char *format, ...)
        __attribute__((noreturn));

#define _avs_unit_assert(Condition, File, Line, ...)            \
    do {                                                        \
        if (!(Condition)) {                                     \
            _avs_unit_assert_fail((File), (Line), __VA_ARGS__); \
        }                                                       \
    } while (0)

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_UNIT_SRC_TEST_H */
