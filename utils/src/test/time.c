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

#include <time.h>

#include <avsystem/commons/time.h>
#include <avsystem/commons/unit/test.h>

AVS_UNIT_TEST(time, time_from_ms) {
    struct timespec value;
    value = avs_time_from_ms(1234);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 234000000L);
    value = avs_time_from_ms(-1234);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, -2);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 766000000L);
}

AVS_UNIT_TEST(time, add_ms_positive) {
    struct timespec value = { 0, 0 };
    avs_time_add_ms(&value, 1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 0);
    AVS_UNIT_ASSERT_EQUAL(1 * 1000 * 1000, value.tv_nsec);
}

AVS_UNIT_TEST(time, add_ms_negative) {
    struct timespec value = { 0, 1 * 1000 * 1000 };
    avs_time_add_ms(&value, -1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 0);
    AVS_UNIT_ASSERT_EQUAL(0, value.tv_nsec);

}

AVS_UNIT_TEST(time, add_ms_positive_overflow) {
    struct timespec value = { 0, 999 * 1000 * 1000 };
    avs_time_add_ms(&value, 1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 1);
    AVS_UNIT_ASSERT_EQUAL(0, value.tv_nsec);
}

AVS_UNIT_TEST(time, add_ms_negative_underflow) {
    struct timespec value = { 0, 0 };
    avs_time_add_ms(&value, -1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, -1);
    AVS_UNIT_ASSERT_EQUAL(999 * 1000 * 1000, value.tv_nsec);
}

AVS_UNIT_TEST(time, div_ns_only) {
    struct timespec value = { 0, 10 };
    value = avs_time_div(&value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 0);
    AVS_UNIT_ASSERT_EQUAL(5, value.tv_nsec);
}

AVS_UNIT_TEST(time, div) {
    struct timespec value = { 1, 10 };
    value = avs_time_div(&value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 0);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 500 * 1000 * 1000 + 5);
}

AVS_UNIT_TEST(time, div_s_rest) {
    struct timespec value = { 3, 500 * 1000 * 1000 };
    value = avs_time_div(&value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 750 * 1000 * 1000);
}

AVS_UNIT_TEST(time, div_big_divisor) {
    struct timespec value = { 1, 0 };
    value = avs_time_div(&value, 1 * 1000 * 1000 * 1000);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 0);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 1);
}

AVS_UNIT_TEST(time, div_big_seconds) {
    struct timespec value = { 999 * 1000 * 1000, 0 };
    value = avs_time_div(&value, 1 * 1000 * 1000 * 1000);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, 0);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 999 * 1000 * 1000);
}

AVS_UNIT_TEST(time, div_negative) {
    struct timespec value = { -1, 0 };
    value = avs_time_div(&value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, -1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 500 * 1000 * 1000);
}

AVS_UNIT_TEST(time, div_negative_ns) {
    struct timespec value = { -1, 500 * 1000 * 1000 };
    value = avs_time_div(&value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, -1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 750 * 1000 * 1000);
}

AVS_UNIT_TEST(time, div_big_negative) {
    struct timespec value = { -999 * 1000 * 1000, 0 };
    value = avs_time_div(&value, 1 * 1000 * 1000 * 1000);
    AVS_UNIT_ASSERT_EQUAL(value.tv_sec, -1);
    AVS_UNIT_ASSERT_EQUAL(value.tv_nsec, 1 * 1000 * 1000);
}
