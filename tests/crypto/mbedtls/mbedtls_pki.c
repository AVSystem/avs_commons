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

#include <avs_commons_init.h>

#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_TEST(convert_x509_time, year_to_days) {
    // Let's start in 1900 and test more than two full 400-year cycles.
    // NOTE: This initially used 1583 as the initial year, but it turns out that
    // timegm() on macOS does not support years before 1900, so we have nothing
    // to verify the calculation against.
    static const int START_YEAR = sizeof(time_t) > 4 ? 1900 : 1902;
    // On 32-bit architectures we unfortunately can't test beyond 2038
    static const int END_YEAR = sizeof(time_t) > 4 ? 2800 : 2038;
    for (int year = START_YEAR; year < END_YEAR; ++year) {
        bool is_leap;
        int64_t days = year_to_days(year, &is_leap);
        if (year % 4 == 0) {
            if (year % 100 == 0) {
                if (year % 400 == 0) {
                    AVS_UNIT_ASSERT_TRUE(is_leap);
                } else {
                    AVS_UNIT_ASSERT_FALSE(is_leap);
                }
            } else {
                AVS_UNIT_ASSERT_TRUE(is_leap);
            }
        } else {
            AVS_UNIT_ASSERT_FALSE(is_leap);
        }

        // NOTE: timegm() is a non-standard extension present in GNU and BSD,
        // that's why we can't use it in actual library code.
        time_t unix_timestamp = timegm(&(struct tm) {
            .tm_mday = 1,
            .tm_mon = 0,
            .tm_year = year - 1900
        });

        AVS_UNIT_ASSERT_EQUAL(days * (time_t) 86400, unix_timestamp);
    }
}

AVS_UNIT_TEST(convert_x509_time, month_to_days) {
    // Check for non-leap year
    for (int month = 1; month <= 12; ++month) {
        int days = month_to_days(month, false);

        time_t unix_timestamp = timegm(&(struct tm) {
            .tm_mday = 1,
            .tm_mon = month - 1,
            .tm_year = 70
        });

        AVS_UNIT_ASSERT_EQUAL(days * (time_t) 86400, unix_timestamp);
    }

    // Check for leap year
    for (int month = 1; month <= 12; ++month) {
        int days = month_to_days(month, true);

        time_t unix_timestamp = timegm(&(struct tm) {
            .tm_mday = 1,
            .tm_mon = month - 1,
            .tm_year = 72
        });

        AVS_UNIT_ASSERT_EQUAL((2 * 365 + days) * (time_t) 86400,
                              unix_timestamp);
    }
}

AVS_UNIT_TEST(convert_x509_time, example_date) {
    // year_to_days() and month_to_days() are tested thoroughly above;
    // let's test a single complete date and time
    // to check that their results are combined properly
    avs_time_real_t result = convert_x509_time(&(const mbedtls_x509_time) {
        .year = 2005,
        .mon = 4,
        .day = 2,
        .hour = 19,
        .min = 37,
        .sec = 1
    });

    // $ env LC_ALL=C date '+%s' -d '2005-04-02 21:37:01 CEST'
    // 1112470621
    AVS_UNIT_ASSERT_EQUAL(result.since_real_epoch.seconds, 1112470621);
    AVS_UNIT_ASSERT_EQUAL(result.since_real_epoch.nanoseconds, 0);
}
