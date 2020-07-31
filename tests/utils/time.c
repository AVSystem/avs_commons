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

#include <time.h>

#include <avsystem/commons/avs_time.h>
#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_TEST(time, time_arithmetic) {
    avs_time_real_t realtime =
            avs_time_real_add((avs_time_real_t) { { 42, 0 } },
                              (avs_time_duration_t) { 514, 0 });
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, 556);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 0);

    avs_time_monotonic_t monotonic =
            avs_time_monotonic_add((avs_time_monotonic_t) { { -42, 0 } },
                                   (avs_time_duration_t) { -514, 0 });
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds, -556);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds, 0);

    avs_time_duration_t duration = avs_time_duration_add(
            (avs_time_duration_t) { INT64_MAX / 2, 0 },
            (avs_time_duration_t) { INT64_MAX / 2 + 2, 0 });
    AVS_UNIT_ASSERT_FALSE(avs_time_duration_valid(duration));

    realtime = avs_time_real_add((avs_time_real_t) { { INT64_MIN, 0 } },
                                 (avs_time_duration_t) { INT64_MIN, 0 });
    AVS_UNIT_ASSERT_FALSE(avs_time_real_valid(realtime));

    monotonic =
            avs_time_monotonic_add((avs_time_monotonic_t) { { INT64_MIN, 0 } },
                                   (avs_time_duration_t) { INT64_MAX, 0 });
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds, -1);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds, 0);

    duration = avs_time_duration_add((avs_time_duration_t) { 0, 999999999 },
                                     (avs_time_duration_t) { 0, 42 });
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 1);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 41);

    realtime = avs_time_real_add((avs_time_real_t) { { INT64_MAX, 999999999 } },
                                 (avs_time_duration_t) { 0, 42 });
    AVS_UNIT_ASSERT_FALSE(avs_time_real_valid(realtime));

    duration = avs_time_monotonic_diff((avs_time_monotonic_t) { { 0, 0 } },
                                       (avs_time_monotonic_t) {
                                               { INT64_MIN, 1 } });
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, INT64_MAX);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 999999999);

    duration =
            avs_time_duration_diff((avs_time_duration_t) { INT64_MIN + 1, 42 },
                                   (avs_time_duration_t) { 0, 999999999 });
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, INT64_MIN);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 43);

    duration = avs_time_real_diff((avs_time_real_t) { { INT64_MIN, 42 } },
                                  (avs_time_real_t) { { 0, 999999999 } });
    AVS_UNIT_ASSERT_FALSE(avs_time_duration_valid(duration));
}

AVS_UNIT_TEST(time, time_to_scalar) {
    int64_t result;
    AVS_UNIT_ASSERT_SUCCESS(avs_time_real_to_scalar(
            &result, AVS_TIME_NS, (avs_time_real_t) { { 0, 123456789 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 123456789);
    AVS_UNIT_ASSERT_FAILED(avs_time_monotonic_to_scalar(
            &result, AVS_TIME_NS,
            (avs_time_monotonic_t) { { 0, 1234567898 } }));
    AVS_UNIT_ASSERT_SUCCESS(avs_time_duration_to_scalar(
            &result, AVS_TIME_NS,
            (avs_time_duration_t) { 123456789, 876543210 }));
    AVS_UNIT_ASSERT_EQUAL(result, 123456789876543210L);

    AVS_UNIT_ASSERT_SUCCESS(avs_time_monotonic_to_scalar(
            &result, AVS_TIME_US, (avs_time_monotonic_t) { { 0, 123456789 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 123456);
    AVS_UNIT_ASSERT_FAILED(avs_time_duration_to_scalar(
            &result, AVS_TIME_US, (avs_time_duration_t) { 0, 1234567898 }));
    AVS_UNIT_ASSERT_SUCCESS(avs_time_real_to_scalar(
            &result, AVS_TIME_US,
            (avs_time_real_t) { { 123456789, 876543210 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 123456789876543L);

    AVS_UNIT_ASSERT_SUCCESS(avs_time_duration_to_scalar(
            &result, AVS_TIME_MS, (avs_time_duration_t) { 0, 123456789 }));
    AVS_UNIT_ASSERT_EQUAL(result, 123);
    AVS_UNIT_ASSERT_FAILED(avs_time_real_to_scalar(
            &result, AVS_TIME_MS, (avs_time_real_t) { { 0, 1234567898 } }));
    AVS_UNIT_ASSERT_SUCCESS(avs_time_monotonic_to_scalar(
            &result, AVS_TIME_MS,
            (avs_time_monotonic_t) { { 123456789, 876543210 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 123456789876L);

    AVS_UNIT_ASSERT_SUCCESS(avs_time_real_to_scalar(
            &result, AVS_TIME_S, (avs_time_real_t) { { 0, 123456789 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 0);
    AVS_UNIT_ASSERT_FAILED(avs_time_monotonic_to_scalar(
            &result, AVS_TIME_S, (avs_time_monotonic_t) { { 0, 1234567898 } }));
    AVS_UNIT_ASSERT_SUCCESS(avs_time_duration_to_scalar(
            &result, AVS_TIME_S,
            (avs_time_duration_t) { 123456789, 876543210 }));
    AVS_UNIT_ASSERT_EQUAL(result, 123456789L);

    AVS_UNIT_ASSERT_SUCCESS(avs_time_monotonic_to_scalar(
            &result, AVS_TIME_MIN,
            (avs_time_monotonic_t) { { 0, 123456789 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 0);
    AVS_UNIT_ASSERT_FAILED(avs_time_duration_to_scalar(
            &result, AVS_TIME_MIN, (avs_time_duration_t) { 0, 1234567898 }));
    AVS_UNIT_ASSERT_SUCCESS(avs_time_real_to_scalar(
            &result, AVS_TIME_MIN,
            (avs_time_real_t) { { 123456789, 876543210 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 2057613);

    AVS_UNIT_ASSERT_SUCCESS(avs_time_duration_to_scalar(
            &result, AVS_TIME_HOUR, (avs_time_duration_t) { 0, 123456789 }));
    AVS_UNIT_ASSERT_EQUAL(result, 0);
    AVS_UNIT_ASSERT_FAILED(avs_time_real_to_scalar(
            &result, AVS_TIME_HOUR, (avs_time_real_t) { { 0, 1234567898 } }));
    AVS_UNIT_ASSERT_SUCCESS(avs_time_monotonic_to_scalar(
            &result, AVS_TIME_HOUR,
            (avs_time_monotonic_t) { { 123456789, 876543210 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 34293);

    AVS_UNIT_ASSERT_SUCCESS(avs_time_real_to_scalar(
            &result, AVS_TIME_DAY, (avs_time_real_t) { { 0, 123456789 } }));
    AVS_UNIT_ASSERT_EQUAL(result, 0);
    AVS_UNIT_ASSERT_FAILED(avs_time_monotonic_to_scalar(
            &result, AVS_TIME_DAY,
            (avs_time_monotonic_t) { { 0, 1234567898 } }));
    AVS_UNIT_ASSERT_SUCCESS(avs_time_duration_to_scalar(
            &result, AVS_TIME_DAY,
            (avs_time_duration_t) { 123456789, 876543210 }));
    AVS_UNIT_ASSERT_EQUAL(result, 1428);
}

AVS_UNIT_TEST(time, time_to_fscalar) {
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_real_to_fscalar((avs_time_real_t) { { 0, 123456789 } },
                                     AVS_TIME_NS),
            123456789.0);
    AVS_UNIT_ASSERT_EQUAL(avs_time_monotonic_to_fscalar(
                                  (avs_time_monotonic_t) { { 0, 1234567898 } },
                                  AVS_TIME_NS),
                          NAN);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_duration_to_fscalar((avs_time_duration_t) { 123456789,
                                                                 876543210 },
                                         AVS_TIME_NS),
            123456789876543210.0);
    AVS_UNIT_ASSERT_EQUAL(avs_time_monotonic_to_fscalar(
                                  (avs_time_monotonic_t) { { 0, 123456789 } },
                                  AVS_TIME_US),
                          123456.789);
    AVS_UNIT_ASSERT_EQUAL(avs_time_duration_to_fscalar(
                                  (avs_time_duration_t) { 0, 1234567898 },
                                  AVS_TIME_US),
                          NAN);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_real_to_fscalar(
                    (avs_time_real_t) { { 123456789, 876543210 } },
                    AVS_TIME_US),
            123456789876543.21);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_duration_to_fscalar((avs_time_duration_t) { 0, 123456789 },
                                         AVS_TIME_MS),
            123.456789);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_real_to_fscalar((avs_time_real_t) { { 0, 1234567898 } },
                                     AVS_TIME_MS),
            NAN);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_monotonic_to_fscalar(
                    (avs_time_monotonic_t) { { 123456789, 876543210 } },
                    AVS_TIME_MS),
            123456789876.54321);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_real_to_fscalar((avs_time_real_t) { { 0, 123456789 } },
                                     AVS_TIME_S),
            0.123456789);
    AVS_UNIT_ASSERT_EQUAL(avs_time_monotonic_to_fscalar(
                                  (avs_time_monotonic_t) { { 0, 1234567898 } },
                                  AVS_TIME_S),
                          NAN);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_duration_to_fscalar(
                    (avs_time_duration_t) { 123456789, 876543210 }, AVS_TIME_S),
            123456789.87654321);
    AVS_UNIT_ASSERT_EQUAL(avs_time_monotonic_to_fscalar(
                                  (avs_time_monotonic_t) { { 0, 123456789 } },
                                  AVS_TIME_MIN),
                          0.00205761315);
    AVS_UNIT_ASSERT_EQUAL(avs_time_duration_to_fscalar(
                                  (avs_time_duration_t) { 0, 1234567898 },
                                  AVS_TIME_MIN),
                          NAN);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_real_to_fscalar(
                    (avs_time_real_t) { { 123456789, 876543210 } },
                    AVS_TIME_MIN),
            2057613.1646090534);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_duration_to_fscalar((avs_time_duration_t) { 0, 123456789 },
                                         AVS_TIME_HOUR),
            3.42935525e-5);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_real_to_fscalar((avs_time_real_t) { { 0, 1234567898 } },
                                     AVS_TIME_HOUR),
            NAN);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_monotonic_to_fscalar(
                    (avs_time_monotonic_t) { { 123456789, 876543210 } },
                    AVS_TIME_HOUR),
            34293.55274348422);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_real_to_fscalar((avs_time_real_t) { { 0, 123456789 } },
                                     AVS_TIME_DAY),
            1.4288980208333333e-6);
    AVS_UNIT_ASSERT_EQUAL(avs_time_monotonic_to_fscalar(
                                  (avs_time_monotonic_t) { { 0, 1234567898 } },
                                  AVS_TIME_DAY),
                          NAN);
    AVS_UNIT_ASSERT_EQUAL(
            avs_time_duration_to_fscalar((avs_time_duration_t) { 123456789,
                                                                 876543210 },
                                         AVS_TIME_DAY),
            1428.8980309785093);
}

AVS_UNIT_TEST(time, time_from_scalar) {
    avs_time_real_t realtime =
            avs_time_real_from_scalar(1234567898L, AVS_TIME_NS);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, 1);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 234567898);
    avs_time_monotonic_t monotonic =
            avs_time_monotonic_from_scalar(-1234567898L, AVS_TIME_NS);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds, -2);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds,
                          765432102);
    avs_time_duration_t duration =
            avs_time_duration_from_scalar(1234567898L, AVS_TIME_US);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 1234);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 567898000);
    realtime = avs_time_real_from_scalar(-1234567898L, AVS_TIME_US);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, -1235);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 432102000);
    monotonic = avs_time_monotonic_from_scalar(1234567898L, AVS_TIME_MS);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds, 1234567);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds,
                          898000000);
    duration = avs_time_duration_from_scalar(-1234567898L, AVS_TIME_MS);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, -1234568);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 102000000);
    realtime = avs_time_real_from_scalar(1234567898L, AVS_TIME_S);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, 1234567898L);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 0);
    monotonic = avs_time_monotonic_from_scalar(-1234567898L, AVS_TIME_S);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds,
                          -1234567898L);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds, 0);
    duration = avs_time_duration_from_scalar(1234567898L, AVS_TIME_MIN);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 74074073880L);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 0);
    realtime = avs_time_real_from_scalar(-1234567898L, AVS_TIME_MIN);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, -74074073880L);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 0);
    monotonic = avs_time_monotonic_from_scalar(1234567898L, AVS_TIME_HOUR);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds,
                          4444444432800L);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds, 0);
    duration = avs_time_duration_from_scalar(-1234567898L, AVS_TIME_HOUR);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, -4444444432800L);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 0);
    realtime = avs_time_real_from_scalar(1234567898L, AVS_TIME_DAY);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, 106666666387200L);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 0);
    monotonic = avs_time_monotonic_from_scalar(-1234567898L, AVS_TIME_DAY);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds,
                          -106666666387200L);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds, 0);
}

AVS_UNIT_TEST(time, time_from_fscalar) {
    avs_time_real_t realtime =
            avs_time_real_from_fscalar(1234567898.7654321, AVS_TIME_NS);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, 1);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 234567898);
    avs_time_monotonic_t monotonic =
            avs_time_monotonic_from_fscalar(-1234567898.7654321, AVS_TIME_NS);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds, -2);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds,
                          765432102);
    avs_time_duration_t duration =
            avs_time_duration_from_fscalar(1234567898.7654321, AVS_TIME_US);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 1234);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 567898765);
    realtime = avs_time_real_from_fscalar(-1234567898.7654321, AVS_TIME_US);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, -1235);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 432101235);
    monotonic =
            avs_time_monotonic_from_fscalar(1234567898.7654321, AVS_TIME_MS);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds, 1234567);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds,
                          898765432);
    duration = avs_time_duration_from_fscalar(-1234567898.7654321, AVS_TIME_MS);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, -1234568);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 101234568);
    realtime = avs_time_real_from_fscalar(1234567898.7654321, AVS_TIME_S);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, 1234567898L);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 765432119);
    monotonic =
            avs_time_monotonic_from_fscalar(-1234567898.7654321, AVS_TIME_S);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds,
                          -1234567899L);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds,
                          234567881);
    duration = avs_time_duration_from_fscalar(1234567898.7654321, AVS_TIME_MIN);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 74074073925L);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 925927162);
    realtime = avs_time_real_from_fscalar(-1234567898.7654321, AVS_TIME_MIN);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, -74074073926L);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 74072838);
    monotonic =
            avs_time_monotonic_from_fscalar(1234567898.7654321, AVS_TIME_HOUR);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds,
                          4444444435555L);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds,
                          555324554);
    duration =
            avs_time_duration_from_fscalar(-1234567898.7654321, AVS_TIME_HOUR);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, -4444444435556L);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 444675446);
    realtime = avs_time_real_from_fscalar(1234567898.7654321, AVS_TIME_DAY);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.seconds, 106666666453333L);
    AVS_UNIT_ASSERT_EQUAL(realtime.since_real_epoch.nanoseconds, 329589843);
    monotonic =
            avs_time_monotonic_from_fscalar(-1234567898.7654321, AVS_TIME_DAY);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.seconds,
                          -106666666453334L);
    AVS_UNIT_ASSERT_EQUAL(monotonic.since_monotonic_epoch.nanoseconds,
                          670410157);
}

AVS_UNIT_TEST(time, time_to_scalar_overflow) {
    int64_t result;
    avs_time_duration_t duration =
            avs_time_duration_from_scalar(INT64_MAX, AVS_TIME_NS);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_time_duration_to_scalar(&result, AVS_TIME_NS, duration));
    AVS_UNIT_ASSERT_EQUAL(result, INT64_MAX);
    ++duration.nanoseconds;
    AVS_UNIT_ASSERT_TRUE(avs_time_duration_valid(duration));
    AVS_UNIT_ASSERT_FAILED(
            avs_time_duration_to_scalar(&result, AVS_TIME_NS, duration));

    duration = avs_time_duration_from_scalar(INT64_MIN, AVS_TIME_NS);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_time_duration_to_scalar(&result, AVS_TIME_NS, duration));
    AVS_UNIT_ASSERT_EQUAL(result, INT64_MIN);
    --duration.nanoseconds;
    AVS_UNIT_ASSERT_TRUE(avs_time_duration_valid(duration));
    AVS_UNIT_ASSERT_FAILED(
            avs_time_duration_to_scalar(&result, AVS_TIME_NS, duration));
}

AVS_UNIT_TEST(time, time_mul) {
    avs_time_duration_t duration =
            avs_time_duration_mul((avs_time_duration_t) { 42, 987654321 }, 514);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 22095);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 654320994);

    duration = avs_time_duration_mul((avs_time_duration_t) { 42, 987654321 },
                                     -514);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, -22096);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 345679006);

    duration =
            avs_time_duration_mul((avs_time_duration_t) { -43, 12345679 }, 514);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, -22096);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 345679006);

    duration = avs_time_duration_mul((avs_time_duration_t) { INT64_MIN, 0 }, 0);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 0);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 0);

    duration = avs_time_duration_mul((avs_time_duration_t) { INT64_MIN, 0 }, 1);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, INT64_MIN);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 0);

    duration = avs_time_duration_mul((avs_time_duration_t) { INT64_MIN / 2, 0 },
                                     2);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, INT64_MIN);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 0);

    duration = avs_time_duration_mul((avs_time_duration_t) { INT64_MIN + 1, 0 },
                                     2);
    AVS_UNIT_ASSERT_FALSE(avs_time_duration_valid(duration));

    duration = avs_time_duration_mul(
            (avs_time_duration_t) { INT64_MAX / 2, 999999999 }, 2);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, INT64_MAX);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 999999998);

    duration = avs_time_duration_mul(
            (avs_time_duration_t) { INT64_MAX / 2 + 1, 0 }, 2);
    AVS_UNIT_ASSERT_FALSE(avs_time_duration_valid(duration));
}

AVS_UNIT_TEST(time, fmul) {
    avs_time_duration_t duration =
            avs_time_duration_fmul((avs_time_duration_t) { 123, 456789876 },
                                   1.5);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 185);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 185184814);

    duration = avs_time_duration_fmul((avs_time_duration_t) { -124, 543210124 },
                                      1.5);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, -186);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 814815186);

    duration = avs_time_duration_fmul((avs_time_duration_t) { 123, 456789876 },
                                      -1.5);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, -186);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 814815186);

    duration = avs_time_duration_fmul((avs_time_duration_t) { -124, 543210124 },
                                      -1.5);
    AVS_UNIT_ASSERT_EQUAL(duration.seconds, 185);
    AVS_UNIT_ASSERT_EQUAL(duration.nanoseconds, 185184814);
}

AVS_UNIT_TEST(time, div) {
    avs_time_duration_t value = { 1, 10 };
    value = avs_time_duration_div(value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.seconds, 0);
    AVS_UNIT_ASSERT_EQUAL(value.nanoseconds, 500 * 1000 * 1000 + 5);
}

AVS_UNIT_TEST(time, div_s_rest) {
    avs_time_duration_t value = { 3, 500 * 1000 * 1000 };
    value = avs_time_duration_div(value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.seconds, 1);
    AVS_UNIT_ASSERT_EQUAL(value.nanoseconds, 750 * 1000 * 1000);
}

AVS_UNIT_TEST(time, div_big_divisor) {
    avs_time_duration_t value = { 1, 0 };
    value = avs_time_duration_div(value, 1 * 1000 * 1000 * 1000);
    AVS_UNIT_ASSERT_EQUAL(value.seconds, 0);
    AVS_UNIT_ASSERT_EQUAL(value.nanoseconds, 1);
}

AVS_UNIT_TEST(time, div_big_seconds) {
    avs_time_duration_t value = { 999 * 1000 * 1000, 0 };
    value = avs_time_duration_div(value, 1 * 1000 * 1000 * 1000);
    AVS_UNIT_ASSERT_EQUAL(value.seconds, 0);
    AVS_UNIT_ASSERT_EQUAL(value.nanoseconds, 999 * 1000 * 1000);
}

AVS_UNIT_TEST(time, div_negative) {
    avs_time_duration_t value = { -1, 0 };
    value = avs_time_duration_div(value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.seconds, -1);
    AVS_UNIT_ASSERT_EQUAL(value.nanoseconds, 500 * 1000 * 1000);
}

AVS_UNIT_TEST(time, div_negative_ns) {
    avs_time_duration_t value = { -1, 500 * 1000 * 1000 };
    value = avs_time_duration_div(value, 2);
    AVS_UNIT_ASSERT_EQUAL(value.seconds, -1);
    AVS_UNIT_ASSERT_EQUAL(value.nanoseconds, 750 * 1000 * 1000);
}

AVS_UNIT_TEST(time, div_big_negative) {
    avs_time_duration_t value = { -999 * 1000 * 1000, 0 };
    value = avs_time_duration_div(value, 1 * 1000 * 1000 * 1000);
    AVS_UNIT_ASSERT_EQUAL(value.seconds, -1);
    AVS_UNIT_ASSERT_EQUAL(value.nanoseconds, 1 * 1000 * 1000);
}

AVS_UNIT_TEST(time, duration_as_string) {
    avs_time_duration_t value = { 123, 456 };
    AVS_UNIT_ASSERT_EQUAL_STRING(AVS_TIME_DURATION_AS_STRING(value),
                                 "123.000000456");
}

AVS_UNIT_TEST(time, negative_duration_as_string) {
    avs_time_duration_t value = { -123, 456 };
    AVS_UNIT_ASSERT_EQUAL_STRING(AVS_TIME_DURATION_AS_STRING(value),
                                 "-122.999999544");
}
