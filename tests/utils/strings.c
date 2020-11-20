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

AVS_UNIT_TEST(int_as_string, minus_one) {
    AVS_UNIT_ASSERT_EQUAL_STRING(
            int64_as_string_custom(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, -1),
            "-1");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            avs_int64_as_string_impl__(
                    &(char[AVS_UINT_STR_BUF_SIZE(uint64_t)]){ "" }, -1),
            "-1");
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

static const char *double_as_string_custom_wrapper(char (*buf)[32],
                                                   double value,
                                                   uint8_t precision) {
    assert(precision >= 1);
    assert(precision <= 18);
    int result = double_as_string_custom(*buf, sizeof(*buf), value, precision);
    assert(result >= 0);
    (void) result;
    return *buf;
}

#define DOUBLE_AS_STRING_CUSTOM(Value, Precision) \
    double_as_string_custom_wrapper(&(char[32]){ "" }, (Value), (Precision))

// DBL_TRUE_MIN is new in C11, let's define it for older standards
#ifndef DBL_TRUE_MIN
#    define DBL_TRUE_MIN ((double) 4.94065645841246544176568792868221372e-324L)
#endif

AVS_UNIT_TEST(double_as_string, simple) {
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0, 6), "1");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(42.0, 6), "42");
    // NOTE: truncated trailing zeros:
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(73.12, 6), "73.12");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1e10, 6), "1e+10");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.1e-4, 6), "0.00011");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1e-4, 6), "1e-4");
}

AVS_UNIT_TEST(double_as_string, specials_and_limits) {
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(0.0, 18), "0");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(NAN, 18), "nan");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(INFINITY, 18), "inf");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-INFINITY, 18),
                                 "-inf");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_MAX, 1), "2e+308");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_MAX, 6),
                                 "1.79769e+308");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_MAX, 18),
                                 "1.79769313486231552e+308");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 + DBL_EPSILON, 1),
                                 "1");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 + DBL_EPSILON, 16),
                                 "1");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 + DBL_EPSILON, 17),
                                 "1.0000000000000002");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 + DBL_EPSILON, 18),
                                 "1.00000000000000016");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 - DBL_EPSILON, 1),
                                 "1");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 - DBL_EPSILON, 15),
                                 "1");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 - DBL_EPSILON, 16),
                                 "0.9999999999999998");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 - DBL_EPSILON, 17),
                                 "0.99999999999999984");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(1.0 - DBL_EPSILON, 18),
                                 "0.999999999999999744");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_MIN, 1), "2e-308");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_MIN, 6),
                                 "2.22507e-308");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_MIN, 18),
                                 "2.22507385850720128e-308");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_TRUE_MIN, 1),
                                 "5e-324");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_TRUE_MIN, 6),
                                 "4.94066e-324");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(DBL_TRUE_MIN, 18),
                                 "4.94065645841246528e-324");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_MAX, 1),
                                 "-2e+308");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_MAX, 6),
                                 "-1.79769e+308");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_MAX, 18),
                                 "-1.79769313486231552e+308");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-1.0 - DBL_EPSILON, 1),
                                 "-1");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(-1.0 - DBL_EPSILON, 16), "-1");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-1.0 - DBL_EPSILON,
                                                         17),
                                 "-1.0000000000000002");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-1.0 - DBL_EPSILON,
                                                         18),
                                 "-1.00000000000000016");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-1.0 + DBL_EPSILON, 1),
                                 "-1");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(-1.0 + DBL_EPSILON, 15), "-1");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-1.0 + DBL_EPSILON,
                                                         16),
                                 "-0.9999999999999998");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-1.0 + DBL_EPSILON,
                                                         17),
                                 "-0.99999999999999984");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-1.0 + DBL_EPSILON,
                                                         18),
                                 "-0.999999999999999744");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_MIN, 1),
                                 "-2e-308");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_MIN, 6),
                                 "-2.22507e-308");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_MIN, 18),
                                 "-2.22507385850720128e-308");

    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_TRUE_MIN, 1),
                                 "-5e-324");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_TRUE_MIN, 6),
                                 "-4.94066e-324");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(-DBL_TRUE_MIN, 18),
                                 "-4.94065645841246528e-324");
}

AVS_UNIT_TEST(double_as_string, pi_precision) {
    const double PI = 3.14159265358979323846;
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 1), "3");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 2), "3.1");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 3), "3.14");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 4), "3.142");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 5), "3.1416");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 6), "3.14159");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 7), "3.141593");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 8), "3.1415927");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 9), "3.14159265");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 10),
                                 "3.141592654");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 11),
                                 "3.1415926536");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 12),
                                 "3.14159265359");
    // NOTE: trailing zero trimmed in the case of precision == 13
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 13),
                                 "3.14159265359");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 14),
                                 "3.1415926535898");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 15),
                                 "3.14159265358979");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 16),
                                 "3.141592653589793");
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 17),
                                 "3.1415926535897932");
    // NOTE: representation with precision == 18 is inaccurate
    AVS_UNIT_ASSERT_EQUAL_STRING(DOUBLE_AS_STRING_CUSTOM(PI, 18),
                                 "3.14159265358979328");
}

AVS_UNIT_TEST(double_as_string, pi_exp_positive) {
    // NOTE: representations in this function are innacurate
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+1, 18),
            "31.4159265358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+2, 18),
            "314.159265358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+3, 18),
            "3141.59265358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+4, 18),
            "31415.9265358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+5, 18),
            "314159.265358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+6, 18),
            "3141592.65358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+7, 18),
            "31415926.5358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+8, 18),
            "314159265.358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+9, 18),
            "3141592653.58979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+10, 18),
            "31415926535.8979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+11, 18),
            "314159265358.979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+12, 18),
            "3141592653589.79328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+13, 18),
            "31415926535897.9328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+14, 18),
            "314159265358979.328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+15, 18),
            "3141592653589793.28");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+16, 18),
            "31415926535897932.8");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+17, 18),
            "314159265358979328");
    // Exponential notation kicks in here:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+18, 18),
            "3.14159265358979328e+18");
    // Let's try much higher exponents:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+180, 18),
            "3.14159265358979328e+180");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+299, 18),
            "3.14159265358979328e+299");
    // Here we lose precision:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+300, 18),
            "3.14159265358979264e+300");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+301, 18),
            "3.14159265358979328e+301");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+302, 18),
            "3.14159265358979328e+302");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+303, 18),
            "3.14159265358979328e+303");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+304, 18),
            "3.14159265358979328e+304");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+305, 18),
            "3.14159265358979328e+305");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+306, 18),
            "3.14159265358979328e+306");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+307, 18),
            "3.14159265358979328e+307");
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
    // This is too large to be representable, gets replaced by infinity:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e+308, 18), "inf");
#pragma GCC diagnostic pop
}

AVS_UNIT_TEST(double_as_string, pi_exp_negative) {
    // NOTE: representations in this function are innacurate
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-1, 18),
            "0.314159265358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-2, 18),
            "0.0314159265358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-3, 18),
            "0.00314159265358979328");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-4, 18),
            "0.000314159265358979328");
    // Exponential notation kicks in here:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-5, 18),
            "3.14159265358979328e-5");
    // Let's try much higher magnitude exponents
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-10, 18),
            "3.14159265358979328e-10");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-100, 18),
            "3.14159265358979328e-100");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-291, 18),
            "3.14159265358979328e-291");
    // From here we start needing to do the pre-conversion multiplication in
    // multiple stages because 18 - (-292) - 1 > 308 (i.e., DBL_MAX_10_EXP):
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-292, 18),
            "3.14159265358979328e-292");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-293, 18),
            "3.14159265358979328e-293");
    // Here we actually lose precision due to this two-stage multiplication:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-294, 18),
            "3.14159265358979392e-294");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-295, 18),
            "3.14159265358979328e-295");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-296, 18),
            "3.14159265358979328e-296");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-297, 18),
            "3.14159265358979328e-297");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-298, 18),
            "3.14159265358979328e-298");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-299, 18),
            "3.14159265358979328e-299");
    // Here we lose precision as well:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-300, 18),
            "3.14159265358979264e-300");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-301, 18),
            "3.14159265358979328e-301");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-302, 18),
            "3.14159265358979328e-302");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-303, 18),
            "3.14159265358979328e-303");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-304, 18),
            "3.14159265358979328e-304");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-305, 18),
            "3.14159265358979328e-305");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-306, 18),
            "3.14159265358979328e-306");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-307, 18),
            "3.14159265358979328e-307");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-308, 18),
            "3.14159265358979328e-308");
    // From here the value is a denormalized number; precision is lost
    // inherently due to smaller number of bits available:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-309, 18),
            "3.14159265358979072e-309");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-310, 18),
            "3.14159265358980608e-310");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-311, 18),
            "3.14159265358995392e-311");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-312, 18),
            "3.14159265358847168e-312");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-313, 18),
            "3.14159265358847232e-313");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-314, 18),
            "3.14159265378609792e-314");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-315, 18),
            "3.14159265329203264e-315");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-316, 18),
            "3.14159264341072e-316");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-317, 18),
            "3.14159249519102592e-317");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-318, 18),
            "3.14159051892844288e-318");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-319, 18),
            "3.14161522221073472e-319");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-320, 18),
            "3.1417634419044864e-320");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-321, 18),
            "3.14225750755032832e-321");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-322, 18),
            "3.1620201333839776e-322");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-323, 18),
            "2.96439387504747968e-323");
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-324, 18),
            "4.94065645841246528e-324");
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
    // This is too small to be representable, gets truncated to zero:
    AVS_UNIT_ASSERT_EQUAL_STRING(
            DOUBLE_AS_STRING_CUSTOM(3.14159265358979323846e-325, 18), "0");
#pragma GCC diagnostic pop
}
