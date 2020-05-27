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

#ifndef AVS_COMMONS_UNIT_TEST_H
#define AVS_COMMONS_UNIT_TEST_H

#include <setjmp.h>

#if __STDC_VERSION__ >= 199901L
#    include <stdbool.h>
#    define AVS_UNIT_HAVE_BOOL__
#elif defined(__cplusplus)
#    define AVS_UNIT_HAVE_BOOL__
#endif

#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_errno.h>
#ifdef AVS_COMMONS_WITH_AVS_LIST
#    include <avsystem/commons/avs_list.h>
#endif // AVS_COMMONS_WITH_AVS_LIST

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file avs_test.h
 *
 * This file allows implementing unit tests that will be automatically executed
 * by the <c>avs_unit</c> library.
 *
 * The preferred way to write unit test is to add a similar code snippet at the
 * end of each file to be tested:
 *
 * @code
 * #ifdef UNIT_TESTING
 * #include "file_with_tests.c"
 * #endif
 * @endcode
 *
 * Then, when defining compilation rules for your tests, define
 * <c>UNIT_TESTING</c> (or other macro of your preference) from the compiler
 * command line.
 *
 * This way, the testing code will have access to the static functions of the
 * code under test.
 *
 * See also <c>mock_helpers.h</c> for features to mock function calls.
 *
 * The library contains a <c>main()</c> function, so the testing code shall not
 * include one. It relies on GCC-specific features to automatically discover and
 * execute test cases.
 *
 * The testing binary may be invoked with up to two optional arguments,
 * specifying the test suite and test case names, respectively. It can also
 * include the {{-v}} or {{--verbose}} option repeated any number of times, each
 * increasing the verbosity level.
 *
 * Any verbosity level higher than 0 will cause additional information about
 * each test case to be printed. The verbosity level will also be passed to
 * user-defined initialization functions, if any.
 *
 * <example>
 * @code
 * //// file_under_test.c ////
 *
 * int square(int arg) {
 *     return arg * arg;
 * }
 *
 * void uppercase(char *input) {
 *     for (; input && *input; ++input) {
 *         if (*input >= 'a' && *input < 'z') { // <-- bug! :-E
 *             *input += 'A' - 'a';
 *         }
 *     }
 * }
 *
 * #ifdef UNIT_TESTING
 * #include "test_file.c"
 * #endif
 * @endcode
 *
 * @code
 * //// test_file.c ////
 * #include <avsystem/commons/avs_unit_test.h>
 *
 * AVS_UNIT_TEST(square, small_numbers) {
 *     AVS_UNIT_ASSERT_EQUAL(square(2), 4);
 *     AVS_UNIT_ASSERT_EQUAL(square(5), 25);
 * }
 *
 * AVS_UNIT_TEST(uppercase, hello) {
 *     char input[] = "Hello, world123!";
 *     uppercase(input);
 *     AVS_UNIT_ASSERT_EQUAL_STRING(input, "HELLO, WORLD123!");
 * }
 *
 * AVS_UNIT_TEST(uppercase, zanzibar) {
 *     char input[] = "Zanzibar";
 *     uppercase(input);
 *     AVS_UNIT_ASSERT_EQUAL_STRING(input, "ZANZIBAR");
 * }
 * @endcode
 *
 * Compilation and execution:
 * @code
 * $ cc -DUNIT_TESTING file_under_test.c -lavs_unit -lavs_list -o test
 * $ ./test
 * square                                                           1/1
 * [test_file.c:18] expected <ZANZIBAR> was <ZANzIBAR>
 *     zanzibar                                                     FAIL
 * uppercase                                                        1/2
 * @endcode
 * </example>
 */

/**
 * Internal functions used by the library to implement the functionality.
 */
/**@{*/
typedef void (*avs_unit_init_function_t)(int verbose);
typedef void (*avs_unit_test_function_t)(void);

void avs_unit_add_global_init__(avs_unit_init_function_t init_func);
void avs_unit_add_suite_init__(const char *suite_name,
                               avs_unit_init_function_t init_func);
void avs_unit_add_test__(const char *suite_name,
                         const char *name,
                         avs_unit_test_function_t test);
void avs_unit_assert_avs_ok__(avs_error_t err, const char *file, int line);
void avs_unit_assert_success__(int result, const char *file, int line);
void avs_unit_assert_avs_err__(avs_error_t err, const char *file, int line);
void avs_unit_assert_failed__(int result, const char *file, int line);
void avs_unit_assert_true__(int result, const char *file, int line);
void avs_unit_assert_false__(int result, const char *file, int line);

void avs_unit_abort__(const char *msg, const char *file, int line);

void avs_unit_assert_equal_func__(int check_result,
                                  const char *actual_str,
                                  const char *expected_str,
                                  const char *file,
                                  int line);

void avs_unit_assert_not_equal_func__(int check_result,
                                      const char *actual_str,
                                      const char *not_expected_str,
                                      const char *file,
                                      int line);

void avs_unit_assert_bytes_equal__(const void *actual,
                                   const void *expected,
                                   size_t num_bytes,
                                   const char *file,
                                   int line);

void avs_unit_assert_bytes_not_equal__(const void *actual,
                                       const void *expected,
                                       size_t num_bytes,
                                       const char *file,
                                       int line);

void avs_unit_assert_equal_string__(const char *actual,
                                    const char *expected,
                                    const char *file,
                                    int line);
void avs_unit_assert_not_equal_string__(const char *actual,
                                        const char *not_expected,
                                        const char *file,
                                        int line);

void avs_unit_assert_null__(const void *pointer, const char *file, int line);

void avs_unit_assert_not_null__(const void *pointer,
                                const char *file,
                                int line);

#ifdef AVS_COMMONS_WITH_AVS_LIST
void avs_unit_assert_equal_list__(const void *actual,
                                  const void *expected,
                                  size_t element_size,
                                  avs_list_comparator_func_t comparator,
                                  const char *file,
                                  int line);
#endif // AVS_COMMONS_WITH_AVS_LIST

typedef struct {
    char actual_str[64];
    char expected_str[64];
} avs_unit_check_equal_function_strings_t;

#define AVS_UNIT_CHECK_EQUAL_FUNCTION_DECLARE__(type, name_suffix) \
    int avs_unit_check_equal_##name_suffix##__(                    \
            type actual,                                           \
            type expected,                                         \
            avs_unit_check_equal_function_strings_t *strings)

#ifdef __cplusplus
} /* extern "C" */

#    define AVS_UNIT_CHECK_EQUAL_FUNCTION__(type, name_suffix)                 \
        extern "C" AVS_UNIT_CHECK_EQUAL_FUNCTION_DECLARE__(type, name_suffix); \
        template <typename T>                                                  \
        static inline int AVS_UNIT_CHECK_EQUAL__(                              \
                type actual,                                                   \
                const T &expected,                                             \
                avs_unit_check_equal_function_strings_t *strings) {            \
            return avs_unit_check_equal_##name_suffix##__(                     \
                    actual, expected, strings);                                \
        }

#else /* __cplusplus */
#    define AVS_UNIT_CHECK_EQUAL_FUNCTION__(type, name_suffix) \
        AVS_UNIT_CHECK_EQUAL_FUNCTION_DECLARE__(type, name_suffix);

#    ifdef AVS_UNIT_HAVE_BOOL__
#        define AVS_UNIT_CHECK_BOOL__(actual, expected, strings, inner)     \
            __builtin_choose_expr(                                          \
                    __builtin_types_compatible_p(__typeof__(actual), bool), \
                    avs_unit_check_equal_i__(                               \
                            (int) (actual), (int) (expected), (strings)),   \
                    inner)
#    else
#        define AVS_UNIT_CHECK_BOOL__(actual, expected, strings, inner) inner
#    endif

// clang-format off
#define AVS_UNIT_CHECK_EQUAL__(actual, expected, strings)\
AVS_UNIT_CHECK_BOOL__(actual, expected, strings,\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), char),\
    avs_unit_check_equal_c__((char) (actual), (char) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), signed char),\
    avs_unit_check_equal_sc__((signed char) (actual), (signed char) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), short),\
    avs_unit_check_equal_s__((short) (actual), (short) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), int),\
    avs_unit_check_equal_i__((int) (actual), (int) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), long),\
    avs_unit_check_equal_l__((long) (actual), (long) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), long long),\
    avs_unit_check_equal_ll__((long long) (actual), (long long) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), unsigned char),\
    avs_unit_check_equal_uc__((unsigned char) (actual), (unsigned char) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), unsigned short),\
    avs_unit_check_equal_us__((unsigned short) (actual), (unsigned short) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), unsigned int),\
    avs_unit_check_equal_ui__((unsigned int) (actual), (unsigned int) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), unsigned long),\
    avs_unit_check_equal_ul__((unsigned long) (actual), (unsigned long) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), unsigned long long),\
    avs_unit_check_equal_ull__((unsigned long long) (actual), (unsigned long long) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), float),\
    avs_unit_check_equal_f__((float) (actual), (float) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), double),\
    avs_unit_check_equal_d__((double) (actual), (double) (expected), (strings)),\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), long double),\
    avs_unit_check_equal_ld__((long double) (actual), (long double) (expected), (strings)),\
    avs_unit_abort__("AVS_UNIT_ASSERT_EQUAL called for unsupported data type\n", __FILE__, __LINE__)\
)))))))))))))))
// clang-format on
#endif /* __cplusplus */

AVS_UNIT_CHECK_EQUAL_FUNCTION__(char, c)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(signed char, sc)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(short, s)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(int, i)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long, l)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long long, ll)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned char, uc)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned short, us)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned int, ui)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned long, ul)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned long long, ull)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(float, f)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(double, d)
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long double, ld)

#define AVS_UNIT_ASSERT_EQUAL_BYTES__(actual, expected)                      \
    __builtin_choose_expr(                                                   \
            __builtin_types_compatible_p(__typeof__(expected), const char[]) \
                    || __builtin_types_compatible_p(__typeof__(expected),    \
                                                    char[]),                 \
            avs_unit_assert_bytes_equal__((actual),                          \
                                          (expected),                        \
                                          sizeof(expected) - 1,              \
                                          __FILE__,                          \
                                          __LINE__),                         \
            avs_unit_abort__("AVS_UNIT_ASSERT_EQUAL_BYTES called for "       \
                             "unsupported data type\n",                      \
                             __FILE__,                                       \
                             __LINE__))

#define AVS_UNIT_ASSERT_NOT_EQUAL_BYTES__(actual, expected)                  \
    __builtin_choose_expr(                                                   \
            __builtin_types_compatible_p(__typeof__(expected), const char[]) \
                    || __builtin_types_compatible_p(__typeof__(expected),    \
                                                    char[]),                 \
            avs_unit_assert_bytes_not_equal__((actual),                      \
                                              (expected),                    \
                                              sizeof(expected) - 1,          \
                                              __FILE__,                      \
                                              __LINE__),                     \
            avs_unit_abort__("AVS_UNIT_ASSERT_NOT_EQUAL_BYTES called for "   \
                             "unsupported data type\n",                      \
                             __FILE__,                                       \
                             __LINE__))
/**@}*/

/**
 * Defines a global initialization function.
 *
 * The function defined will be executed once, at the start of test binary
 * execution process.
 *
 * <example>
 * @code
 * AVS_UNIT_GLOBAL_INIT(verbose_level) {
 *     if (!verbose_level) {
 *         disable_my_logger();
 *     }
 * }
 * @endcode
 * </example>
 *
 * @param VERBOSE_VAR Name of a verbosity level variable (of type <c>int</c>).
 */
#define AVS_UNIT_GLOBAL_INIT(VERBOSE_VAR)                                      \
    static void AVS_CONCAT(_avs_unit_global_init_, __LINE__)(int VERBOSE_VAR); \
    void AVS_CONCAT(_avs_unit_global_init_constructor_, __LINE__)(void)        \
            __attribute__((constructor));                                      \
    void AVS_CONCAT(_avs_unit_global_init_constructor_, __LINE__)(void) {      \
        avs_unit_add_global_init__(                                            \
                AVS_CONCAT(_avs_unit_global_init_, __LINE__));                 \
    }                                                                          \
    static void AVS_CONCAT(_avs_unit_global_init_, __LINE__)(int VERBOSE_VAR)

/**
 * Defines a suite initialization function.
 *
 * The function defined will be executed once, at the start of test suite
 * execution process.
 *
 * @param suite       Name of the test suite.
 *
 * @param VERBOSE_VAR Name of a verbosity level variable (of type <c>int</c>).
 */
#define AVS_UNIT_SUITE_INIT(suite, VERBOSE_VAR)                             \
    static void AVS_CONCAT(_avs_unit_suite_init_, suite, _, __LINE__)(      \
            int VERBOSE_VAR);                                               \
    void AVS_CONCAT(_avs_unit_suite_init_constructor_, suite, _, __LINE__)( \
            void) __attribute__((constructor));                             \
    void AVS_CONCAT(_avs_unit_suite_init_constructor_, suite, _, __LINE__)( \
            void) {                                                         \
        avs_unit_add_suite_init__(                                          \
                #suite,                                                     \
                AVS_CONCAT(_avs_unit_suite_init_, suite, _, __LINE__));     \
    }                                                                       \
    static void AVS_CONCAT(_avs_unit_suite_init_, suite, _, __LINE__)(      \
            int VERBOSE_VAR)

/**
 * Defines a unit test case.
 *
 * <example>
 * @code
 * AVS_UNIT_TEST(module1, fancy_func) {
 *     AVS_UNIT_ASSERT_SUCCESS(fancy_func(123));
 *     AVS_UNIT_ASSERT_FAILED(fancy_func(-1));
 * }
 * @endcode
 * </example>
 *
 * @param suite Name of the test suite.
 *
 * @param name  Name of the test case.
 */
#define AVS_UNIT_TEST(suite, name)                                           \
    static void _avs_unit_test_##suite##_##name(void);                       \
    void _avs_unit_test_constructor_##suite##_##name(void)                   \
            __attribute__((constructor));                                    \
    void _avs_unit_test_constructor_##suite##_##name(void) {                 \
        avs_unit_add_test__(#suite, #name, _avs_unit_test_##suite##_##name); \
    }                                                                        \
    static void _avs_unit_test_##suite##_##name(void)

/**
 * Assertions.
 */
/**@{*/

/**
 * Asserts that the specified value is 0.
 *
 * It is intended to check for successful function return values.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param result Value to check.
 */
#ifndef __cplusplus
#    define AVS_UNIT_ASSERT_SUCCESS(result)                                    \
        __builtin_choose_expr(                                                 \
                __builtin_types_compatible_p(__typeof__(result), avs_error_t), \
                avs_unit_assert_avs_ok__,                                      \
                avs_unit_assert_success__)((result), __FILE__, __LINE__)
#else // __cplusplus
// overloaded variant
static inline void
avs_unit_assert_success__(avs_error_t err, const char *file, int line) {
    return avs_unit_assert_avs_ok__(err, file, line);
}

#    define AVS_UNIT_ASSERT_SUCCESS(result) \
        avs_unit_assert_success__((result), __FILE__, __LINE__)
#endif // __cplusplus

/**
 * Asserts that the specified value is not 0.
 *
 * It is intended to check for unsuccessful function return values.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param result Value to check.
 */
#ifndef __cplusplus
#    define AVS_UNIT_ASSERT_FAILED(result)                                     \
        __builtin_choose_expr(                                                 \
                __builtin_types_compatible_p(__typeof__(result), avs_error_t), \
                avs_unit_assert_avs_err__,                                     \
                avs_unit_assert_failed__)((result), __FILE__, __LINE__)
#else // __cplusplus
// overloaded variant
static inline void
avs_unit_assert_failed__(avs_error_t err, const char *file, int line) {
    return avs_unit_assert_avs_ok__(err, file, line);
}

#    define AVS_UNIT_ASSERT_FAILED(result) \
        avs_unit_assert_failed__((result), __FILE__, __LINE__)
#endif // __cplusplus

/**
 * Asserts that the specified value is not 0.
 *
 * It is intended to check for conceptually boolean values.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param result Value to check.
 */
#define AVS_UNIT_ASSERT_TRUE(result) \
    avs_unit_assert_true__((int) (result), __FILE__, __LINE__)

/**
 * Asserts that the specified value is not 0.
 *
 * It is intended to check for conceptually boolean values.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param result Value to check.
 */
#define AVS_UNIT_ASSERT_FALSE(result) \
    avs_unit_assert_false__((int) (result), __FILE__, __LINE__)

/**
 * Asserts that the two specified values are equal.
 *
 * All integer and floating-point types are supported.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual   The value returned from code under test.
 *
 * @param expected The expected value to compare with.
 */
#define AVS_UNIT_ASSERT_EQUAL(actual, expected)                     \
    do {                                                            \
        avs_unit_check_equal_function_strings_t strings;            \
        avs_unit_assert_equal_func__(                               \
                AVS_UNIT_CHECK_EQUAL__(actual, expected, &strings), \
                strings.actual_str,                                 \
                strings.expected_str,                               \
                __FILE__,                                           \
                __LINE__);                                          \
    } while (0)

/**
 * Asserts that corresponding fields in two specified structures are equal.
 *
 * The same types as for @ref AVS_UNIT_ASSERT_EQUAL are supported.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST
 *
 * @param actual_struct_ptr   Pointer to structure containing actual value.
 *
 * @param expected_struct_ptr Pointer to structure containing expected value.
 *
 * @param field               Name of the structure field to compare.
 */
#define AVS_UNIT_ASSERT_FIELD_EQUAL(                                          \
        actual_struct_ptr, expected_struct_ptr, field)                        \
    __builtin_choose_expr(                                                    \
            __builtin_types_compatible_p(__typeof__(*(actual_struct_ptr)),    \
                                         __typeof__(*(expected_struct_ptr))), \
            ({                                                                \
                AVS_UNIT_ASSERT_EQUAL((actual_struct_ptr)->field,             \
                                      (expected_struct_ptr)->field);          \
            }),                                                               \
            avs_unit_abort__("AVS_UNIT_ASSERT_FIELD_EQUAL called for "        \
                             "different types\n",                             \
                             __FILE__,                                        \
                             __LINE__))

/**
 * Asserts that the two specified values are not equal.
 *
 * All integer and floating-point types are supported.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual       The value returned from code under test.
 *
 * @param not_expected The value to compare with, that is expected not to be
 *                     returned.
 */
#define AVS_UNIT_ASSERT_NOT_EQUAL(actual, not_expected)                 \
    do {                                                                \
        avs_unit_check_equal_function_strings_t strings;                \
        avs_unit_assert_not_equal_func__(                               \
                AVS_UNIT_CHECK_EQUAL__(actual, not_expected, &strings), \
                strings.actual_str,                                     \
                strings.expected_str,                                   \
                __FILE__,                                               \
                __LINE__);                                              \
    } while (0)

/**
 * Asserts that corresponding fields in two specified structures are not equal.
 *
 * The same types as for @ref AVS_UNIT_ASSERT_NOT_EQUAL are supported.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST
 *
 * @param actual_struct_ptr   Pointer to structure containing actual value.
 *
 * @param expected_struct_ptr Pointer to structure containing expected value.
 *
 * @param field               Name of the structure field to compare.
 */
#define AVS_UNIT_ASSERT_FIELD_NOT_EQUAL(                                      \
        actual_struct_ptr, expected_struct_ptr, field)                        \
    __builtin_choose_expr(                                                    \
            __builtin_types_compatible_p(__typeof__(*(actual_struct_ptr)),    \
                                         __typeof__(*(expected_struct_ptr))), \
            ({                                                                \
                AVS_UNIT_ASSERT_NOT_EQUAL((actual_struct_ptr)->field,         \
                                          (expected_struct_ptr)->field);      \
            }),                                                               \
            avs_unit_abort__("AVS_UNIT_ASSERT_FIELD_NOT_EQUAL called for "    \
                             "different types\n",                             \
                             __FILE__,                                        \
                             __LINE__))

/**
 * Asserts that two specified string values are equal.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual   The value returned from code under test.
 *
 * @param expected The expected value to compare with.
 */
#define AVS_UNIT_ASSERT_EQUAL_STRING(actual, expected) \
    avs_unit_assert_equal_string__(actual, expected, __FILE__, __LINE__)

/**
 * Asserts that two specified string values are not equal.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual       The value returned from code under test.
 *
 * @param not_expected The expected value to compare with.
 */
#define AVS_UNIT_ASSERT_NOT_EQUAL_STRING(actual, not_expected) \
    avs_unit_assert_not_equal_string__(actual, not_expected, __FILE__, __LINE__)

/**
 * Asserts that two buffers contain same data.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual    The value returned from code under test.
 *
 * @param expected  A null-terminated string literal which contents will be
 *                  compared to the @p actual. Its length determines number of
 *                  bytes to compare. Note: the trailing NULL character is NOT
 *                  considered a part of the string, i.e. only
 *                  (sizeof(expected) - 1) bytes are compared.
 */
#define AVS_UNIT_ASSERT_EQUAL_BYTES(actual, expected) \
    AVS_UNIT_ASSERT_EQUAL_BYTES__(actual, expected)

/**
 * Asserts that two buffers contain same data.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual    The value returned from code under test.
 *
 * @param expected  The expected value to compare with.
 *
 * @param num_bytes Number of bytes in each buffer.
 */
#define AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(actual, expected, num_bytes) \
    avs_unit_assert_bytes_equal__(                                     \
            actual, expected, num_bytes, __FILE__, __LINE__)

/**
 * Asserts that two buffers contain different data.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual    The value returned from code under test.
 *
 * @param expected  A null-terminated string literal which contents will be
 *                  compared to the @p actual. Its length determines number of
 *                  bytes to compare. Note: the trailing NULL character is NOT
 *                  considered a part of the string, i.e. only
 *                  (sizeof(expected) - 1) bytes are compared.
 */
#define AVS_UNIT_ASSERT_NOT_EQUAL_BYTES(actual, expected) \
    AVS_UNIT_ASSERT_NOT_EQUAL_BYTES__(actual, expected)

/**
 * Asserts that two buffers contain different data.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual    The value returned from code under test.
 *
 * @param expected  The expected value to compare with.
 *
 * @param num_bytes Number of bytes in each buffer.
 */
#define AVS_UNIT_ASSERT_NOT_EQUAL_BYTES_SIZED(actual, expected, num_bytes) \
    avs_unit_assert_bytes_not_equal__(                                     \
            actual, expected, num_bytes, __FILE__, __LINE__)

/**
 * Asserts that the specified pointer is <c>NULL</c>.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param pointer Value to check.
 */
#define AVS_UNIT_ASSERT_NULL(pointer) \
    avs_unit_assert_null__(pointer, __FILE__, __LINE__)

/**
 * Asserts that the specified pointer is not <c>NULL</c>.
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param pointer Value to check.
 */
#define AVS_UNIT_ASSERT_NOT_NULL(pointer) \
    avs_unit_assert_not_null__(pointer, __FILE__, __LINE__)

/**@}*/

#ifdef AVS_COMMONS_WITH_AVS_LIST

/**
 * Asserts that two specified lists are equal. Must not be called on lists
 * containing elements of different types!
 *
 * This macro shall be called from unit test cases defined in
 * @ref AVS_UNIT_TEST.
 *
 * @param actual       The list returned from code under test.
 *
 * @param expected     The expected list to compare with.
 *
 * @param element_size The size in bytes of a single element.
 *
 * @param comparator   A function for comparing pair of two elements. Must
 *                     return 0 for a pair of equal elements.
 */
#    define AVS_UNIT_ASSERT_EQUAL_LIST(                 \
            actual, expected, element_size, comparator) \
        avs_unit_assert_equal_list__(actual,            \
                                     expected,          \
                                     element_size,      \
                                     comparator,        \
                                     __FILE__,          \
                                     __LINE__)
#endif // AVS_COMMONS_WITH_AVS_LIST

/**
 * Convenience aliases for assert macros.
 *
 * To avoid collisions with existing ASSERT_ macros, tests must explicitly
 * define @ref AVS_UNIT_ENABLE_SHORT_ASSERTS before including this header.
 *
 * @{
 */
#ifdef AVS_UNIT_ENABLE_SHORT_ASSERTS
#    define ASSERT_OK AVS_UNIT_ASSERT_SUCCESS
#    define ASSERT_FAIL AVS_UNIT_ASSERT_FAILED

#    define ASSERT_TRUE AVS_UNIT_ASSERT_TRUE
#    define ASSERT_FALSE AVS_UNIT_ASSERT_FALSE

#    define ASSERT_EQ AVS_UNIT_ASSERT_EQUAL
#    define ASSERT_NE AVS_UNIT_ASSERT_NOT_EQUAL

#    define ASSERT_FIELD_EQ AVS_UNIT_ASSERT_FIELD_EQUAL
#    define ASSERT_FIELD_NE AVS_UNIT_ASSERT_FIELD_NOT_EQUAL

#    define ASSERT_EQ_STR AVS_UNIT_ASSERT_EQUAL_STRING
#    define ASSERT_NE_STR AVS_UNIT_ASSERT_NOT_EQUAL_STRING

#    define ASSERT_EQ_BYTES AVS_UNIT_ASSERT_EQUAL_BYTES
#    define ASSERT_NE_BYTES AVS_UNIT_ASSERT_NOT_EQUAL_BYTES

#    define ASSERT_EQ_BYTES_SIZED AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED
#    define ASSERT_NE_BYTES_SIZED AVS_UNIT_ASSERT_NOT_EQUAL_BYTES_SIZED

#    define ASSERT_NULL AVS_UNIT_ASSERT_NULL
#    define ASSERT_NOT_NULL AVS_UNIT_ASSERT_NOT_NULL

#    ifdef AVS_COMMONS_WITH_AVS_LIST
#        define ASSERT_EQ_LIST AVS_UNIT_ASSERT_EQUAL_LIST
#    endif // AVS_COMMONS_WITH_AVS_LIST

#endif // AVS_UNIT_ENABLE_SHORT_ASSERTS
/* @} */

#endif /* AVS_COMMONS_UNIT_TEST_H */
