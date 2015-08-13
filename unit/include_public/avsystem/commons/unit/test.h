/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_UNIT_TEST_H
#define AVS_COMMONS_UNIT_TEST_H

#include <setjmp.h>

#if __STDC_VERSION__ >= 199901L
#include <stdbool.h>
#define AVS_UNIT_HAVE_BOOL__
#elif defined(__cplusplus)
#define AVS_UNIT_HAVE_BOOL__
#endif

#include <avsystem/commons/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @file test.h
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
void avs_unit_assert_success__(int result,
                               const char *file,
                               int line);
void avs_unit_assert_failed__(int result, const char *file, int line);
void avs_unit_assert_true__(int result,
                       const char *file,
                       int line);
void avs_unit_assert_false__(int result, const char *file, int line);

void avs_unit_abort__(const char *msg, const char *file, int line);

typedef struct {
    char actual_str[64];
    char expected_str[64];
} avs_unit_check_equal_function_strings_t;

#define AVS_UNIT_CHECK_EQUAL_FUNCTION__(type, name_suffix)                     \
int avs_unit_check_equal_##name_suffix##__(type actual, type expected,         \
        avs_unit_check_equal_function_strings_t *strings)

AVS_UNIT_CHECK_EQUAL_FUNCTION__(char, c);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(short, s);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(int, i);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long, l);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long long, ll);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned char, uc);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned short, us);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned int, ui);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned long, ul);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned long long, ull);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(float, f);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(double, d);
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long double, ld);

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

#ifdef AVS_UNIT_HAVE_BOOL__
#define AVS_UNIT_CHECK_BOOL__(actual, expected, strings, inner)\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), bool),\
    avs_unit_check_equal_i__((int) (actual), (int) (expected), (strings)),\
    inner)
#else
#define AVS_UNIT_CHECK_BOOL__(actual, expected, strings, inner) inner
#endif

#define AVS_UNIT_CHECK_EQUAL__(actual, expected, strings)\
AVS_UNIT_CHECK_BOOL__(actual, expected, strings,\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(actual), char),\
    avs_unit_check_equal_c__((char) (actual), (char) (expected), (strings)),\
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
))))))))))))))

#define AVS_UNIT_ASSERT_EQUAL_BYTES__(actual, expected)\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(expected), const char[]),\
        avs_unit_assert_bytes_equal__((actual), (expected), sizeof(expected) - 1, __FILE__, __LINE__),\
        avs_unit_abort__("AVS_UNIT_ASSERT_EQUAL_BYTES called for unsupported data type\n", __FILE__, __LINE__))

#define AVS_UNIT_ASSERT_NOT_EQUAL_BYTES__(actual, expected)\
__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(expected), const char[]),\
        avs_unit_assert_bytes_not_equal__((actual), (expected), sizeof(expected) - 1, __FILE__, __LINE__),\
        avs_unit_abort__("AVS_UNIT_ASSERT_NOT_EQUAL_BYTES called for unsupported data type\n", __FILE__, __LINE__))

void avs_unit_assert_equal_string__(const char *actual,
                                    const char *expected,
                                    const char *file,
                                    int line);
void avs_unit_assert_not_equal_string__(const char *actual,
                                        const char *not_expected,
                                        const char *file,
                                        int line);

void avs_unit_assert_null__(const void *pointer, const char *file, int line);

void avs_unit_assert_not_null__(const void *pointer, const char *file,
                                int line);
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
static void AVS_CONCAT(_avs_unit_global_init_, __LINE__) (int VERBOSE_VAR);    \
void AVS_CONCAT(_avs_unit_global_init_constructor_, __LINE__) (void)           \
        __attribute__((constructor));                                          \
void AVS_CONCAT(_avs_unit_global_init_constructor_, __LINE__) (void) {         \
    avs_unit_add_global_init__(AVS_CONCAT(_avs_unit_global_init_, __LINE__));  \
}                                                                              \
static void AVS_CONCAT(_avs_unit_global_init_, __LINE__) (int VERBOSE_VAR)

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
#define AVS_UNIT_SUITE_INIT(suite, VERBOSE_VAR)                                \
static void                                                                    \
AVS_CONCAT(_avs_unit_suite_init_##suite##_, __LINE__) (int VERBOSE_VAR);       \
void AVS_CONCAT(_avs_unit_suite_init_constructor_##suite##_, __LINE__) (void)  \
        __attribute__((constructor));                                          \
void AVS_CONCAT(_avs_unit_suite_init_constructor_##suite##_, __LINE__) (void) {\
    avs_unit_add_suite_init__(#suite,                                          \
                              AVS_CONCAT(_avs_unit_suite_init_##suite##_,      \
                                         __LINE__));                           \
}                                                                              \
static void                                                                    \
AVS_CONCAT(_avs_unit_suite_init_##suite##_, __LINE__) (int VERBOSE_VAR)

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
#define AVS_UNIT_TEST(suite, name)                                             \
static void _avs_unit_test_##suite##_##name(void);                             \
void _avs_unit_test_constructor_##suite##_##name(void)                         \
        __attribute__((constructor));                                          \
void _avs_unit_test_constructor_##suite##_##name(void) {                       \
    avs_unit_add_test__(#suite, #name, _avs_unit_test_##suite##_##name);       \
}                                                                              \
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
#define AVS_UNIT_ASSERT_SUCCESS(result) \
    avs_unit_assert_success__(result, __FILE__, __LINE__)

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
#define AVS_UNIT_ASSERT_FAILED(result) \
    avs_unit_assert_failed__(result, __FILE__, __LINE__)

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
#define AVS_UNIT_ASSERT_EQUAL(actual, expected) \
do { \
    avs_unit_check_equal_function_strings_t strings; \
    avs_unit_assert_equal_func__( \
            AVS_UNIT_CHECK_EQUAL__(actual, expected, &strings), \
            strings.actual_str, strings.expected_str, __FILE__, __LINE__); \
} while(0)

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
#define AVS_UNIT_ASSERT_NOT_EQUAL(actual, not_expected) \
do { \
    avs_unit_check_equal_function_strings_t strings; \
    avs_unit_assert_not_equal_func__( \
            AVS_UNIT_CHECK_EQUAL__(actual, not_expected, &strings), \
            strings.actual_str, strings.expected_str, __FILE__, __LINE__); \
} while(0)

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
    avs_unit_assert_bytes_equal__(actual, expected, num_bytes, __FILE__, __LINE__)

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
    avs_unit_assert_bytes_not_equal__(actual, expected, num_bytes, __FILE__, __LINE__)

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

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_UNIT_TEST_H */
