/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>

#include <avsystem/commons/defs.h>
#include <avsystem/commons/list.h>
#include <avsystem/commons/log.h>
#include <avsystem/commons/unit/mock_helpers.h>
#include <avsystem/commons/unit/test.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

typedef struct avs_unit_test_struct {
    const char *name;
    avs_unit_test_function_t test;
} avs_unit_test_t;

typedef struct avs_unit_test_suite_struct {
    const char *name;
    AVS_LIST(avs_unit_init_function_t) init;
    AVS_LIST(avs_unit_test_t) tests;
} avs_unit_test_suite_t;

typedef enum message_level {
    NORMAL,
    VERBOSE
} message_level_t;

static jmp_buf _avs_unit_jmp_buf;
static AVS_LIST(avs_unit_init_function_t) global_init = NULL;
static AVS_LIST(avs_unit_test_suite_t) test_suites = NULL;
static int verbose = 0;

static int add_init_func(AVS_LIST(avs_unit_init_function_t) *list,
                         avs_unit_init_function_t init_func) {
    avs_unit_init_function_t *new_init =
            AVS_LIST_NEW_ELEMENT(avs_unit_init_function_t);
    if (!new_init) {
        return -1;
    }
    *new_init = init_func;
    AVS_LIST_APPEND(list, new_init);
    return 0;
}

void avs_unit_add_global_init__(avs_unit_init_function_t init_func) {
    if (add_init_func(&global_init, init_func)) {
        fprintf(stderr, "cannot add new global init function\n");
        exit(EXIT_FAILURE);
    }
}

static void test_fail_printf(const char *file, int line, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("\033[1m[%s:%d] ", file, line);
    vprintf(fmt, ap);
    printf("\033[0m");
    va_end(ap);
}

void avs_unit_abort__(const char *msg, const char *file, int line) {
    test_fail_printf(file, line, msg);
    abort();
}

static void test_fail_print_hex_diff(const uint8_t *actual,
                                     const uint8_t *expected,
                                     size_t buffer_size,
                                     size_t diff_start_offset,
                                     size_t diff_bytes,
                                     size_t context_size) {
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

    size_t start = (size_t)MAX((ssize_t)diff_start_offset - (ssize_t)context_size, 0);
    size_t end = MIN(diff_start_offset + diff_bytes + context_size, buffer_size);

#undef MIN
#undef MAX

    size_t i;
    size_t marker_offset = sizeof("expected:") + 1 + (diff_start_offset - start) * (sizeof(" 00") - 1);

    printf("  actual:");
    for (i = start; i < end; ++i) {
        printf(" \033[%dm%02x", actual[i] != expected[i], actual[i]);
    }
    printf("\033[0m\nexpected:");
    for (i = start; i < end; ++i) {
        printf(" \033[%dm%02x", actual[i] != expected[i], expected[i]);
    }
    printf("\033[0m\n%*s\n", (int)marker_offset, "^");
}

static avs_unit_test_suite_t *find_test_suite(const char *suite_name) {
    avs_unit_test_suite_t *result = NULL;
    AVS_LIST_FOREACH(result, test_suites) {
        if (strcmp(result->name, suite_name) == 0) {
            return result;
        }
    }
    return NULL;
}

static avs_unit_test_suite_t *add_test_suite(const char *suite_name) {
    avs_unit_test_suite_t *new_suite =
            AVS_LIST_NEW_ELEMENT(avs_unit_test_suite_t);
    if (new_suite) {
        new_suite->name = suite_name;
        AVS_LIST_APPEND(&test_suites, new_suite);
    }
    return new_suite;
}

static avs_unit_test_suite_t *find_or_add_test_suite(const char *suite_name) {
    avs_unit_test_suite_t *suite = NULL;
    suite = find_test_suite(suite_name);
    if (!suite) {
        suite = add_test_suite(suite_name);
    }
    if (!suite) {
        fprintf(stderr, "cannot add new test suite: %s\n", suite_name);
        exit(EXIT_FAILURE);
    }
    return suite;
}

void avs_unit_add_suite_init__(const char *suite_name,
                               avs_unit_init_function_t init_func) {
    avs_unit_test_suite_t *suite = find_or_add_test_suite(suite_name);
    if (add_init_func(&suite->init, init_func)) {
        fprintf(stderr,
                "cannot add new init function for suite: %s\n", suite_name);
        exit(EXIT_FAILURE);
    }
}

void avs_unit_add_test__(const char *suite_name,
                         const char *name,
                         avs_unit_test_function_t test) {
    avs_unit_test_suite_t *suite = find_or_add_test_suite(suite_name);
    avs_unit_test_t *new_test = AVS_LIST_NEW_ELEMENT(avs_unit_test_t);
    if (!new_test) {
        fprintf(stderr, "cannot add new test: %s/%s\n", suite_name, name);
        exit(EXIT_FAILURE);
    }
    new_test->name = name;
    new_test->test = test;
    AVS_LIST_APPEND(&suite->tests, new_test);
}

/* <editor-fold defaultstate="collapsed" desc="ASSERTIONS"> */
void avs_unit_assert_success__(int result,
                               const char *file,
                               int line) {
    if (result != 0) {
        test_fail_printf(file, line, "expected success\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

void avs_unit_assert_failed__(int result,
                              const char *file,
                              int line) {
    if (result == 0) {
        test_fail_printf(file, line, "expected failure\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

void avs_unit_assert_true__(int result,
                            const char *file,
                            int line) {
    if (result == 0) {
        test_fail_printf(file, line, "expected true\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

void avs_unit_assert_false__(int result,
                             const char *file,
                             int line) {
    if (result != 0) {
        test_fail_printf(file, line, "expected false\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

#define CHECK_EQUAL_BODY(format)                                               \
{                                                                              \
    snprintf(strings->actual_str, sizeof(strings->actual_str),                 \
             format, actual);                                                  \
    snprintf(strings->expected_str, sizeof(strings->expected_str),             \
             format, expected);                                                \
    return memcmp(&actual, &expected, sizeof(actual)) == 0;                    \
}

AVS_UNIT_CHECK_EQUAL_FUNCTION__(char, c) CHECK_EQUAL_BODY("%c")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(short, s) CHECK_EQUAL_BODY("%d")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(int, i) CHECK_EQUAL_BODY("%d")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long, l) CHECK_EQUAL_BODY("%ld")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long long, ll) CHECK_EQUAL_BODY("%lld")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned char, uc) CHECK_EQUAL_BODY("0x%02x")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned short, us) CHECK_EQUAL_BODY("%u")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned int, ui) CHECK_EQUAL_BODY("%u")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned long, ul) CHECK_EQUAL_BODY("%lu")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(unsigned long long, ull) CHECK_EQUAL_BODY("%llu")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(float, f) CHECK_EQUAL_BODY("%.12g")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(double, d) CHECK_EQUAL_BODY("%.12g")
AVS_UNIT_CHECK_EQUAL_FUNCTION__(long double, ld) CHECK_EQUAL_BODY("%.12Lg")

void avs_unit_assert_equal_func__(int check_result,
                                  const char *actual_str,
                                  const char *expected_str,
                                  const char *file,
                                  int line) {
    if (!check_result) {
        test_fail_printf(file, line,
                         "expected <%s> was <%s>\n",
                         expected_str, actual_str);
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

void avs_unit_assert_not_equal_func__(int check_result,
                                      const char *actual_str,
                                      const char *not_expected_str,
                                      const char *file,
                                      int line) {
    (void) actual_str;
    if (check_result) {
        test_fail_printf(file, line,
                         "expected value other than <%s>\n",
                         not_expected_str);
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

void avs_unit_assert_equal_string__(const char *actual,
                                    const char *expected,
                                    const char *file,
                                    int line) {
    if (!expected) {
        test_fail_printf(file, line, "expected is NULL\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
    if (!actual) {
        test_fail_printf(file, line, "actual is NULL\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
    if (strcmp(actual, expected)) {
        test_fail_printf(file, line,
                         "expected <%s> was <%s>\n",
                         expected, actual);
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

static size_t find_first__(bool equal,
                           const uint8_t *a,
                           const uint8_t *b,
                           size_t start,
                           size_t size) {
    size_t at;
    for (at = start; at < size; ++at) {
        if ((a[at] == b[at]) == equal) {
            return at;
        }
    }

    return size;
}

#define find_first_equal(a, b, start, size) find_first__(true, (a), (b), (start), (size))
#define find_first_different(a, b, start, size) find_first__(false, (a), (b), (start), (size))

static void print_differences(const void *actual,
                              const void *expected,
                              size_t num_bytes) {
    static const size_t CONTEXT_SIZE = 5;
    static const size_t MAX_ERRORS = 3;
    size_t found_errors = 0;
    size_t at = 0;
    const uint8_t *actual_ptr = (const uint8_t*)actual;
    const uint8_t *expected_ptr = (const uint8_t*)expected;

    for (found_errors = 0; found_errors < MAX_ERRORS; ++found_errors) {
        size_t error_start = find_first_different(actual_ptr, expected_ptr, at, num_bytes);
        size_t error_end;
        size_t error_bytes = 0;

        if (error_start >= num_bytes) {
            return;
        }

        error_end = find_first_equal(actual_ptr, expected_ptr, error_start, num_bytes);
        error_bytes = error_end - error_start;

        while (error_end < num_bytes) {
            at = find_first_different(actual_ptr, expected_ptr, error_end, num_bytes);
            if (at - error_end <= CONTEXT_SIZE * 2) {
                error_end = find_first_equal(actual_ptr, expected_ptr, at, num_bytes);
                error_bytes += error_end - at;
                at = error_end;
            } else {
                break;
            }
        }

        printf("- %lu different byte(s) at offset %lu:\n", error_bytes, error_start);
        test_fail_print_hex_diff(actual_ptr, expected_ptr, num_bytes,
                                 error_start, error_end - error_start,
                                 CONTEXT_SIZE);
    }

    printf("- (more errors skipped)\n");
}

static void compare_bytes(const void *actual,
                          const void *expected,
                          size_t num_bytes,
                          bool expect_same,
                          const char *file,
                          int line) {
    if (!memcmp(actual, expected, num_bytes) == expect_same) {
        return;
    }

    test_fail_printf(file, line, "byte sequences are %sequal:\n",
                     expect_same ? "not " : "");

    if (expect_same) {
        print_differences(actual, expected, num_bytes);
    }

    longjmp(_avs_unit_jmp_buf, 1);
}

void avs_unit_assert_bytes_equal__(const void *actual,
                                   const void *expected,
                                   size_t num_bytes,
                                   const char *file,
                                   int line) {
    compare_bytes(actual, expected, num_bytes, true, file, line);
}

void avs_unit_assert_bytes_not_equal__(const void *actual,
                                       const void *expected,
                                       size_t num_bytes,
                                       const char *file,
                                       int line) {
    compare_bytes(actual, expected, num_bytes, false, file, line);
}

void avs_unit_assert_not_equal_string__(const char *actual,
                                        const char *not_expected,
                                        const char *file,
                                        int line) {
    if (!not_expected) {
        test_fail_printf(file, line, "expected is NULL\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
    if (!actual) {
        test_fail_printf(file, line, "actual is NULL\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
    if (strcmp(actual, not_expected) == 0) {
        test_fail_printf(file, line,
                         "expected value other than <%s>\n",
                         not_expected);
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

void avs_unit_assert_null__(const void *pointer,
                            const char *file,
                            int line) {
    if (pointer) {
        test_fail_printf(file, line, "expected NULL\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

void avs_unit_assert_not_null__(const void *pointer,
                                const char *file,
                                int line) {
    if (!pointer) {
        test_fail_printf(file, line, "expected not NULL\n");
        longjmp(_avs_unit_jmp_buf, 1);
    }
}

/* </editor-fold> */

static const char *string_status(int result) {
    static char buffer[32];
    if (result) {
        /* FAIL */
        snprintf(buffer, sizeof(buffer), "\033[0;31mFAIL\033[0m");
    } else {
        /* SUCCESS */
        snprintf(buffer, sizeof(buffer), "\033[0;32mOK\033[0m");
    }
    return buffer;
}

static void test_printf(message_level_t level, const char *format, ...) {
    if (level == NORMAL || verbose) {
        va_list list;
        va_start(list, format);
        vprintf(format, list);
        va_end(list);
    }
}

static void parse_command_line_args(int argc, char* argv[],
                                    const char * volatile *out_selected_suite,
                                    const char * volatile *out_selected_test) {
    while (1) {
        static const struct option long_options[] = {
            { "verbose", no_argument, 0, 'v' },
            { 0, 0, 0, 0 }
        };

        int option_index = 0;
        int c;

        c = getopt_long(argc, argv, "v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'v':
            verbose += 1;
            break;
        default:
            break;
        }
    }

    for (; optind < argc; ++optind) {
        if (!*out_selected_suite) {
            *out_selected_suite = argv[optind];
        } else if (!*out_selected_test) {
            *out_selected_test = argv[optind];
        }
    }
}

static int parse_log_level(const char *str,
                           avs_log_level_t *level) {
    if (!strcasecmp(str, "trace")) {
        *level = AVS_LOG_TRACE;
    } else if (!strcasecmp(str, "debug")) {
        *level = AVS_LOG_DEBUG;
    } else if (!strcasecmp(str, "info")) {
        *level = AVS_LOG_INFO;
    } else if (!strcasecmp(str, "warning")) {
        *level = AVS_LOG_WARNING;
    } else if (!strcasecmp(str, "error")) {
        *level = AVS_LOG_ERROR;
    } else if (!strcasecmp(str, "quiet")) {
        *level = AVS_LOG_QUIET;
    } else {
        return -1;
    }

    return 0;
}

static int parse_log_level_definition(const char **def,
                                      char *out_module,
                                      size_t module_size,
                                      char *out_level_str,
                                      size_t level_str_size,
                                      avs_log_level_t *out_level) {
    const char *eq = strchr(*def, '=');
    const char *end;
    int result = -1;

    if (!eq) {
        *def = strchr(*def, ';');
        if (*def) {
            ++*def;
        }
        return -1;
    }

    if (!(end = strchr(eq, ';'))) {
        end = strchr(eq, '\0');
    }

    if (eq - *def < (ssize_t)module_size
            && end - (eq + 1) < (ssize_t)level_str_size) {
        memcpy(out_module, *def, (size_t)(eq - *def));
        memcpy(out_level_str, eq + 1, (size_t)(end - (eq + 1)));

        if (parse_log_level(out_level_str, out_level)) {
            test_printf(NORMAL, "invalid log level: %s for module %s\n",
                        out_level_str, out_module);
        } else {
            result = 0;
        }
    }

    if (*end) {
        *def = end + 1;
    } else {
        *def = NULL;
    }

    return result;
}

static void process_env_vars(void) {
    const char *log = getenv("AVS_LOG");
    bool log_levels_changed = false;

    while (log) {
        char module[128] = "";
        char level_str[16] = "";
        avs_log_level_t level;

        if (!parse_log_level_definition(&log, module, sizeof(module),
                                        level_str, sizeof(level_str), &level)) {
            avs_log_set_level__(module, level);
            log_levels_changed = true;
            test_printf(VERBOSE, "log level set to %s for module %s\n",
                        level_str, module);
        }
    }

    if (log_levels_changed) {
        atexit(avs_log_reset);
    }
}

int main(int argc, char *argv[]) {
    const char * volatile selected_suite = NULL;
    const char * volatile selected_test = NULL;
    avs_unit_init_function_t * volatile current_init = NULL;
    avs_unit_test_suite_t * volatile current_suite = NULL;
    volatile int tests_result = 0;

    parse_command_line_args(argc, argv, &selected_suite, &selected_test);
    process_env_vars();

    AVS_LIST_FOREACH(current_init, global_init) {
        (*current_init)(verbose);
    }

    AVS_LIST_FOREACH(current_suite, test_suites) {
        avs_unit_test_t * volatile current_test = NULL;
        volatile size_t tests_passed = 0;
        volatile size_t tests_count;

        if (selected_suite && strcmp(selected_suite, current_suite->name)) {
            continue;
        }
        tests_count = AVS_LIST_SIZE(current_suite->tests);

        test_printf(VERBOSE, "\033[0;33m%s\033[0m\n", current_suite->name);

        AVS_LIST_FOREACH(current_init, current_suite->init) {
            (*current_init)(verbose);
        }

        AVS_LIST_FOREACH(current_test, current_suite->tests) {
            int result = 0;
            avs_unit_mock_reset_all__();
            if (selected_test && strcmp(selected_test, current_test->name)) {
                continue;
            }
            if (setjmp(_avs_unit_jmp_buf) == 0) {
                current_test->test();
                result = 0;
            } else {
                result = 1;
                tests_result = 1;
            }

            if (result) {
                test_printf(NORMAL, "    %-60s %s\n",
                            current_test->name, string_status(result));
            } else {
                test_printf(VERBOSE, "    %-60s %s\n",
                            current_test->name, string_status(result));
                ++tests_passed;
            }
        }
        test_printf(NORMAL,
                    "\033[0;33m%-65s\033[0;%sm%" PRIu64 "/%" PRIu64 "\033[0m\n",
                    current_suite->name,
                    (selected_test || tests_passed == tests_count) ? "32" : "31",
                    (uint64_t) tests_passed, (uint64_t) tests_count);
        test_printf(VERBOSE, "\n");
    }
    AVS_LIST_CLEAR(&test_suites) {
        AVS_LIST_CLEAR(&test_suites->init);
        AVS_LIST_CLEAR(&test_suites->tests);
    }
    AVS_LIST_CLEAR(&global_init);
    avs_unit_mock_cleanup__();

    return tests_result;
}
