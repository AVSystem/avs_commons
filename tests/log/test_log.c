/*
 * Copyright 2025 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/avs_log.h>
#include <avsystem/commons/avs_unit_test.h>

#include <stdlib.h>

static avs_log_level_t EXPECTED_LEVEL;
static char EXPECTED_MODULE[64];
static char EXPECTED_FILE[256];
static int EXPECTED_LINE;
static char EXPECTED_MESSAGE[512];

static void reset_expected(void) {
    EXPECTED_LEVEL = AVS_LOG_QUIET;
    EXPECTED_MODULE[0] = '\0';
    EXPECTED_MESSAGE[0] = '\0';
    EXPECTED_FILE[0] = '\0';
    EXPECTED_LINE = 0;
}

#define ASSERT_LOG_CLEAN                                      \
    do {                                                      \
        AVS_UNIT_ASSERT_EQUAL(EXPECTED_LEVEL, AVS_LOG_QUIET); \
        AVS_UNIT_ASSERT_EQUAL_STRING(EXPECTED_MODULE, "");    \
        AVS_UNIT_ASSERT_EQUAL_STRING(EXPECTED_FILE, "");      \
        AVS_UNIT_ASSERT_EQUAL(EXPECTED_LINE, 0);              \
        AVS_UNIT_ASSERT_EQUAL_STRING(EXPECTED_MESSAGE, "");   \
    } while (0)

#define ASSERT_LOG(Module, Level, ...)                                     \
    do {                                                                   \
        ASSERT_LOG_CLEAN;                                                  \
        EXPECTED_LEVEL = AVS_LOG_##Level;                                  \
        strcpy(EXPECTED_MODULE, #Module);                                  \
        snprintf(EXPECTED_MESSAGE, sizeof(EXPECTED_MESSAGE), __VA_ARGS__); \
    } while (0)

#define ASSERT_EXTENDED_LOG(Module, Level, File, Line, ...)                \
    do {                                                                   \
        ASSERT_LOG_CLEAN;                                                  \
        EXPECTED_LEVEL = AVS_LOG_##Level;                                  \
        strcpy(EXPECTED_MODULE, #Module);                                  \
        strcpy(EXPECTED_FILE, File);                                       \
        EXPECTED_LINE = Line;                                              \
        snprintf(EXPECTED_MESSAGE, sizeof(EXPECTED_MESSAGE), __VA_ARGS__); \
    } while (0)

static void
mock_handler(avs_log_level_t level, const char *module, const char *message) {
    AVS_UNIT_ASSERT_EQUAL(level, EXPECTED_LEVEL);
    AVS_UNIT_ASSERT_EQUAL_STRING(module, EXPECTED_MODULE);
    AVS_UNIT_ASSERT_EQUAL_STRING(message, EXPECTED_MESSAGE);
    reset_expected();
}

static void mock_extended_handler(avs_log_level_t level,
                                  const char *module,
                                  const char *file,
                                  unsigned line,
                                  const char *message) {
    AVS_UNIT_ASSERT_EQUAL(level, EXPECTED_LEVEL);
    AVS_UNIT_ASSERT_EQUAL_STRING(module, EXPECTED_MODULE);
    AVS_UNIT_ASSERT_EQUAL_STRING(file, EXPECTED_FILE);
    AVS_UNIT_ASSERT_EQUAL(line, EXPECTED_LINE);
    AVS_UNIT_ASSERT_EQUAL_STRING(message, EXPECTED_MESSAGE);
    reset_expected();
}

static void reset_everything(void) {
    avs_log_reset();
    avs_log_set_handler(mock_handler);
    reset_expected();
}

AVS_UNIT_GLOBAL_INIT(verbose) {
    (void) verbose;
    AVS_UNIT_ASSERT_TRUE(g_log.handler.normal == default_log_handler);
    AVS_UNIT_ASSERT_FALSE(g_log.is_extended_handler);
#ifndef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
    AVS_UNIT_ASSERT_EQUAL(g_log.default_level, AVS_LOG_INFO);
    AVS_UNIT_ASSERT_TRUE(g_log.module_levels == NULL);
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
    reset_everything();
}

AVS_UNIT_TEST(log, initial) {
    /* plain */
    ASSERT_LOG(test,
               INFO,
               "INFO [test] [" __FILE__ ":%d]: Hello, world!",
               __LINE__ + 1);
    avs_log(test, INFO, "Hello, world!");

    /* formatted */
    ASSERT_LOG(test,
               ERROR,
               "ERROR [test] [" __FILE__ ":%d]: Hello, world!",
               __LINE__ + 1);
    avs_log(test, ERROR, "%s, %s!", "Hello", "world");

    avs_log(test, DEBUG, "Not printed");

    ASSERT_LOG_CLEAN;
    reset_everything();
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT INFO
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
}

AVS_UNIT_TEST(log, default_level) {
    /* not testing TRACE as it may not be compiled in */
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT DEBUG
    avs_log_set_default_level(
            AVS_LOG_TRACE); // runtime check won't affect the test
#else
    avs_log_set_default_level(AVS_LOG_DEBUG);
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/

    ASSERT_LOG(test,
               DEBUG,
               "DEBUG [test] [" __FILE__ ":%d]: Testing DEBUG",
               __LINE__ + 1);
    avs_log(test, DEBUG, "Testing DEBUG");
    ASSERT_LOG(test,
               INFO,
               "INFO [test] [" __FILE__ ":%d]: Testing INFO",
               __LINE__ + 1);
    avs_log(test, INFO, "Testing INFO");
    ASSERT_LOG(test,
               WARNING,
               "WARNING [test] [" __FILE__ ":%d]: Testing WARNING",
               __LINE__ + 1);
    avs_log(test, WARNING, "Testing WARNING");
    ASSERT_LOG(test,
               ERROR,
               "ERROR [test] [" __FILE__ ":%d]: Testing ERROR",
               __LINE__ + 1);
    avs_log(test, ERROR, "Testing ERROR");
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT INFO
#else
    avs_log_set_default_level(AVS_LOG_INFO);
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
    avs_log(test, DEBUG, "Testing DEBUG");
    ASSERT_LOG(test,
               INFO,
               "INFO [test] [" __FILE__ ":%d]: Testing INFO",
               __LINE__ + 1);
    avs_log(test, INFO, "Testing INFO");
    ASSERT_LOG(test,
               WARNING,
               "WARNING [test] [" __FILE__ ":%d]: Testing WARNING",
               __LINE__ + 1);
    avs_log(test, WARNING, "Testing WARNING");
    ASSERT_LOG(test,
               ERROR,
               "ERROR [test] [" __FILE__ ":%d]: Testing ERROR",
               __LINE__ + 1);
    avs_log(test, ERROR, "Testing ERROR");
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT WARNING
#else
    avs_log_set_default_level(AVS_LOG_WARNING);
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
    avs_log(test, DEBUG, "Testing DEBUG");
    avs_log(test, INFO, "Testing INFO");
    ASSERT_LOG(test,
               WARNING,
               "WARNING [test] [" __FILE__ ":%d]: Testing WARNING",
               __LINE__ + 1);
    avs_log(test, WARNING, "Testing WARNING");
    ASSERT_LOG(test,
               ERROR,
               "ERROR [test] [" __FILE__ ":%d]: Testing ERROR",
               __LINE__ + 1);
    avs_log(test, ERROR, "Testing ERROR");
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT ERROR
#else
    avs_log_set_default_level(AVS_LOG_ERROR);
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
    avs_log(test, DEBUG, "Testing DEBUG");
    avs_log(test, INFO, "Testing INFO");
    avs_log(test, WARNING, "Testing WARNING");
    ASSERT_LOG(test,
               ERROR,
               "ERROR [test] [" __FILE__ ":%d]: Testing ERROR",
               __LINE__ + 1);
    avs_log(test, ERROR, "Testing ERROR");
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT QUIET
#else
    avs_log_set_default_level(AVS_LOG_QUIET);
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
    avs_log(test, DEBUG, "Testing DEBUG");
    avs_log(test, INFO, "Testing INFO");
    avs_log(test, WARNING, "Testing WARNING");
    avs_log(test, ERROR, "Testing ERROR");

    ASSERT_LOG_CLEAN;
    reset_everything();
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT INFO
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
}
AVS_UNIT_TEST(log, module_levels) {
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_FOR_MODULE_debugged_module
#    undef AVS_LOG_LEVEL_FOR_MODULE_stable_module
#    define AVS_LOG_LEVEL_FOR_MODULE_debugged_module DEBUG
#    define AVS_LOG_LEVEL_FOR_MODULE_stable_module ERROR
    avs_log_set_default_level(
            AVS_LOG_TRACE); // runtime check won't affect the test
#else
    avs_log_set_level(debugged_module, AVS_LOG_DEBUG);
    avs_log_set_level(stable_module, AVS_LOG_ERROR);
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
    ASSERT_LOG(debugged_module,
               DEBUG,
               "DEBUG [debugged_module] [" __FILE__ ":%d]: Testing DEBUG",
               __LINE__ + 1);
    avs_log(debugged_module, DEBUG, "Testing DEBUG");
    ASSERT_LOG(debugged_module,
               INFO,
               "INFO [debugged_module] [" __FILE__ ":%d]: Testing INFO",
               __LINE__ + 1);
    avs_log(debugged_module, INFO, "Testing INFO");
    ASSERT_LOG(debugged_module,
               WARNING,
               "WARNING [debugged_module] [" __FILE__ ":%d]: Testing WARNING",
               __LINE__ + 1);
    avs_log(debugged_module, WARNING, "Testing WARNING");
    ASSERT_LOG(debugged_module,
               ERROR,
               "ERROR [debugged_module] [" __FILE__ ":%d]: Testing ERROR",
               __LINE__ + 1);
    avs_log(debugged_module, ERROR, "Testing ERROR");

    avs_log(stable_module, DEBUG, "Testing DEBUG");
    avs_log(stable_module, INFO, "Testing INFO");
    avs_log(stable_module, WARNING, "Testing WARNING");
    ASSERT_LOG(stable_module,
               ERROR,
               "ERROR [stable_module] [" __FILE__ ":%d]: Testing ERROR",
               __LINE__ + 1);
    avs_log(stable_module, ERROR, "Testing ERROR");

    /* default level is INFO */
    avs_log(other_module, DEBUG, "Testing DEBUG");
    ASSERT_LOG(other_module,
               INFO,
               "INFO [other_module] [" __FILE__ ":%d]: Testing INFO",
               __LINE__ + 1);
    avs_log(other_module, INFO, "Testing INFO");
    ASSERT_LOG(other_module,
               WARNING,
               "WARNING [other_module] [" __FILE__ ":%d]: Testing WARNING",
               __LINE__ + 1);
    avs_log(other_module, WARNING, "Testing WARNING");
    ASSERT_LOG(other_module,
               ERROR,
               "ERROR [other_module] [" __FILE__ ":%d]: Testing ERROR",
               __LINE__ + 1);
    avs_log(other_module, ERROR, "Testing ERROR");

    ASSERT_LOG_CLEAN;
    reset_everything();
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT INFO
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
}

static int fail(void) {
    AVS_UNIT_ASSERT_TRUE(0);
    return -1;
}

static int success(void) {
    return 42;
}

AVS_UNIT_TEST(log, lazy_log) {
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_FOR_MODULE_debugged_module
#    undef AVS_LOG_LEVEL_FOR_MODULE_stable_module
#    define AVS_LOG_LEVEL_FOR_MODULE_debugged_module DEBUG
#    define AVS_LOG_LEVEL_FOR_MODULE_stable_module ERROR
    avs_log_set_default_level(
            AVS_LOG_TRACE); // runtime check won't affect the test
#else
    avs_log_set_level(debugged_module, AVS_LOG_DEBUG);
    avs_log_set_level(stable_module, AVS_LOG_ERROR);
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
    ASSERT_LOG(debugged_module,
               DEBUG,
               "DEBUG [debugged_module] [" __FILE__ ":%d]: Testing DEBUG 42",
               __LINE__ + 1);
    avs_log(debugged_module, LAZY_DEBUG, "Testing DEBUG %d", success());
    ASSERT_LOG(debugged_module,
               INFO,
               "INFO [debugged_module] [" __FILE__ ":%d]: Testing INFO 42",
               __LINE__ + 1);
    avs_log(debugged_module, LAZY_INFO, "Testing INFO %d", success());
    ASSERT_LOG(debugged_module,
               WARNING,
               "WARNING [debugged_module] [" __FILE__
               ":%d]: Testing WARNING 42",
               __LINE__ + 1);
    avs_log(debugged_module, LAZY_WARNING, "Testing WARNING %d", success());
    ASSERT_LOG(debugged_module,
               ERROR,
               "ERROR [debugged_module] [" __FILE__ ":%d]: Testing ERROR 42",
               __LINE__ + 1);
    avs_log(debugged_module, LAZY_ERROR, "Testing ERROR %d", success());

    avs_log(stable_module, LAZY_DEBUG, "Testing DEBUG %d", fail());
    avs_log(stable_module, LAZY_INFO, "Testing INFO %d", fail());
    avs_log(stable_module, LAZY_WARNING, "Testing WARNING %d", fail());
    ASSERT_LOG(stable_module,
               ERROR,
               "ERROR [stable_module] [" __FILE__ ":%d]: Testing ERROR 42",
               __LINE__ + 1);
    avs_log(stable_module, LAZY_ERROR, "Testing ERROR %d", success());

    /* default level is INFO */
    avs_log_lazy(other_module, DEBUG, "Testing DEBUG %d", fail());
    ASSERT_LOG(other_module,
               INFO,
               "INFO [other_module] [" __FILE__ ":%d]: Testing INFO 42",
               __LINE__ + 1);
    avs_log_lazy(other_module, INFO, "Testing INFO %d", success());
    ASSERT_LOG(other_module,
               WARNING,
               "WARNING [other_module] [" __FILE__ ":%d]: Testing WARNING 42",
               __LINE__ + 1);
    avs_log_lazy(other_module, WARNING, "Testing WARNING %d", success());
    ASSERT_LOG(other_module,
               ERROR,
               "ERROR [other_module] [" __FILE__ ":%d]: Testing ERROR 42",
               __LINE__ + 1);
    avs_log_lazy(other_module, ERROR, "Testing ERROR %d", success());

    ASSERT_LOG_CLEAN;
    reset_everything();
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT INFO
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
}

AVS_UNIT_TEST(log, truncated) {
#define LOG_MSG "log to be truncated"
#define TEST_BUF_SIZE 32

    char *buf = (char *) malloc(32);
    va_list empty_va_list;
    memset(&empty_va_list, 0, sizeof(empty_va_list));

    memset(buf, 'a', 32);
    ASSERT_LOG(test, INFO, "INFO [test] [plik:1]: log to...");
    log_with_buffer_unlocked_v(buf,
                               TEST_BUF_SIZE,
                               AVS_LOG_INFO,
                               "test",
                               "plik",
                               1,
                               LOG_MSG,
                               empty_va_list);

    memset(buf, 'a', 32);
    ASSERT_LOG(test, INFO, "INFO [test] [pl");
    log_with_buffer_unlocked_v(
            buf, 16, AVS_LOG_INFO, "test", "plik", 1, LOG_MSG, empty_va_list);

    memset(buf, 'a', 32);
    ASSERT_LOG(test, INFO, "INFO [test] [plik:1]: 123456789");
    log_with_buffer_unlocked_v(buf,
                               TEST_BUF_SIZE,
                               AVS_LOG_INFO,
                               "test",
                               "plik",
                               1,
                               "123456789",
                               empty_va_list);

    free(buf);

#undef LOG_MSG
}

AVS_UNIT_TEST(log, extended) {
    avs_log_set_extended_handler(mock_extended_handler);
    ASSERT_EXTENDED_LOG(test, INFO, __FILE__, __LINE__ + 1, "test");
    avs_log(test, INFO, "test");

    ASSERT_EXTENDED_LOG(test, ERROR, __FILE__, __LINE__ + 1, "test 2");
    avs_log(test, ERROR, "test %d", 2);

    ASSERT_EXTENDED_LOG(test, INFO, __FILE__, __LINE__ + 1, "test 3 4");
    avs_log(test, INFO, "test %d %d", 3, 4);

    avs_log_set_handler(mock_handler);
    ASSERT_LOG(test,
               INFO,
               "INFO [test] [" __FILE__ ":%d]: Hello, world!",
               __LINE__ + 1);
    avs_log(test, INFO, "Hello, world!");

    avs_log_set_extended_handler(mock_extended_handler);
    ASSERT_EXTENDED_LOG(test, WARNING, __FILE__, __LINE__ + 1, "test 5");
    avs_log(test, WARNING, "test %d", 5);

    ASSERT_LOG_CLEAN;
    reset_everything();
#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    undef AVS_LOG_LEVEL_DEFAULT
#    define AVS_LOG_LEVEL_DEFAULT INFO
#endif /*AVS_LOGS_CHECKED_DURING_COMPILE_TIME*/
}
