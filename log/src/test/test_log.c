/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <avsystem/commons/unit/test.h>
#include <avsystem/commons/log.h>

static avs_log_level_t EXPECTED_LEVEL;
static char EXPECTED_MODULE[64];
static char EXPECTED_MESSAGE[512];

static void reset_expected(void) {
    EXPECTED_LEVEL = AVS_LOG_QUIET;
    EXPECTED_MODULE[0] = '\0';
    EXPECTED_MESSAGE[0] = '\0';
}

#define ASSERT_LOG_CLEAN do { \
    AVS_UNIT_ASSERT_EQUAL(EXPECTED_LEVEL, AVS_LOG_QUIET); \
    AVS_UNIT_ASSERT_EQUAL_STRING(EXPECTED_MODULE, ""); \
    AVS_UNIT_ASSERT_EQUAL_STRING(EXPECTED_MESSAGE, ""); \
} while (0)

#define ASSERT_LOG(Module, Level, Message) do { \
    ASSERT_LOG_CLEAN; \
    EXPECTED_LEVEL = AVS_LOG_##Level; \
    strcpy(EXPECTED_MODULE, #Module); \
    strcpy(EXPECTED_MESSAGE, Message); \
} while (0)

static void mock_handler(avs_log_level_t level,
                         const char *module,
                         const char *message) {
    AVS_UNIT_ASSERT_EQUAL(level, EXPECTED_LEVEL);
    AVS_UNIT_ASSERT_EQUAL_STRING(module, EXPECTED_MODULE);
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
    AVS_UNIT_ASSERT_TRUE(HANDLER == default_log_handler);
    AVS_UNIT_ASSERT_EQUAL(DEFAULT_LEVEL, AVS_LOG_INFO);
    AVS_UNIT_ASSERT_TRUE(MODULE_LEVELS == NULL);
    reset_everything();
}

AVS_UNIT_TEST(log, initial) {
    /* plain */
    ASSERT_LOG(test, INFO, "INFO [test] [src/test/test_log.c:62]: Hello, world!");
    avs_log(test, INFO, "Hello, world!");

    /* formatted */
    ASSERT_LOG(test, ERROR, "ERROR [test] [src/test/test_log.c:66]: Hello, world!");
    avs_log(test, ERROR, "%s, %s!", "Hello", "world");

    avs_log(test, DEBUG, "Not printed");

    ASSERT_LOG_CLEAN;
    reset_everything();
}

AVS_UNIT_TEST(log, default_level) {
    /* not testing TRACE as it may not be compiled in */
    avs_log_set_default_level(AVS_LOG_DEBUG);
    ASSERT_LOG(test, DEBUG, "DEBUG [test] [src/test/test_log.c:78]: Testing DEBUG");
    avs_log(test, DEBUG, "Testing DEBUG");
    ASSERT_LOG(test, INFO, "INFO [test] [src/test/test_log.c:80]: Testing INFO");
    avs_log(test, INFO, "Testing INFO");
    ASSERT_LOG(test, WARNING, "WARNING [test] [src/test/test_log.c:82]: Testing WARNING");
    avs_log(test, WARNING, "Testing WARNING");
    ASSERT_LOG(test, ERROR, "ERROR [test] [src/test/test_log.c:84]: Testing ERROR");
    avs_log(test, ERROR, "Testing ERROR");

    avs_log_set_default_level(AVS_LOG_INFO);
    avs_log(test, DEBUG, "Testing DEBUG");
    ASSERT_LOG(test, INFO, "INFO [test] [src/test/test_log.c:89]: Testing INFO");
    avs_log(test, INFO, "Testing INFO");
    ASSERT_LOG(test, WARNING, "WARNING [test] [src/test/test_log.c:91]: Testing WARNING");
    avs_log(test, WARNING, "Testing WARNING");
    ASSERT_LOG(test, ERROR, "ERROR [test] [src/test/test_log.c:93]: Testing ERROR");
    avs_log(test, ERROR, "Testing ERROR");

    avs_log_set_default_level(AVS_LOG_WARNING);
    avs_log(test, DEBUG, "Testing DEBUG");
    avs_log(test, INFO, "Testing INFO");
    ASSERT_LOG(test, WARNING, "WARNING [test] [src/test/test_log.c:99]: Testing WARNING");
    avs_log(test, WARNING, "Testing WARNING");
    ASSERT_LOG(test, ERROR, "ERROR [test] [src/test/test_log.c:101]: Testing ERROR");
    avs_log(test, ERROR, "Testing ERROR");

    avs_log_set_default_level(AVS_LOG_ERROR);
    avs_log(test, DEBUG, "Testing DEBUG");
    avs_log(test, INFO, "Testing INFO");
    avs_log(test, WARNING, "Testing WARNING");
    ASSERT_LOG(test, ERROR, "ERROR [test] [src/test/test_log.c:108]: Testing ERROR");
    avs_log(test, ERROR, "Testing ERROR");

    avs_log_set_default_level(AVS_LOG_QUIET);
    avs_log(test, DEBUG, "Testing DEBUG");
    avs_log(test, INFO, "Testing INFO");
    avs_log(test, WARNING, "Testing WARNING");
    avs_log(test, ERROR, "Testing ERROR");

    ASSERT_LOG_CLEAN;
    reset_everything();
}

AVS_UNIT_TEST(log, module_levels) {
    avs_log_set_level(debugged_module, AVS_LOG_DEBUG);
    avs_log_set_level(stable_module, AVS_LOG_ERROR);

    ASSERT_LOG(debugged_module, DEBUG, "DEBUG [debugged_module] [src/test/test_log.c:125]: Testing DEBUG");
    avs_log(debugged_module, DEBUG, "Testing DEBUG");
    ASSERT_LOG(debugged_module, INFO, "INFO [debugged_module] [src/test/test_log.c:127]: Testing INFO");
    avs_log(debugged_module, INFO, "Testing INFO");
    ASSERT_LOG(debugged_module, WARNING, "WARNING [debugged_module] [src/test/test_log.c:129]: Testing WARNING");
    avs_log(debugged_module, WARNING, "Testing WARNING");
    ASSERT_LOG(debugged_module, ERROR, "ERROR [debugged_module] [src/test/test_log.c:131]: Testing ERROR");
    avs_log(debugged_module, ERROR, "Testing ERROR");

    avs_log(stable_module, DEBUG, "Testing DEBUG");
    avs_log(stable_module, INFO, "Testing INFO");
    avs_log(stable_module, WARNING, "Testing WARNING");
    ASSERT_LOG(stable_module, ERROR, "ERROR [stable_module] [src/test/test_log.c:137]: Testing ERROR");
    avs_log(stable_module, ERROR, "Testing ERROR");

    /* default level is INFO */
    avs_log(other_module, DEBUG, "Testing DEBUG");
    ASSERT_LOG(other_module, INFO, "INFO [other_module] [src/test/test_log.c:142]: Testing INFO");
    avs_log(other_module, INFO, "Testing INFO");
    ASSERT_LOG(other_module, WARNING, "WARNING [other_module] [src/test/test_log.c:144]: Testing WARNING");
    avs_log(other_module, WARNING, "Testing WARNING");
    ASSERT_LOG(other_module, ERROR, "ERROR [other_module] [src/test/test_log.c:146]: Testing ERROR");
    avs_log(other_module, ERROR, "Testing ERROR");

    ASSERT_LOG_CLEAN;
    reset_everything();
}

static int fail(void) {
    AVS_UNIT_ASSERT_TRUE(0);
    return -1;
}

static int success(void) {
    return 42;
}

AVS_UNIT_TEST(log, lazy_log) {
    avs_log_set_level(debugged_module, AVS_LOG_DEBUG);
    avs_log_set_level(stable_module, AVS_LOG_ERROR);

    ASSERT_LOG(debugged_module, DEBUG, "DEBUG [debugged_module] [src/test/test_log.c:166]: Testing DEBUG 42");
    avs_log(debugged_module, LAZY_DEBUG, "Testing DEBUG %d", success());
    ASSERT_LOG(debugged_module, INFO, "INFO [debugged_module] [src/test/test_log.c:168]: Testing INFO 42");
    avs_log(debugged_module, LAZY_INFO, "Testing INFO %d", success());
    ASSERT_LOG(debugged_module, WARNING, "WARNING [debugged_module] [src/test/test_log.c:170]: Testing WARNING 42");
    avs_log(debugged_module, LAZY_WARNING, "Testing WARNING %d", success());
    ASSERT_LOG(debugged_module, ERROR, "ERROR [debugged_module] [src/test/test_log.c:172]: Testing ERROR 42");
    avs_log(debugged_module, LAZY_ERROR, "Testing ERROR %d", success());

    avs_log(stable_module, LAZY_DEBUG, "Testing DEBUG %d", fail());
    avs_log(stable_module, LAZY_INFO, "Testing INFO %d", fail());
    avs_log(stable_module, LAZY_WARNING, "Testing WARNING %d", fail());
    ASSERT_LOG(stable_module, ERROR, "ERROR [stable_module] [src/test/test_log.c:178]: Testing ERROR 42");
    avs_log(stable_module, LAZY_ERROR, "Testing ERROR %d", success());

    /* default level is INFO */
    avs_log(other_module, LAZY_DEBUG, "Testing DEBUG %d", fail());
    ASSERT_LOG(other_module, INFO, "INFO [other_module] [src/test/test_log.c:183]: Testing INFO 42");
    avs_log(other_module, LAZY_INFO, "Testing INFO %d", success());
    ASSERT_LOG(other_module, WARNING, "WARNING [other_module] [src/test/test_log.c:185]: Testing WARNING 42");
    avs_log(other_module, LAZY_WARNING, "Testing WARNING %d", success());
    ASSERT_LOG(other_module, ERROR, "ERROR [other_module] [src/test/test_log.c:187]: Testing ERROR 42");
    avs_log(other_module, LAZY_ERROR, "Testing ERROR %d", success());

    ASSERT_LOG_CLEAN;
    reset_everything();
}
