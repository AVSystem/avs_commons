#ifndef AVS_COMMONS_UNIT_SRC_TEST_H
#define AVS_COMMONS_UNIT_SRC_TEST_H

void _avs_unit_test_fail_printf(const char *file,
                                int line,
                                const char *format,
                                ...);

void _avs_unit_assert_fail(const char *file,
                           int line,
                           const char *format,
                           ...);

#define _avs_unit_assert(Condition, File, Line, ...) \
    do { \
        if (!(Condition)) { \
            _avs_unit_assert_fail((File), (Line), __VA_ARGS__); \
        } \
    } while (0)

#endif /* AVS_COMMONS_UNIT_SRC_TEST_H */
