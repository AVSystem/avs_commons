#ifndef AVS_COMMONS_UNIT_SRC_TEST_H
#define AVS_COMMONS_UNIT_SRC_TEST_H

void _avs_unit_test_fail_printf(const char *file,
                                int line,
                                const char *format,
                                ...);

void _avs_unit_assert(bool condition,
                      const char *file,
                      int line,
                      const char *format,
                      ...);

#endif /* AVS_COMMONS_UNIT_SRC_TEST_H */
