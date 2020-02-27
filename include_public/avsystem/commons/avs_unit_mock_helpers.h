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

#ifndef AVS_COMMONS_UNIT_MOCK_HELPERS_H
#define AVS_COMMONS_UNIT_MOCK_HELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file avs_mock_helpers.h
 *
 * This file allows mocking specific functions for testing purposes. It works
 * by replacing specific functions with macros that can be configured at test
 * time.
 *
 * <example>
 * The following code snippets demonstrate how to use this feature.
 *
 * Example file under test:
 *
 * @code
 * #ifdef UNIT_TESTING
 * #include "safe_malloc_mocks.h"
 * #endif
 *
 * void *safe_malloc(size_t size) {
 *     void *result = malloc(size);
 *     if (!result) {
 *         abort();
 *     }
 * }
 *
 * #ifdef UNIT_TESTING
 * #include "safe_malloc_test.c"
 * #endif
 * @endcode
 *
 * <c>safe_malloc_mocks.h</c>:
 *
 * @code
 * #include <avsystem/commons/avs_unit_mock_helpers.h>
 *
 * AVS_UNIT_MOCK_CREATE(malloc)
 * #define malloc(...) AVS_UNIT_MOCK_WRAPPER(malloc)(__VA_ARGS__)
 *
 * AVS_UNIT_MOCK_CREATE(abort)
 * #define abort(...) AVS_UNIT_MOCK_WRAPPER(abort)(__VA_ARGS__)
 * @endcode
 *
 * <c>safe_malloc_test.c</c>:
 *
 * @code
 * #include <avsystem/commons/avs_unit_test.h>
 *
 * static void *failing_malloc(size_t size) {
 *     return NULL;
 * }
 *
 * static void fake_abort(void) {
 *     // do nothing
 * }
 *
 * AVS_UNIT_TEST(safe_malloc, null) {
 *     AVS_UNIT_MOCK(malloc) = failing_malloc;
 *     AVS_UNIT_MOCK(abort) = fake_abort;
 *     safe_malloc(512);
 *     AVS_UNIT_ASSERT_EQUAL(AVS_UNIT_MOCK_INVOCATIONS(malloc), 1);
 *     AVS_UNIT_ASSERT_EQUAL(AVS_UNIT_MOCK_INVOCATIONS(abort), 1);
 * }
 * @endcode
 * </example>
 */

/**
 * Gets the function pointer mocking a specified function, as an lvalue.
 *
 * @param _function_to_mock Name of the mocked function.
 *
 * @return lvalue referring to a function pointer which will be invoked instead
 *         of the original function, if not <c>NULL</c>.
 */
#define AVS_UNIT_MOCK(_function_to_mock) AVS_UNIT_MOCK_##_function_to_mock

/**
 * Wraps invocation to a specific mocked function.
 *
 * Returns a function object either referred to by the mock function pointer, or
 * the original function (if the mock is <c>NULL</c>), and increases the
 * invocation counter.
 *
 * This macro should be used when defining mock macros. See the file-level
 * example for usage.
 *
 * @param _function_to_wrap Name of the mocked function.
 *
 * @return Mocked callable.
 */
#define AVS_UNIT_MOCK_WRAPPER(_function_to_wrap)                            \
    (avs_unit_mock_invoke__(                                                \
             (avs_unit_mock_func_ptr *) &AVS_UNIT_MOCK(_function_to_wrap)), \
     (AVS_UNIT_MOCK(_function_to_wrap) ? AVS_UNIT_MOCK(_function_to_wrap)   \
                                       : _function_to_wrap))

/**
 * Internal functions used by the library to implement the functionality.
 */
/**@{*/
typedef void (*avs_unit_mock_func_ptr)(void);

void avs_unit_mock_add__(avs_unit_mock_func_ptr *new_mock_ptr);
void avs_unit_mock_reset_all__();
void avs_unit_mock_cleanup__();
void avs_unit_mock_invoke__(avs_unit_mock_func_ptr *invoked_func);
unsigned avs_unit_mock_invocations__(avs_unit_mock_func_ptr *invoked_func);
/**@}*/

/**
 * Gets the number of mocked function invocations during the current unit test.
 *
 * @param func Name of the mocked function.
 *
 * @return Number of times the function was invoked.
 */
#define AVS_UNIT_MOCK_INVOCATIONS(func) \
    avs_unit_mock_invocations__((avs_unit_mock_func_ptr *) &AVS_UNIT_MOCK(func))

/**
 * Declares and defines a mocked function pointer.
 *
 * @param _function_to_mock Name of the mocked function.
 */
#define AVS_UNIT_MOCK_CREATE(_function_to_mock)                                \
    static __typeof__(_function_to_mock) *AVS_UNIT_MOCK(_function_to_mock);    \
    static void _avs_unit_mock_constructor_##_function_to_mock(void)           \
            __attribute__((constructor));                                      \
    static void _avs_unit_mock_constructor_##_function_to_mock(void) {         \
        avs_unit_mock_add__(                                                   \
                (avs_unit_mock_func_ptr *) &AVS_UNIT_MOCK(_function_to_mock)); \
    }

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_UNIT_MOCK_HELPERS_H */
