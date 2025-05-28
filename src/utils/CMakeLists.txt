# Copyright 2025 AVSystem <avsystem@avsystem.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(AVS_UTILS_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_cleanup.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_memory.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_shared_buffer.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_time.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_utils.h")

set(AVS_UTILS_COMMON_SOURCES
    ${AVS_UTILS_PUBLIC_HEADERS}
    avs_x_time_conv.h

    avs_cleanup.c
    avs_hexlify.c
    avs_numbers.c
    avs_shared_buffer.c
    avs_strings.c
    avs_strerror.c
    avs_time.c
    avs_token.c)

add_library(avs_utils STATIC
            ${AVS_UTILS_COMMON_SOURCES}
            compat/posix/avs_compat_time.c
            compat/stdlib/avs_memory.c
            compat/stdlib/avs_memory_alignfix.c)

if(UNIX OR WIN32)
    set(POSIX_AVS_TIME_DEFAULT ON)
else()
    set(POSIX_AVS_TIME_DEFAULT OFF)
endif()

option(WITH_POSIX_AVS_TIME "Enable avs_time_real_now() and avs_time_monotonic_now() implementation based on POSIX clock_gettime()" "${POSIX_AVS_TIME_DEFAULT}")

option(WITH_STANDARD_ALLOCATOR "Enable default implementation of avs_malloc/calloc/realloc/free" ON)
cmake_dependent_option(WITH_ALIGNFIX_ALLOCATOR
                       "Enable alternative implementation of avs_malloc/calloc/realloc/free that works around platforms where the standard allocator has broken alignment guarantees"
                       OFF "NOT WITH_STANDARD_ALLOCATOR" OFF)

target_link_libraries(avs_utils PUBLIC avs_commons_global_headers ${MATH_LIBRARY})
if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_utils PUBLIC avs_log)
endif()

avs_add_test(NAME avs_utils
             LIBS avs_utils
                  $<$<BOOL:${WITH_AVS_SCHED}>:avs_sched>
                  $<$<BOOL:${WITH_AVS_NET}>:avs_net>
             SOURCES
             $<TARGET_PROPERTY:avs_utils,SOURCES>
             ${AVS_COMMONS_SOURCE_DIR}/tests/utils/memory.c
             ${AVS_COMMONS_SOURCE_DIR}/tests/utils/shared_buffer.c)

if(WITH_TEST AND NOT WITH_ALIGNFIX_ALLOCATOR)
    # Let's run tests of the alignfix allocator even if it's disabled
    add_library(avs_utils_for_alignfix_test STATIC EXCLUDE_FROM_ALL
                ${AVS_UTILS_COMMON_SOURCES}
                compat/stdlib/avs_memory_alignfix.c)
    target_link_libraries(avs_utils_for_alignfix_test PUBLIC $<TARGET_PROPERTY:avs_utils,LINK_LIBRARIES>)
    target_compile_definitions(avs_utils_for_alignfix_test PRIVATE
                               AVS_SUPPRESS_POISONING
                               AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR
                               malloc=_avs_alignfix_test_malloc
                               calloc=_avs_alignfix_test_calloc
                               realloc=_avs_alignfix_test_realloc
                               free=_avs_alignfix_test_free)
    target_compile_definitions(avs_utils_for_alignfix_test PUBLIC
                               AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST)
    avs_add_test(NAME avs_utils_with_alignfix
                 LIBS avs_utils_for_alignfix_test
                      $<$<BOOL:${WITH_AVS_SCHED}>:avs_sched>
                      $<$<BOOL:${WITH_AVS_NET}>:avs_net>
                 SOURCES
                 ${AVS_COMMONS_SOURCE_DIR}/tests/utils/memory.c)
endif()

avs_install_export(avs_utils utils)
install(FILES ${AVS_UTILS_PUBLIC_HEADERS}
        COMPONENT utils
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)
