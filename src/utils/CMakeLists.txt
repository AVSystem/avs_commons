# Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/cleanup.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/memory.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/shared_buffer.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/time.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/utils.h")

add_library(avs_utils STATIC
            ${AVS_UTILS_PUBLIC_HEADERS}
            x_time_conv.h

            cleanup.c
            hexlify.c
            numbers.c
            shared_buffer.c
            strings.c
            strerror.c
            time.c
            token.c)

if(UNIX OR WIN32)
    set(POSIX_AVS_TIME_DEFAULT ON)
else()
    set(POSIX_AVS_TIME_DEFAULT OFF)
endif()

option(WITH_POSIX_AVS_TIME "Enable avs_time_real_now() and avs_time_monotonic_now() implementation based on POSIX clock_gettime()" "${POSIX_AVS_TIME_DEFAULT}")
if(WITH_POSIX_AVS_TIME)
    target_sources(avs_utils PRIVATE
                   compat/posix/compat_time.c)
endif()

option(WITH_STANDARD_ALLOCATOR "Enable default implementation of avs_malloc/calloc/realloc/free" ON)
if(WITH_STANDARD_ALLOCATOR)
    target_sources(avs_utils PRIVATE
                   compat/stdlib/memory.c)
endif()

target_include_directories(avs_utils PUBLIC
                           $<BUILD_INTERFACE:${AVS_COMMONS_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_utils PUBLIC avs_commons_global_headers ${MATH_LIBRARY})
if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_utils PUBLIC avs_log)
endif()

avs_add_test(NAME avs_utils
             LIBS avs_utils
             SOURCES
             $<TARGET_PROPERTY:avs_utils,SOURCES>
             ${AVS_COMMONS_SOURCE_DIR}/tests/utils/memory.c
             ${AVS_COMMONS_SOURCE_DIR}/tests/utils/shared_buffer.c)

avs_install_export(avs_utils utils)
install(FILES ${AVS_UTILS_PUBLIC_HEADERS}
        COMPONENT utils
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)
