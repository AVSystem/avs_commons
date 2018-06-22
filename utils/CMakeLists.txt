# Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

add_library(avs_utils STATIC
            include_public/avsystem/commons/time.h
            include_public/avsystem/commons/memory.h
            include_public/avsystem/commons/utils.h

            src/x_time_conv.h

            src/cleanup.c
            src/hexlify.c
            src/numbers.c
            src/strings.c
            src/time.c
            src/token.c)

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
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_utils PUBLIC ${MATH_LIBRARY})

add_avs_test3(avs_utils)

avs_install_export3(avs_utils utils)
install(DIRECTORY include_public/
        COMPONENT utils
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
