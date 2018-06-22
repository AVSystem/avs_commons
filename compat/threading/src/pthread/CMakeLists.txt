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

find_package(Threads)
cmake_dependent_option(WITH_AVS_COMPAT_THREADING_PTHREAD "Enable threading primitives implementation based on pthreads" ON THREADS_FOUND OFF)
if(NOT WITH_AVS_COMPAT_THREADING_PTHREAD)
    return()
endif()

add_library(avs_compat_threading_pthread STATIC
            ${COMPAT_THREADING_PUBLIC_HEADERS}
            mutex.c
            init_once.c)
target_include_directories(avs_compat_threading_pthread PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_compat_threading_pthread PUBLIC avs_utils ${CMAKE_THREAD_LIBS_INIT})

if(NOT TARGET avs_compat_threading)
    add_library(avs_compat_threading ALIAS avs_compat_threading_pthread)
endif()

avs_install_export3(avs_compat_threading_pthread threading)

if(WITH_TEST AND THREADS_FOUND)
    add_avs_test3(NAME avs_compat_threading_pthread
                  LIBS avs_compat_threading_pthread ${CMAKE_THREAD_LIBS_INIT}
                  SOURCES ${COMPAT_THREADING_TEST_SOURCES})
endif()
