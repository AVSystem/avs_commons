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

set(SOURCES
    mutex.c
    init_once.c)

include_directories(../../../../utils/include_public)

add_library(avs_compat_threading_pthread STATIC ${SOURCES})
target_link_libraries(avs_compat_threading_pthread ${CMAKE_THREAD_LIBS_INIT})
avs_install_export(avs_compat_threading_pthread threading)

if(NOT TARGET avs_compat_threading)
    add_library(avs_compat_threading ALIAS avs_compat_threading_pthread)
endif()

if(WITH_TEST AND THREADS_FOUND)
    add_avs_test(avs_compat_threading_pthread
                 ${COMMON_SOURCES}
                 ${COMMON_TEST_SOURCES}
                 ${SOURCES})
    target_link_libraries(avs_compat_threading_pthread_test ${CMAKE_THREAD_LIBS_INIT})
endif()
