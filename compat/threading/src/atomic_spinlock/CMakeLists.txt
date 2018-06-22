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

option(WITH_AVS_COMPAT_THREADING_ATOMIC_SPINLOCK "Enable threading primitives implementation based on spinlocks and C11 atomics" ${HAVE_C11_STDATOMIC})
if(NOT WITH_AVS_COMPAT_THREADING_ATOMIC_SPINLOCK)
    return()
endif()

add_library(avs_compat_threading_atomic_spinlock STATIC
            ${COMPAT_THREADING_PUBLIC_HEADERS}
            mutex.c
            init_once.c)

target_include_directories(avs_compat_threading_atomic_spinlock PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_compat_threading_atomic_spinlock PUBLIC avs_utils avs_log)

if(NOT TARGET avs_compat_threading)
    add_library(avs_compat_threading ALIAS avs_compat_threading_atomic_spinlock)
endif()

avs_install_export3(avs_compat_threading_atomic_spinlock threading)

find_package(Threads)
if(WITH_TEST AND THREADS_FOUND)
    add_avs_test3(NAME avs_compat_threading_atomic_spinlock
                  LIBS avs_compat_threading_atomic_spinlock ${CMAKE_THREAD_LIBS_INIT}
                  SOURCES ${COMPAT_THREADING_TEST_SOURCES})
endif()
