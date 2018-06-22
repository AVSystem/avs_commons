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

set(SOURCES
    mutex.c
    init_once.c)

include_directories(../../../../utils/include_public)

add_library(avs_compat_threading_atomic_spinlock STATIC ${SOURCES})
avs_install_export(avs_compat_threading_atomic_spinlock threading)

if(NOT TARGET avs_compat_threading)
    add_library(avs_compat_threading ALIAS avs_compat_threading_atomic_spinlock)
endif()

find_package(Threads)
if(WITH_TEST AND THREADS_FOUND)
    add_avs_test(avs_compat_threading_atomic_spinlock
                 ${COMMON_SOURCES}
                 ${COMMON_TEST_SOURCES}
                 ${SOURCES})
    target_link_libraries(avs_compat_threading_atomic_spinlock_test ${CMAKE_THREAD_LIBS_INIT})
endif()
