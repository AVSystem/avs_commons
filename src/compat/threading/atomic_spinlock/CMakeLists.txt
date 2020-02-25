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

option(WITH_AVS_COMPAT_THREADING_ATOMIC_SPINLOCK "Enable threading primitives implementation based on spinlocks and C11 atomics" ${HAVE_C11_STDATOMIC})
set(AVS_COMMONS_COMPAT_THREADING_WITH_ATOMIC_SPINLOCK ${WITH_AVS_COMPAT_THREADING_ATOMIC_SPINLOCK} CACHE INTERNAL "" FORCE)
if(NOT WITH_AVS_COMPAT_THREADING_ATOMIC_SPINLOCK)
    return()
endif()

add_library(avs_compat_threading_atomic_spinlock STATIC
            ${COMPAT_THREADING_PUBLIC_HEADERS}
            avs_atomic_spinlock_condvar.c
            avs_atomic_spinlock_init_once.c
            avs_atomic_spinlock_mutex.c
            avs_atomic_spinlock_structs.h)

target_link_libraries(avs_compat_threading_atomic_spinlock PUBLIC avs_utils)
if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_compat_threading_atomic_spinlock PUBLIC avs_log)
endif()

if(NOT TARGET avs_compat_threading)
    add_library(avs_compat_threading ALIAS avs_compat_threading_atomic_spinlock)
endif()

avs_install_export(avs_compat_threading_atomic_spinlock threading)

find_package(Threads)
if(WITH_TEST AND THREADS_FOUND)
    avs_add_test(NAME avs_compat_threading_atomic_spinlock
                 LIBS avs_compat_threading_atomic_spinlock ${CMAKE_THREAD_LIBS_INIT}
                 SOURCES ${COMPAT_THREADING_TEST_SOURCES}
                 VALGRIND_ARGS "--fair-sched=yes")
endif()
