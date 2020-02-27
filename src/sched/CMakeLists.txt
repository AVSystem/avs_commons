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

set(AVS_SCHED_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_sched.h")

add_library(avs_sched STATIC
            ${AVS_SCHED_PUBLIC_HEADERS}
            avs_sched.c)

target_link_libraries(avs_sched PUBLIC avs_commons_global_headers avs_list)

cmake_dependent_option(WITH_SCHEDULER_THREAD_SAFE "Enable thread-safe locking of scheduler structures" ON WITH_AVS_COMPAT_THREADING OFF)

avs_install_export(avs_sched sched)
install(FILES ${AVS_SCHED_PUBLIC_HEADERS}
        COMPONENT sched
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)

# On Linux, one needs to link libdl to use dlsym(). On BSD, it is not necessary,
# and even harmful, since libdl does not exist.
set(CMAKE_REQUIRED_INCLUDES "dlfcn.h")
foreach(lib "" dl)
    message(STATUS "Looking for dlsym() in library: ${lib}")
    set(CMAKE_REQUIRED_LIBRARIES ${lib})

    # check_function_exists caches its result; make sure the check is
    # actually repeated for each lib
    unset(HAVE_DLSYM CACHE)
    check_function_exists(dlsym HAVE_DLSYM)
    set(CMAKE_REQUIRED_LIBRARIES)

    if(HAVE_DLSYM)
        set(DETECTED_DLSYM_LIBRARY "${lib}" CACHE STRING "" FORCE)
        break()
    endif()
endforeach()
set(CMAKE_REQUIRED_INCLUDES)
set(DLSYM_LIBRARY "${DETECTED_DLSYM_LIBRARY}" CACHE STRING "Name of the library containing dlsym() symbol")

avs_add_test(NAME avs_sched
             LIBS avs_sched "${DLSYM_LIBRARY}"
             SOURCES $<TARGET_PROPERTY:avs_sched,SOURCES>
                     ${AVS_COMMONS_SOURCE_DIR}/tests/sched/test_sched.c)

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_sched PUBLIC avs_log)
    if(TARGET avs_sched_test)
        target_link_libraries(avs_sched_test PUBLIC avs_log)
    endif()
endif()

if(WITH_SCHEDULER_THREAD_SAFE)
    target_link_libraries(avs_sched PUBLIC avs_compat_threading)
endif()
