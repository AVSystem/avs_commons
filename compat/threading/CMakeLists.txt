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

set(PUBLIC_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include_public/avsystem/commons/mutex.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include_public/avsystem/commons/init_once.h)

set(COMMON_SOURCES ${PUBLIC_HEADERS})
set(COMMON_TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/mutex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/init_once.c)

set(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public")

set(avs_compat_threading_INCLUDE_DIRS ${INCLUDE_DIRS} PARENT_SCOPE)

include_directories(${INCLUDE_DIRS})

option(WITH_CUSTOM_AVS_THREADING "Do not provide any default implementations of avs_threading" OFF)
if(NOT WITH_CUSTOM_AVS_THREADING)
# NOTE: first available implementation defines default avs_compat_threading targets
    add_subdirectory(src/atomic_spinlock)
    add_subdirectory(src/pthread)
endif()

if(NOT TARGET avs_compat_threading)
    message(WARNING "No default implementation of threading compatibility layer! "
            "Some symbols will need to be user-provided.")
    # Add fake avs_compat_threading "library" just so that other components
    # have something to link to
    add_library(avs_compat_threading INTERFACE)
    avs_install_export(avs_compat_threading compat_threading)
endif()

install(DIRECTORY include_public/
        COMPONENT compat_threading
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
