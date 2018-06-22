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

set(SOURCES
    src/log.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/log.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

set(INCLUDE_DIRS
    include_public
    ../list/include_public
    ../compat/threading/include_public
    ../utils/include_public)
make_absolute_sources(ABSOLUTE_INCLUDE_DIRS ${INCLUDE_DIRS})
set(AVS_TEST_INCLUDE_DIRS "${ABSOLUTE_INCLUDE_DIRS}" PARENT_SCOPE)

include_directories(${INCLUDE_DIRS})

set(avs_log_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public" PARENT_SCOPE)

add_library(avs_log STATIC ${ALL_SOURCES})
target_link_libraries(avs_log avs_list)

if(WITH_AVS_COMPAT_THREADING)
    target_link_libraries(avs_log avs_compat_threading)
endif()

avs_install_export(avs_log log)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT log
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

include_directories(${AVS_TEST_INCLUDE_DIRS})
add_avs_test(avs_log ${ALL_SOURCES})
