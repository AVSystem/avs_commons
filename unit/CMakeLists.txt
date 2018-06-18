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
    src/mock.c
    src/test.c
    src/stack_trace.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/unit/memstream.h
    include_public/avsystem/commons/unit/mock_helpers.h
    include_public/avsystem/commons/unit/mocksock.h
    include_public/avsystem/commons/unit/test.h)

set(INCLUDE_DIRS include_public
    ../list/include_public
    ../log/include_public
    ../utils/include_public)
set(DEPS_LIBRARIES avs_list avs_utils)

if(WITH_AVS_LOG)
    set(DEPS_LIBRARIES ${DEPS_LIBRARIES} avs_log)
endif()

if(WITH_AVS_NET)
    set(SOURCES ${SOURCES} src/mocksock.c)
    set(DEPS_LIBRARIES ${DEPS_LIBRARIES} avs_net)
    set(INCLUDE_DIRS ${INCLUDE_DIRS} ../net/include_public)
endif()

if(WITH_AVS_STREAM)
    set(SOURCES ${SOURCES} src/memstream.c)
    set(DEPS_LIBRARIES ${DEPS_LIBRARIES} avs_stream)
    set(INCLUDE_DIRS ${INCLUDE_DIRS} ../stream/include_public)
endif()

make_absolute_sources(ABSOLUTE_INCLUDE_DIRS ${INCLUDE_DIRS})
set(AVS_TEST_INCLUDE_DIRS "${ABSOLUTE_INCLUDE_DIRS}" PARENT_SCOPE)

include_directories(${INCLUDE_DIRS})

set(avs_unit_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public" PARENT_SCOPE)

add_library(avs_unit STATIC ${SOURCES} ${PUBLIC_HEADERS})
target_link_libraries(avs_unit ${DEPS_LIBRARIES})

avs_install_export(avs_unit unit)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT unit
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
