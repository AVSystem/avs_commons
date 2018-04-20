# Copyright 2018 AVSystem <avsystem@avsystem.com>
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
    src/persistence.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/persistence.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

set(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public")

set(avs_persistence_INCLUDE_DIRS ${INCLUDE_DIRS} PARENT_SCOPE)

include_directories(${INCLUDE_DIRS})

add_library(avs_persistence STATIC ${ALL_SOURCES})
avs_emit_deps(avs_persistence avs_list avs_rbtree avs_stream avs_utils)

add_avs_test(avs_persistence ${ALL_SOURCES})
if(TARGET avs_persistence_test)
    target_link_libraries(avs_persistence_test
                          ${AVS_TARGET_DEPS_avs_persistence})
endif()

avs_install_export(avs_persistence persistence)
install(DIRECTORY include_public/
        COMPONENT persistence
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
