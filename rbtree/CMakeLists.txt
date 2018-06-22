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
    src/rbtree.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/rbtree.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

set(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public")

set(avs_rbtree_INCLUDE_DIRS ${INCLUDE_DIRS} PARENT_SCOPE)

include_directories(${INCLUDE_DIRS}
                    ../utils/include_public)

add_library(avs_rbtree STATIC ${ALL_SOURCES})

avs_install_export(avs_rbtree rbtree)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT rbtree
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

include_directories(${AVS_TEST_INCLUDE_DIRS}
                    "../unit/include_public")
add_avs_test(avs_rbtree ${ALL_SOURCES})
if(WITH_CXX_TESTS)
    add_avs_test(avs_rbtree_cxx src/test/test_rbtree_cxx.cpp)
endif()
