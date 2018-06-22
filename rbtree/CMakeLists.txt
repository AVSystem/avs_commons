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

add_library(avs_rbtree STATIC
            include_public/avsystem/commons/rbtree.h

            src/rbtree.c)

target_include_directories(avs_rbtree PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_rbtree PUBLIC avs_utils)

avs_install_export3(avs_rbtree rbtree)
install(DIRECTORY include_public/
        COMPONENT rbtree
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

add_avs_test3(avs_rbtree ${ALL_SOURCES})

# TODO: fix this
#if(WITH_CXX_TESTS)
#    add_avs_test(avs_rbtree_cxx src/test/test_rbtree_cxx.cpp)
#endif()
