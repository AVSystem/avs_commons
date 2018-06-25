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

add_library(avs_list STATIC
            include_public/avsystem/commons/list.h

            src/list.c)

target_include_directories(avs_list PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_list PUBLIC avs_utils)

avs_install_export(avs_list list)
install(DIRECTORY include_public/
        COMPONENT list
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

add_avs_test(NAME avs_list
             LIBS avs_list
             SOURCES
             $<TARGET_PROPERTY:avs_list,SOURCES>
             src/test/test_list.c)

if(WITH_CXX_TESTS)
    add_avs_test(NAME avs_list_cxx
                 LIBS avs_list
                 SOURCES
                 $<TARGET_PROPERTY:avs_list,SOURCES>
                 src/test/test_list_cxx.cpp)
endif()
