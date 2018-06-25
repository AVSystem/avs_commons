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

add_library(avs_algorithm STATIC
            include_public/avsystem/commons/base64.h

            src/base64.c)

target_include_directories(avs_algorithm PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_algorithm PUBLIC avs_commons_config)

avs_add_test(NAME avs_algorithm
             LIBS avs_algorithm
             SOURCES $<TARGET_PROPERTY:avs_algorithm,SOURCES>)

avs_install_export(avs_algorithm algorithm)
install(DIRECTORY include_public/
        COMPONENT algorithm
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
