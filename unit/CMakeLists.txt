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

add_library(avs_unit STATIC
            include_public/avsystem/commons/unit/memstream.h
            include_public/avsystem/commons/unit/mock_helpers.h
            include_public/avsystem/commons/unit/mocksock.h
            include_public/avsystem/commons/unit/test.h

            src/mock.c
            src/test.c
            src/stack_trace.c)

target_include_directories(avs_unit PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_unit PUBLIC avs_commons_global_headers)

if(WITH_AVS_LOG)
    target_link_libraries(avs_unit PUBLIC avs_log)
endif()

if(WITH_AVS_NET)
    target_sources(avs_unit PRIVATE src/mocksock.c)
    target_link_libraries(avs_unit PUBLIC avs_net)
endif()

if(WITH_AVS_STREAM)
    target_sources(avs_unit PRIVATE src/memstream.c)
    target_link_libraries(avs_unit PUBLIC avs_stream)
endif()

avs_install_export(avs_unit unit)
install(DIRECTORY include_public/
        COMPONENT unit
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
