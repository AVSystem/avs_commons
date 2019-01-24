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

add_library(avs_stream STATIC
            include_public/avsystem/commons/stream.h
            include_public/avsystem/commons/stream/stream_buffered.h
            include_public/avsystem/commons/stream/stream_file.h
            include_public/avsystem/commons/stream/stream_inbuf.h
            include_public/avsystem/commons/stream/stream_membuf.h
            include_public/avsystem/commons/stream/stream_outbuf.h
            include_public/avsystem/commons/stream/stream_simple_io.h
            include_public/avsystem/commons/stream_v_table.h

            src/stream.c
            src/stream_buffered.c
            src/stream_file.c
            src/stream_inbuf.c
            src/stream_membuf.c
            src/stream_outbuf.c
            src/stream_simple_io.c)

target_include_directories(avs_stream PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_stream PUBLIC avs_commons_global_headers avs_log)

avs_install_export(avs_stream stream)
install(DIRECTORY include_public/
        COMPONENT stream
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

avs_add_test(NAME avs_stream
             LIBS avs_stream
             SOURCES $<TARGET_PROPERTY:avs_stream,SOURCES>)

add_subdirectory(md5)
add_subdirectory(net)
