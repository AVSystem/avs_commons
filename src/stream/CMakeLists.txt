# Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

option(WITH_AVS_STREAM_FILE "Enable support for file I/O in avs_stream" ON)

set(AVS_STREAM_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_buffered.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_file.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_inbuf.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_membuf.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_outbuf.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_simple_io.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_v_table.h")

add_library(avs_stream STATIC
            ${AVS_STREAM_PUBLIC_HEADERS}
            avs_stream.c
            avs_stream_buffered.c
            avs_stream_file.c
            avs_stream_inbuf.c
            avs_stream_membuf.c
            avs_stream_outbuf.c
            avs_stream_simple_io.c)

target_link_libraries(avs_stream PUBLIC avs_commons_global_headers avs_buffer)
if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_stream PUBLIC avs_log)
endif()

avs_install_export(avs_stream stream)
install(FILES ${AVS_STREAM_PUBLIC_HEADERS}
        COMPONENT stream
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)

avs_add_test(NAME avs_stream
             LIBS avs_stream
             SOURCES $<TARGET_PROPERTY:avs_stream,SOURCES>)

add_subdirectory(md5)
add_subdirectory(net)
