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

set(AVS_STREAM_PUBLIC_HEADERS_ROOT
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_v_table.h")

set(AVS_STREAM_PUBLIC_HEADERS_STREAM
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/stream/stream_buffered.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/stream/stream_file.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/stream/stream_inbuf.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/stream/stream_membuf.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/stream/stream_outbuf.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/stream/stream_simple_io.h")

add_library(avs_stream STATIC
            ${AVS_STREAM_PUBLIC_HEADERS_ROOT}
            ${AVS_STREAM_PUBLIC_HEADERS_STREAM}
            stream.c
            stream_buffered.c
            stream_file.c
            stream_inbuf.c
            stream_membuf.c
            stream_outbuf.c
            stream_simple_io.c)

target_link_libraries(avs_stream PUBLIC avs_commons_global_headers avs_buffer)
if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_stream PUBLIC avs_log)
endif()

avs_install_export(avs_stream stream)
install(FILES ${AVS_STREAM_PUBLIC_HEADERS_ROOT}
        COMPONENT stream
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)
install(FILES ${AVS_STREAM_PUBLIC_HEADERS_STREAM}
        COMPONENT stream
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons/stream)

avs_add_test(NAME avs_stream
             LIBS avs_stream
             SOURCES $<TARGET_PROPERTY:avs_stream,SOURCES>)

add_subdirectory(md5)
add_subdirectory(net)
