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

if(NOT WITH_AVS_BUFFER OR NOT WITH_AVS_NET)
    message(STATUS "netstream disabled: requirements not met")
    return()
endif()

set(AVS_STREAM_NET_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_net.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_stream_netbuf.h")

add_library(avs_stream_net STATIC
            ${AVS_STREM_NET_PUBLIC_HEADERS}
            avs_stream_net.c
            avs_netbuf.c)

target_link_libraries(avs_stream_net PUBLIC avs_stream avs_buffer avs_net_core)

avs_install_export(avs_stream_net stream)
install(FILES ${AVS_STREAM_NET_PUBLIC_HEADERS}
        COMPONENT stream_net
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)
