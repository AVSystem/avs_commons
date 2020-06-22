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

set(AVS_UNIT_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_unit_memstream.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_unit_mock_helpers.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_unit_mocksock.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_unit_test.h")

add_library(avs_unit STATIC
            ${AVS_UNIT_PUBLIC_HEADERS}
            avs_mock.c
            avs_stack_trace.c
            avs_unit_test.c)

target_link_libraries(avs_unit PUBLIC avs_commons_global_headers avs_list)

if(WITH_AVS_LOG)
    target_link_libraries(avs_unit PUBLIC avs_log)
endif()

if(WITH_AVS_NET)
    target_sources(avs_unit PRIVATE avs_mocksock.c)
    target_link_libraries(avs_unit PUBLIC avs_net_core)
endif()

if(WITH_AVS_STREAM)
    target_sources(avs_unit PRIVATE avs_memstream.c)
    target_link_libraries(avs_unit PUBLIC avs_stream)
endif()

avs_install_export(avs_unit unit)
install(FILES ${AVS_UNIT_PUBLIC_HEADERS}
        COMPONENT unit
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)
