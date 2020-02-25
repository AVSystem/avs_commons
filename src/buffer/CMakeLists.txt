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

set(AVS_BUFFER_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_buffer.h")

add_library(avs_buffer STATIC
            ${AVS_BUFFER_PUBLIC_HEADERS}
            avs_buffer.c)

target_link_libraries(avs_buffer PUBLIC avs_commons_global_headers avs_utils)

avs_install_export(avs_buffer buffer)
install(FILES ${AVS_BUFFER_PUBLIC_HEADERS}
        COMPONENT buffer
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)

avs_add_test(NAME avs_buffer
             LIBS avs_buffer
             SOURCES $<TARGET_PROPERTY:avs_buffer,SOURCES>)

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_buffer PUBLIC avs_log)
    if(TARGET avs_buffer_test)
        target_link_libraries(avs_buffer_test PUBLIC avs_log)
    endif()
endif()
