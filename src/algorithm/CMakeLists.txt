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

set(AVS_ALGORITHM_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_base64.h")

add_library(avs_algorithm STATIC
            ${AVS_ALGORITHM_PUBLIC_HEADERS}
            avs_base64.c)

target_link_libraries(avs_algorithm PUBLIC avs_commons_global_headers)

avs_add_test(NAME avs_algorithm
             LIBS avs_algorithm
             SOURCES $<TARGET_PROPERTY:avs_algorithm,SOURCES>)

avs_install_export(avs_algorithm algorithm)
install(FILES ${AVS_ALGORITHM_PUBLIC_HEADERS}
        COMPONENT algorithm
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)
