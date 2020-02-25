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

set(AVS_VECTOR_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_vector.h")

add_library(avs_vector STATIC
            ${AVS_VECTOR_PUBLIC_HEADERS}
            avs_vector.c)

target_link_libraries(avs_vector PUBLIC avs_commons_global_headers avs_utils)

avs_install_export(avs_vector vector)
install(FILES ${AVS_VECTOR_PUBLIC_HEADERS}
        COMPONENT vector
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)

avs_add_test(NAME avs_vector
             LIBS avs_vector
             SOURCES $<TARGET_PROPERTY:avs_vector,SOURCES>)

if(WITH_CXX_TESTS)
    avs_add_test(NAME avs_vector_cxx
                 LIBS avs_vector
                 SOURCES ${AVS_COMMONS_SOURCE_DIR}/tests/vector/test_vector_cxx.cpp)
endif()
