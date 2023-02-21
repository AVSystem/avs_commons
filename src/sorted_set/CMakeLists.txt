# Copyright 2023 AVSystem <avsystem@avsystem.com>
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

set(AVS_SORTED_SET_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_sorted_set.h")

add_library(avs_sorted_set STATIC
            ${AVS_SORTED_SET_PUBLIC_HEADERS}
            avs_sorted_set.c)

set(AVS_SORTED_SET_DEP avs_commons_global_headers avs_utils avs_list)
if(AVS_COMMONS_WITH_AVS_RBTREE)
    list(APPEND AVS_SORTED_SET_DEP avs_rbtree)
endif()
target_link_libraries(avs_sorted_set PUBLIC ${AVS_SORTED_SET_DEP})

avs_install_export(avs_sorted_set sorted_set)
install(FILES ${AVS_SORTED_SET_PUBLIC_HEADERS}
        COMPONENT sorted_set
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)

avs_add_test(NAME avs_sorted_set
             LIBS avs_sorted_set
             SOURCES $<TARGET_PROPERTY:avs_sorted_set,SOURCES>)

if(WITH_CXX_TESTS)
    avs_add_test(NAME avs_sorted_set_cxx
                 LIBS avs_sorted_set
                 SOURCES
                 SOURCES ${AVS_COMMONS_SOURCE_DIR}/tests/sorted_set/test_sorted_set_cxx.cpp)
endif()
