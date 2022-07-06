# Copyright 2022 AVSystem <avsystem@avsystem.com>
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

set(AVS_PERSISTENCE_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_persistence.h")

add_library(avs_persistence STATIC
            ${AVS_PERSISTENCE_PUBLIC_HEADERS}
            avs_persistence.c)

set(AVS_PERSISTENCE_DEP avs_commons_global_headers avs_stream avs_utils avs_list)
if(AVS_COMMONS_WITH_AVS_RBTREE)
    list(APPEND AVS_PERSISTENCE_DEP avs_rbtree)
endif()
if(AVS_COMMONS_WITH_AVS_SORTED_SET)
    list(APPEND AVS_PERSISTENCE_DEP avs_sorted_set)
endif()
target_link_libraries(avs_persistence PUBLIC ${AVS_PERSISTENCE_DEP})

avs_install_export(avs_persistence persistence)
install(FILES ${AVS_PERSISTENCE_PUBLIC_HEADERS}
        COMPONENT persistence
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)

avs_add_test(NAME avs_persistence
             LIBS avs_persistence
             SOURCES $<TARGET_PROPERTY:avs_persistence,SOURCES>)
