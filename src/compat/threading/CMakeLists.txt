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

set(COMPAT_THREADING_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_condvar.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_mutex.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_init_once.h")

set(COMPAT_THREADING_TEST_SOURCES
    ${AVS_COMMONS_SOURCE_DIR}/tests/compat/threading/condvar.c
    ${AVS_COMMONS_SOURCE_DIR}/tests/compat/threading/mutex.c
    ${AVS_COMMONS_SOURCE_DIR}/tests/compat/threading/init_once.c)

option(WITH_CUSTOM_AVS_THREADING "Do not provide any default implementations of avs_threading" OFF)
if(NOT WITH_CUSTOM_AVS_THREADING)
# NOTE: first available implementation defines default avs_compat_threading targets
    add_subdirectory(atomic_spinlock)
    add_subdirectory(pthread)
endif()

if(NOT TARGET avs_compat_threading)
    message(WARNING "No default implementation of threading compatibility layer! "
            "Some symbols will need to be user-provided.")
    # Add fake avs_compat_threading "library" just so that other components
    # have something to link to
    add_library(avs_compat_threading INTERFACE)
    target_link_libraries(avs_compat_threading INTERFACE avs_commons_global_headers)
endif()
avs_install_export(avs_compat_threading compat_threading)

install(FILES ${COMPAT_THREADING_PUBLIC_HEADERS}
        COMPONENT compat_threading
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)
