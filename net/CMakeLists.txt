# Copyright 2017 AVSystem <avsystem@avsystem.com>
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

set(SOURCES
    src/addrinfo.c
    src/api.c
    src/url.c)

if(NOT HAVE_INET_NTOP)
    set(SOURCES ${SOURCES} src/inet_ntop.c)
endif()

if(NOT HAVE_INET_PTON)
    set(SOURCES ${SOURCES} src/inet_pton.c)
endif()

if(WITH_OPENSSL)
    set(SOURCES ${SOURCES} src/openssl.c)
elseif(WITH_MBEDTLS)
    set(SOURCES ${SOURCES} src/mbedtls.c)
elseif(WITH_TINYDTLS)
    set(SOURCES ${SOURCES} src/tinydtls.c)
endif()

set(PRIVATE_HEADERS
    src/net_impl.h)

if(AVS_COMMONS_COMPAT_PLATFORM)
    set(SOURCES ${SOURCES}
        compat/${AVS_COMMONS_COMPAT_PLATFORM}/addrinfo.c
        compat/${AVS_COMMONS_COMPAT_PLATFORM}/net_impl.c)
    set(PRIVATE_HEADERS ${PRIVATE_HEADERS}
        compat/${AVS_COMMONS_COMPAT_PLATFORM}/compat.h)
endif()

set(PUBLIC_HEADERS
    include_public/avsystem/commons/net.h
    include_public/avsystem/commons/socket_v_table.h
    include_public/avsystem/commons/url.h)

set(ALL_SOURCES ${SOURCES} ${PRIVATE_HEADERS} ${PUBLIC_HEADERS})

set(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public")

set(avs_net_INCLUDE_DIRS ${INCLUDE_DIRS} PARENT_SCOPE)

include_directories(${INCLUDE_DIRS})

add_library(avs_net STATIC ${ALL_SOURCES})
if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_net avs_log)
    include_directories(../log/include_public)
endif()

if(WITH_OPENSSL)
    avs_emit_deps(avs_net ssl crypto)
elseif(WITH_MBEDTLS)
    avs_emit_deps(avs_net ${MBEDTLS_TARGETS})
elseif(WITH_TINYDTLS)
    avs_emit_deps(avs_net tinydtls)
endif()

avs_emit_deps(avs_net avs_stream avs_utils)
include_directories(../stream/include_public ../utils/include_public)

add_avs_test(avs_net ${ALL_SOURCES})
avs_install_export(avs_net net)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT net
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
