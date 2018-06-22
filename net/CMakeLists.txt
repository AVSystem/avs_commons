# Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

set(POSIX_AVS_SOCKET_DEFAULT OFF)
if(WIN32 OR UNIX OR POSIX_COMPAT_HEADER)
    set(POSIX_AVS_SOCKET_DEFAULT ON)
endif()

option(WITH_POSIX_AVS_SOCKET "Enable avs_socket implementation based on POSIX socket API" "${POSIX_AVS_SOCKET_DEFAULT}")
cmake_dependent_option(WITH_TLS_SESSION_PERSISTENCE "Enable support for TLS session persistence" ON WITH_AVS_PERSISTENCE OFF)

set(SOURCES
    src/addrinfo.c
    src/api.c
    src/global.c
    src/url.c)

set(TEST_SOURCES)

if(WITH_OPENSSL)
    set(SOURCES ${SOURCES} src/openssl/openssl.c)
    if(WITH_X509)
        set(SOURCES ${SOURCES}
            src/openssl/data_loader.c)
        list(APPEND TEST_SOURCES src/openssl/test/data_loader.c)
    endif()
elseif(WITH_MBEDTLS)
    set(SOURCES ${SOURCES}
        src/mbedtls/mbedtls.c)
    if(WITH_TLS_SESSION_PERSISTENCE)
        set(SOURCES ${SOURCES}
            src/mbedtls/mbedtls_persistence.c
            src/mbedtls/mbedtls_persistence.h)
    endif()
    if(WITH_X509)
        set(SOURCES ${SOURCES}
            src/mbedtls/data_loader.c)
        list(APPEND TEST_SOURCES src/mbedtls/test/data_loader.c)
    endif()
elseif(WITH_TINYDTLS)
    set(SOURCES ${SOURCES} src/tinydtls/tinydtls.c)
endif()

set(PRIVATE_HEADERS
    src/api.h
    src/global.h
    src/net_impl.h)

if(WITH_POSIX_AVS_SOCKET)
    include_directories("${CMAKE_CURRENT_BINARY_DIR}/compat/posix")
    set(SOURCES ${SOURCES}
        compat/posix/compat_addrinfo.c
        compat/posix/net_impl.c)
    set(PRIVATE_HEADERS ${PRIVATE_HEADERS}
        compat/posix/compat.h)
    if(NOT HAVE_INET_NTOP)
        set(SOURCES ${SOURCES} compat/posix/inet_ntop.c)
    endif()
    if(NOT HAVE_INET_PTON)
        set(SOURCES ${SOURCES} compat/posix/inet_pton.c)
    endif()
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

if(WIN32)
    avs_emit_deps(avs_net ws2_32)
endif()

if(WITH_OPENSSL)
    avs_emit_deps(avs_net OpenSSL::SSL OpenSSL::Crypto)
elseif(WITH_MBEDTLS)
    avs_emit_deps(avs_net ${MBEDTLS_TARGETS})
elseif(WITH_TINYDTLS)
    avs_emit_deps(avs_net tinydtls)
endif()

avs_emit_deps(avs_net avs_stream avs_utils avs_compat_threading)
include_directories(../stream/include_public
                    ../utils/include_public
                    ../compat/threading/include_public)

if(WITH_MBEDTLS AND WITH_TLS_SESSION_PERSISTENCE)
    avs_emit_deps(avs_net avs_persistence)
    include_directories(../persistence/include_public
                        ../rbtree/include_public)
endif()

add_avs_test(avs_net ${ALL_SOURCES} ${TEST_SOURCES})
avs_install_export(avs_net net)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT net
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
