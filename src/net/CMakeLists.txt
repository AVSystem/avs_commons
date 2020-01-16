# Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

# Because of complex internal dependencies of avs_net source files, all of them
# have to be recompiled for every single (D)TLS backend.
#
# TODO: it should be possible to decouple them enough to be able to reuse a
# single build of "core" sources for all cases.
set(AVS_NET_SOURCES
    include_public/avsystem/commons/net.h
    include_public/avsystem/commons/socket_v_table.h
    include_public/avsystem/commons/url.h

    api.h
    global.h
    net_impl.h

    addrinfo.c
    api.c
    global.c
    url.c)

add_library(avs_net_core INTERFACE)
target_link_libraries(avs_net_core INTERFACE avs_commons_global_headers)
target_include_directories(avs_net_core INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)

if(WITH_POSIX_AVS_SOCKET)
    target_include_directories(avs_net_core INTERFACE
                               $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/compat/posix>)
    list(APPEND AVS_NET_SOURCES
         compat/posix/compat.h

         compat/posix/compat_addrinfo.c
         compat/posix/net_impl.c)
    if(NOT HAVE_INET_NTOP)
        list(APPEND AVS_NET_SOURCES compat/posix/inet_ntop.c)
    endif()
    if(NOT HAVE_INET_PTON)
        list(APPEND AVS_NET_SOURCES compat/posix/inet_pton.c)
    endif()
endif()

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_net_core INTERFACE avs_log)
endif()

if(WIN32)
    target_link_libraries(avs_net_core INTERFACE ws2_32)
endif()

target_link_libraries(avs_net_core INTERFACE avs_stream avs_utils avs_compat_threading)

avs_install_export(avs_net_core net)
install(DIRECTORY include_public/
        COMPONENT net
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

add_library(avs_net_nosec ${AVS_NET_SOURCES})
target_compile_definitions(avs_net_nosec PRIVATE WITHOUT_SSL)
target_link_libraries(avs_net_nosec PUBLIC avs_net_core)

avs_add_test(NAME avs_net_nosec
             LIBS avs_net_nosec
             SOURCES ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_nosec.c)
avs_install_export(avs_net_nosec net)

if(WITH_OPENSSL)
    option(WITH_DTLS "Enable OpenSSL DTLS support" ON)

    add_library(avs_net_openssl
                ${AVS_NET_SOURCES}
                openssl/openssl.c)
    target_link_libraries(avs_net_openssl PUBLIC avs_net_core OpenSSL::SSL OpenSSL::Crypto)

    if(WITH_X509)
        target_sources(avs_net_openssl PRIVATE openssl/data_loader.c)
    endif()

    avs_add_test(NAME avs_net_openssl
                 LIBS avs_net_openssl
                 SOURCES
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_nosec.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_tls.c
                 $<$<BOOL:${WITH_DTLS}>:${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_dtls.c>
                 $<$<BOOL:${WITH_X509}>:${AVS_COMMONS_SOURCE_DIR}/tests/net/openssl/data_loader.c>)
    avs_install_export(avs_net_openssl net)
endif()

if(WITH_MBEDTLS)
    add_library(avs_net_mbedtls
                ${AVS_NET_SOURCES}
                mbedtls/mbedtls.c)
    target_link_libraries(avs_net_mbedtls PUBLIC avs_net_core mbedtls mbedcrypto mbedx509)

    if(WITH_TLS_SESSION_PERSISTENCE)
        target_sources(avs_net_mbedtls PRIVATE
                       mbedtls/mbedtls_persistence.c
                       mbedtls/mbedtls_persistence.h)

        target_link_libraries(avs_net_mbedtls PUBLIC avs_persistence avs_rbtree)
    endif()
    if(WITH_X509)
        target_sources(avs_net_mbedtls PRIVATE mbedtls/data_loader.c)
    endif()

    avs_add_test(NAME avs_net_mbedtls
                 LIBS avs_net_mbedtls
                 SOURCES
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_nosec.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_tls.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_dtls.c
                 $<$<BOOL:${WITH_X509}>:${AVS_COMMONS_SOURCE_DIR}/tests/net/mbedtls/data_loader.c>)
    avs_install_export(avs_net_mbedtls net)
endif()

if(WITH_TINYDTLS)
    add_library(avs_net_tinydtls
                ${AVS_NET_SOURCES}
                tinydtls/tinydtls.c)
    target_link_libraries(avs_net_tinydtls PUBLIC avs_net_core tinydtls)

    avs_add_test(NAME avs_net_tinydtls
                 LIBS avs_net_tinydtls
                 SOURCES
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_nosec.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_dtls.c)
    avs_install_export(avs_net_tinydtls net)
endif()

# alias avs_net to first available implementation
foreach(target IN ITEMS avs_net_openssl avs_net_mbedtls avs_net_tinydtls avs_net_nosec)
    if(TARGET "${target}")
        add_library(avs_net ALIAS "${target}")
        break()
    endif()
endforeach()
