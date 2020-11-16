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

set(POSIX_AVS_SOCKET_DEFAULT OFF)
if(WIN32 OR UNIX OR POSIX_COMPAT_HEADER)
    set(POSIX_AVS_SOCKET_DEFAULT ON)
endif()

option(WITH_POSIX_AVS_SOCKET "Enable avs_socket implementation based on POSIX socket API" "${POSIX_AVS_SOCKET_DEFAULT}")
cmake_dependent_option(WITH_TLS_SESSION_PERSISTENCE "Enable support for TLS session persistence" ON WITH_AVS_PERSISTENCE OFF)

set(AVS_NET_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_addrinfo.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_net.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_socket.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_socket_v_table.h")

if(WITH_PKI)
    set(AVS_NET_PUBLIC_HEADERS
        ${AVS_NET_PUBLIC_HEADERS}
        "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_net_pki_compat.h")
endif()

# Because of complex internal dependencies of avs_net source files, all of them
# have to be recompiled for every single (D)TLS backend.
#
# TODO: it should be possible to decouple them enough to be able to reuse a
# single build of "core" sources for all cases.
set(AVS_NET_SOURCES
    ${AVS_NET_PUBLIC_HEADERS}

    avs_net_global.h
    avs_net_impl.h

    avs_addrinfo.c
    avs_api.c
    avs_net_global.c

    compat/posix/avs_compat.h

    compat/posix/avs_compat_addrinfo.c
    compat/posix/avs_inet_ntop.c
    compat/posix/avs_net_impl.c)

add_library(avs_net_core INTERFACE)
target_link_libraries(avs_net_core INTERFACE avs_commons_global_headers)

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_net_core INTERFACE avs_log)
endif()

if(WIN32)
    target_link_libraries(avs_net_core INTERFACE ws2_32)
endif()

target_link_libraries(avs_net_core INTERFACE avs_stream avs_utils avs_compat_threading)

avs_install_export(avs_net_core net)
install(FILES ${AVS_NET_PUBLIC_HEADERS}
        COMPONENT net
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)

add_library(avs_net_nosec ${AVS_NET_SOURCES})
target_compile_definitions(avs_net_nosec PRIVATE WITHOUT_SSL)
target_link_libraries(avs_net_nosec PUBLIC avs_net_core)

avs_add_test(NAME avs_net_nosec
             LIBS $<TARGET_PROPERTY:avs_net_nosec,LINK_LIBRARIES>
             COMPILE_DEFINITIONS WITHOUT_SSL
             SOURCES
             ${AVS_NET_SOURCES}
             ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_nosec.c)
avs_install_export(avs_net_nosec net)

if(WITH_OPENSSL)
    option(WITH_DTLS "Enable OpenSSL DTLS support" ON)

    set(AVS_NET_OPENSSL_SOURCES
        ${AVS_NET_SOURCES}
        openssl/avs_openssl.c)

    add_library(avs_net_openssl ${AVS_NET_OPENSSL_SOURCES})
    target_link_libraries(avs_net_openssl PUBLIC avs_net_core avs_crypto_openssl OpenSSL::SSL OpenSSL::Crypto)

    avs_add_test(NAME avs_net_openssl
                 LIBS $<TARGET_PROPERTY:avs_net_openssl,LINK_LIBRARIES>
                 SOURCES
                 ${AVS_NET_OPENSSL_SOURCES}
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_nosec.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_tls.c
                 $<$<BOOL:${WITH_DTLS}>:${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_dtls.c>)
    avs_install_export(avs_net_openssl net)
endif()

if(WITH_MBEDTLS)
    set(AVS_NET_MBEDTLS_SOURCES
        ${AVS_NET_SOURCES}
        mbedtls/avs_mbedtls_persistence.c
        mbedtls/avs_mbedtls_persistence.h
        mbedtls/avs_mbedtls_socket.c)

    add_library(avs_net_mbedtls ${AVS_NET_MBEDTLS_SOURCES})
    target_link_libraries(avs_net_mbedtls PUBLIC avs_net_core avs_crypto_mbedtls mbedtls mbedcrypto mbedx509)

    if(WITH_TLS_SESSION_PERSISTENCE)
        target_link_libraries(avs_net_mbedtls PUBLIC avs_persistence avs_rbtree)
    endif()

    avs_add_test(NAME avs_net_mbedtls
                 LIBS $<TARGET_PROPERTY:avs_net_mbedtls,LINK_LIBRARIES>
                 SOURCES
                 ${AVS_NET_MBEDTLS_SOURCES}
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_nosec.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_tls.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_dtls.c)
    avs_install_export(avs_net_mbedtls net)
endif()

if(WITH_TINYDTLS)
    set(AVS_NET_TINYDTLS_SOURCES
        ${AVS_NET_SOURCES}
        tinydtls/avs_tinydtls.c)

    add_library(avs_net_tinydtls ${AVS_NET_TINYDTLS_SOURCES})
    target_link_libraries(avs_net_tinydtls PUBLIC avs_net_core avs_crypto_generic tinydtls)

    avs_add_test(NAME avs_net_tinydtls
                 LIBS $<TARGET_PROPERTY:avs_net_tinydtls,LINK_LIBRARIES>
                 SOURCES
                 ${AVS_NET_TINYDTLS_SOURCES}
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_nosec.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/net/socket_dtls.c)
    avs_install_export(avs_net_tinydtls net)
endif()

# alias avs_net to first available implementation
foreach(target IN ITEMS avs_net_mbedtls avs_net_openssl avs_net_tinydtls avs_net_nosec)
    if(TARGET "${target}")
        add_library(avs_net ALIAS "${target}")
        avs_install_export(avs_net net)
        break()
    endif()
endforeach()
