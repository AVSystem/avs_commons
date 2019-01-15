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

add_library(avs_net STATIC
            include_public/avsystem/commons/net.h
            include_public/avsystem/commons/socket_v_table.h
            include_public/avsystem/commons/url.h

            src/api.h
            src/global.h
            src/net_impl.h

            src/addrinfo.c
            src/api.c
            src/global.c
            src/url.c)
target_link_libraries(avs_net PUBLIC avs_commons_global_headers)

target_include_directories(avs_net PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)

avs_add_test(NAME avs_net
             PATH avs_net
             SOURCES $<TARGET_PROPERTY:avs_net,SOURCES>)

# SSL
option(WITH_OPENSSL "Enable OpenSSL" OFF)
option(WITH_MBEDTLS "Enable mbed TLS" OFF)
option(WITH_TINYDTLS "Enable tinyDTLS" OFF)

set(_AVS_TLS_BACKENDS "")
if(WITH_OPENSSL)
    list(APPEND _AVS_TLS_BACKENDS "openssl")
endif()
if(WITH_MBEDTLS)
    list(APPEND _AVS_TLS_BACKENDS "mbedtls")
endif()
if(WITH_TINYDTLS)
    list(APPEND _AVS_TLS_BACKENDS "tinydtls")
endif()

list(LENGTH _AVS_TLS_BACKENDS _AVS_NUM_TLS_BACKENDS)
if(_AVS_NUM_TLS_BACKENDS GREATER 1)
    string(REPLACE ";" ", " _AVS_TLS_BACKENDS "${_AVS_TLS_BACKENDS}")
    message(FATAL_ERROR "Selected ${_AVS_TLS_BACKENDS} as TLS backends but only one may be used.")
elseif(_AVS_NUM_TLS_BACKENDS GREATER 0)
    set(WITH_SSL ON CACHE STRING "SSL support is enabled.")
    option(WITH_PSK "Enable pre-shared key support" ON)
    option(WITH_X509 "Enable X.509 certificate support" ON)
endif()

if(WITH_OPENSSL)
    option(WITH_DTLS "Enable OpenSSL DTLS support" ON)
    option(WITH_EC_KEY "Enable OpenSSL EC_KEY support" ON)

    avs_find_library("find_package(OpenSSL REQUIRED)")

    set(WITH_OPENSSL_CUSTOM_CIPHERS OFF CACHE STRING "Customized OpenSSL cipher suite list")

    target_sources(avs_net PRIVATE src/openssl/openssl.c)
    if(WITH_X509)
        target_sources(avs_net PRIVATE src/openssl/data_loader.c)
        if(TARGET avs_net_test)
            target_sources(avs_net_test PRIVATE src/openssl/test/data_loader.c)
        endif()
    endif()
    target_link_libraries(avs_net PUBLIC OpenSSL::SSL OpenSSL::Crypto)
elseif(WITH_MBEDTLS)
    avs_find_library("
        set(CMAKE_MODULE_PATH \\\${CMAKE_MODULE_PATH} \"\\\${CMAKE_CURRENT_LIST_DIR}/cmake\")
        # Assume mbed TLS is installed to the same root as avs_commons
        set(MBEDTLS_ROOT_DIR \"\\\${CMAKE_CURRENT_LIST_DIR}/../..\" CACHE STRING \"mbed TLS installation directory\")
        set(MBEDTLS_USE_STATIC_LIBS ${MBEDTLS_USE_STATIC_LIBS})
        find_package(MbedTLS REQUIRED)")
    target_sources(avs_net PRIVATE src/mbedtls/mbedtls.c)
    if(WITH_TLS_SESSION_PERSISTENCE)
        target_sources(avs_net PRIVATE
                       src/mbedtls/mbedtls_persistence.c
                       src/mbedtls/mbedtls_persistence.h)
    endif()
    if(WITH_X509)
        target_sources(avs_net PRIVATE src/mbedtls/data_loader.c)
        if(TARGET avs_net_test)
            target_sources(avs_net_test PRIVATE src/mbedtls/test/data_loader.c)
        endif()
    endif()
    target_link_libraries(avs_net PUBLIC mbedtls mbedcrypto mbedx509)
elseif(WITH_TINYDTLS)
    avs_find_library("
        set(TINYDTLS_ROOT_DIR \"${TINYDTLS_ROOT_DIR}\")
        find_package(TinyDTLS REQUIRED)
    ")
    target_sources(avs_net PRIVATE src/tinydtls/tinydtls.c)
    target_link_libraries(avs_net PUBLIC tinydtls)
endif()

if(WITH_POSIX_AVS_SOCKET)
    target_include_directories(avs_net PRIVATE compat/posix)
    target_sources(avs_net PRIVATE
                   compat/posix/compat.h

                   compat/posix/compat_addrinfo.c
                   compat/posix/net_impl.c)
    if(NOT HAVE_INET_NTOP)
        target_sources(avs_net PRIVATE compat/posix/inet_ntop.c)
    endif()
    if(NOT HAVE_INET_PTON)
        target_sources(avs_net PRIVATE compat/posix/inet_pton.c)
    endif()
endif()

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_net PUBLIC avs_log)
endif()

if(WIN32)
    target_link_libraries(avs_net PUBLIC ws2_32)
endif()

target_link_libraries(avs_net PUBLIC avs_stream avs_utils avs_compat_threading)

if(WITH_MBEDTLS AND WITH_TLS_SESSION_PERSISTENCE)
    target_link_libraries(avs_net PUBLIC avs_persistence avs_rbtree)
endif()

avs_install_export(avs_net net)
install(DIRECTORY include_public/
        COMPONENT net
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
