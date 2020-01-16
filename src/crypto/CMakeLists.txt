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

set(AVS_CRYPTO_PUBLIC_HEADERS
    include_public/avsystem/commons/hkdf.h
    include_public/avsystem/commons/aead.h)

set(AVS_CRYPTO_SOURCES
    ${AVS_CRYPTO_PUBLIC_HEADERS}
    crypto_utils.c
    crypto_utils.h)

add_library(avs_crypto_core INTERFACE)
target_include_directories(avs_crypto_core INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_crypto_core INTERFACE avs_commons_global_headers avs_utils)

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_crypto_core INTERFACE avs_log)
endif()

if(WITH_OPENSSL AND NOT OPENSSL_VERSION VERSION_LESS 1.1.0)
    add_library(avs_crypto_openssl
                ${AVS_CRYPTO_SOURCES}
                openssl/hkdf.c
                openssl/aead.c)
    target_link_libraries(avs_crypto_openssl PUBLIC avs_crypto_core OpenSSL::Crypto)

    avs_add_test(NAME avs_crypto_openssl
                 LIBS avs_crypto_openssl
                 SOURCES
                 ${AVS_COMMONS_SOURCE_DIR}/tests/crypto/hkdf.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/crypto/aead.c)
    avs_install_export(avs_crypto_openssl crypto)
endif()

if(WITH_MBEDTLS AND NOT MBEDTLS_VERSION VERSION_LESS 2.14.0)
    add_library(avs_crypto_mbedtls
                ${AVS_CRYPTO_SOURCES}
                mbedtls/hkdf.c
                mbedtls/aead.c)
    target_link_libraries(avs_crypto_mbedtls PUBLIC avs_crypto_core mbedcrypto)

    avs_add_test(NAME avs_crypto_mbedtls
                 LIBS avs_crypto_mbedtls
                 SOURCES
                 ${AVS_COMMONS_SOURCE_DIR}/tests/crypto/hkdf.c
                 ${AVS_COMMONS_SOURCE_DIR}/tests/crypto/aead.c)
    avs_install_export(avs_crypto_mbedtls crypto)
endif()

# alias avs_net to first available implementation
foreach(target IN ITEMS avs_crypto_mbedtls avs_crypto_openssl)
    if(TARGET "${target}")
        add_library(avs_crypto ALIAS "${target}")
        break()
    endif()
endforeach()

if(NOT TARGET avs_crypto)
    message(WARNING "No supported crypto backend available, avs_crypto will be disabled")
else()
    install(FILES ${AVS_CRYPTO_PUBLIC_HEADERS}
            COMPONENT crypto
            DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)
    avs_install_export(avs_crypto_core crypto)
endif()
