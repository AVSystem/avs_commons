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

set(AVS_CRYPTO_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_crypto_pki.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_crypto_pki_compat.h"
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_prng.h")

set(AVS_CRYPTO_COMMON_SOURCES
    avs_crypto_global.c
    avs_crypto_global.h
    avs_crypto_pki_persistence.c
    avs_crypto_utils.c
    avs_crypto_utils.h)

set(AVS_CRYPTO_TEST_SOURCES "${AVS_COMMONS_SOURCE_DIR}/tests/crypto/prng.c")

set(AVS_CRYPTO_ADVANCED_FEATURES_TEST_SOURCES
    ${AVS_COMMONS_SOURCE_DIR}/tests/crypto/aead.c
    ${AVS_COMMONS_SOURCE_DIR}/tests/crypto/hkdf.c
    ${AVS_COMMONS_SOURCE_DIR}/tests/crypto/pki.h)

option(WITH_AVS_CRYPTO_ADVANCED_FEATURES
       "Enables/disables advanced cryptographic features, such as AEAD/HKDF support" OFF)

if(WITH_AVS_CRYPTO_ADVANCED_FEATURES AND (NOT WITH_OPENSSL OR OPENSSL_VERSION VERSION_LESS 1.1.0) AND (NOT WITH_MBEDTLS OR MBEDTLS_VERSION VERSION_LESS 2.14.0))
    message(FATAL_ERROR "WITH_AVS_CRYPTO_ADVANCED_FEATURES requires either OpenSSL>=1.1.0 or mbed TLS>=2.14.0")
endif()

set(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES ${WITH_AVS_CRYPTO_ADVANCED_FEATURES} CACHE INTERNAL "")

if(WITH_AVS_CRYPTO_ADVANCED_FEATURES)
    set(AVS_CRYPTO_PUBLIC_HEADERS
        ${AVS_CRYPTO_PUBLIC_HEADERS}
        "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_aead.h"
        "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_hkdf.h")

    if(WITH_PKI)
        set(AVS_CRYPTO_ADVANCED_FEATURES_TEST_SOURCES
            ${AVS_CRYPTO_ADVANCED_FEATURES_TEST_SOURCES}
            "${AVS_COMMONS_SOURCE_DIR}/tests/crypto/pki.c")
    endif()
endif()

add_library(avs_crypto_core INTERFACE)
target_link_libraries(avs_crypto_core INTERFACE avs_commons_global_headers avs_utils)

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_crypto_core INTERFACE avs_log)
endif()

if(WITH_AVS_PERSISTENCE)
    target_link_libraries(avs_crypto_core INTERFACE avs_persistence)

    set(AVS_CRYPTO_ADVANCED_FEATURES_TEST_SOURCES
        ${AVS_CRYPTO_ADVANCED_FEATURES_TEST_SOURCES}
        "${AVS_COMMONS_SOURCE_DIR}/tests/crypto/pki_persistence.c")
endif()

if(WITH_OPENSSL)
    set(AVS_CRYPTO_OPENSSL_SOURCES
        ${AVS_CRYPTO_COMMON_SOURCES}
        openssl/avs_openssl_aead.c
        openssl/avs_openssl_data_loader.c
        openssl/avs_openssl_engine.h
        openssl/avs_openssl_hkdf.c
        openssl/avs_openssl_pki.c
        openssl/avs_openssl_prng.c
        openssl/avs_openssl_prng.h
        openssl/avs_openssl_global.c
        openssl/engine_pkcs11/avs_openssl_pkcs11_engine.c)

    set(AVS_CRYPTO_OPENSSL_TEST_SOURCES
        ${AVS_CRYPTO_TEST_SOURCES}
        $<$<BOOL:${WITH_PKI}>:${AVS_COMMONS_SOURCE_DIR}/tests/crypto/openssl/openssl_data_loader.c>)

    if(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES)
        set(AVS_CRYPTO_OPENSSL_TEST_SOURCES
            ${AVS_CRYPTO_OPENSSL_TEST_SOURCES}
            ${AVS_CRYPTO_ADVANCED_FEATURES_TEST_SOURCES})
    endif()

    add_library(avs_crypto_openssl
                ${AVS_CRYPTO_PUBLIC_HEADERS}
                ${AVS_CRYPTO_OPENSSL_SOURCES})
    target_link_libraries(avs_crypto_openssl PUBLIC avs_crypto_core OpenSSL::Crypto)
    if(WITH_PKI AND WITH_AVS_STREAM_FILE)
        target_link_libraries(avs_crypto_openssl PUBLIC avs_stream)
    endif()

    avs_add_test(NAME avs_crypto_openssl
                 LIBS avs_crypto_openssl OpenSSL::SSL
                 SOURCES
                 ${AVS_CRYPTO_OPENSSL_TEST_SOURCES})

    if (WITH_OPENSSL_PKCS11_ENGINE)
        target_link_libraries(avs_crypto_openssl PUBLIC OpenSSL::SSL ${LIBP11_LIBRARIES} avs_url)
        target_include_directories(avs_crypto_openssl PRIVATE ${LIBP11_INCLUDE_DIRS})

        avs_add_test(NAME avs_crypto_openssl_engine
                     LIBS $<TARGET_PROPERTY:avs_crypto_openssl,LINK_LIBRARIES>
                     COMPILE_DEFINITIONS AVS_COMMONS_OPENSSL_PKCS11_ENGINE_UNIT_TESTING
                     SOURCES $<TARGET_PROPERTY:avs_crypto_openssl,SOURCES>
                     ENVIRONMENT "PKCS11_MODULE_PATH=${SOFTHSM2_LIB}")
    endif()

    avs_install_export(avs_crypto_openssl crypto)
endif()

if(WITH_MBEDTLS)
    set(AVS_CRYPTO_MBEDTLS_SOURCES
        ${AVS_CRYPTO_COMMON_SOURCES}
        mbedtls/avs_mbedtls_aead.c
        mbedtls/avs_mbedtls_data_loader.c
        mbedtls/avs_mbedtls_global.c
        mbedtls/avs_mbedtls_hkdf.c
        mbedtls/avs_mbedtls_pki.c
        mbedtls/avs_mbedtls_prng.c
        mbedtls/avs_mbedtls_prng.h)

    set(AVS_CRYPTO_MBEDTLS_TEST_SOURCES
        ${AVS_CRYPTO_MBEDTLS_SOURCES}
        ${AVS_CRYPTO_TEST_SOURCES}
        $<$<BOOL:${WITH_PKI}>:${AVS_COMMONS_SOURCE_DIR}/tests/crypto/mbedtls/mbedtls_data_loader.c>)

    if(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES)
        set(AVS_CRYPTO_MBEDTLS_TEST_SOURCES
            ${AVS_CRYPTO_MBEDTLS_TEST_SOURCES}
            ${AVS_CRYPTO_ADVANCED_FEATURES_TEST_SOURCES})
    endif()

    add_library(avs_crypto_mbedtls
                ${AVS_CRYPTO_PUBLIC_HEADERS}
                ${AVS_CRYPTO_MBEDTLS_SOURCES})
    target_link_libraries(avs_crypto_mbedtls PUBLIC avs_crypto_core mbedcrypto)
    if(WITH_PKI)
        target_link_libraries(avs_crypto_mbedtls PUBLIC mbedx509)
    endif()

    avs_add_test(NAME avs_crypto_mbedtls
                 LIBS $<TARGET_PROPERTY:avs_crypto_mbedtls,LINK_LIBRARIES>
                 SOURCES
                 ${AVS_CRYPTO_MBEDTLS_TEST_SOURCES})
    avs_install_export(avs_crypto_mbedtls crypto)
endif()

# Contains only simple PRNG generator if OpenSSL and MbedTLS aren't available.
add_library(avs_crypto_generic
            ${AVS_CRYPTO_COMMON_SOURCES}
            ${AVS_CRYPTO_PUBLIC_HEADERS}
            generic/avs_generic_prng.c)
target_compile_definitions(avs_crypto_generic PRIVATE WITHOUT_SSL)
target_link_libraries(avs_crypto_generic PUBLIC avs_crypto_core)

avs_add_test(NAME avs_crypto_generic
             LIBS avs_crypto_generic
             SOURCES
             ${AVS_COMMONS_SOURCE_DIR}/tests/crypto/prng.c)
avs_install_export(avs_crypto_generic crypto)

# alias avs_crypto to first available implementation
foreach(target IN ITEMS avs_crypto_mbedtls avs_crypto_openssl avs_crypto_generic)
    if(TARGET "${target}")
        add_library(avs_crypto ALIAS "${target}")
        avs_install_export(avs_crypto crypto)
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
