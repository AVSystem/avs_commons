# Copyright 2026 AVSystem <avsystem@avsystem.com>
# AVSystem Commons library
# All rights reserved.

cmake_minimum_required(VERSION 3.16)
project(probe_crypto_engine_backend C)

include(FindPkgConfig)
include(
    "${CMAKE_CURRENT_LIST_DIR}/../CheckMbedTlsPsaCrypto.cmake")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/..")

# This probe is called from deps/avs_commons/devconfig.
# It does not build anything. Its only job is to inspect the currently
# selected crypto stack and write two tiny files:
# - recommended_flags.txt: concrete -D flags that devconfig should append
# - probe_message.txt: a short explanation for the user
set(RECOMMENDED_FLAGS_FILE
    "${CMAKE_BINARY_DIR}/recommended_flags.txt"
    CACHE FILEPATH
    "")
set(PROBE_MESSAGE_FILE
    "${CMAKE_BINARY_DIR}/probe_message.txt"
    CACHE FILEPATH
    "")

# Determine which Mbed TLS engine backend is usable for this configuration.
# Respect explicit backend flags first; otherwise inspect the discovered Mbed
# TLS build:
# - Mbed TLS 2.x can use the legacy PKCS#11 backend
# - Mbed TLS 3.x can use PSA only if MBEDTLS_USE_PSA_CRYPTO is enabled
set(MBEDTLS_ENGINE_BACKEND none)
if(WITH_MBEDTLS)
    if(WITH_MBEDTLS_PKCS11_ENGINE)
        set(MBEDTLS_ENGINE_BACKEND pkcs11)
    elseif(WITH_MBEDTLS_PSA_ENGINE)
        set(MBEDTLS_ENGINE_BACKEND psa)
    else()
        find_package(MbedTLS QUIET)
        if(MBEDTLS_FOUND)
            if(MBEDTLS_VERSION VERSION_LESS 3.0.0)
                set(MBEDTLS_ENGINE_BACKEND pkcs11)
            else()
                check_mbedtls_psa_crypto_enabled(MBEDTLS_HAS_PSA_CRYPTO)
                if(MBEDTLS_HAS_PSA_CRYPTO)
                    set(MBEDTLS_ENGINE_BACKEND psa)
                endif()
            endif()
        endif()
    endif()
endif()

# OpenSSL engine support always uses PKCS#11. Prefer the explicit flag, and
# otherwise check whether the build can use libp11 from the current system.
set(OPENSSL_ENGINE_BACKEND none)
if(WITH_OPENSSL)
    if(WITH_OPENSSL_PKCS11_ENGINE)
        set(OPENSSL_ENGINE_BACKEND pkcs11)
    else()
        find_package(OpenSSL QUIET)
        if(OPENSSL_FOUND)
            pkg_search_module(LIBP11 QUIET libp11)
            if(LIBP11_FOUND)
                set(OPENSSL_ENGINE_BACKEND pkcs11)
            endif()
        endif()
    endif()
endif()

set(RECOMMENDED_FLAGS)
set(PROBE_MESSAGE "")

# Standalone avs_commons builds both Mbed TLS and OpenSSL libraries, so the
# generic engine options need to stay consistent with all backends that will be
# enabled in the final configure step.
if(WITH_MBEDTLS)
    if(MBEDTLS_ENGINE_BACKEND STREQUAL "none")
        string(CONCAT PROBE_MESSAGE
               "Leaving crypto engine disabled: no usable Mbed TLS engine "
               "backend detected for this standalone avs_commons build.")
    else()
        list(APPEND RECOMMENDED_FLAGS "-DWITH_AVS_CRYPTO_PKI_ENGINE=ON")
        if(MBEDTLS_ENGINE_BACKEND STREQUAL "pkcs11")
            list(APPEND RECOMMENDED_FLAGS
                 "-DWITH_MBEDTLS_PKCS11_ENGINE=ON")
        else()
            list(APPEND RECOMMENDED_FLAGS
                 "-DWITH_AVS_CRYPTO_PSK_ENGINE=ON"
                 "-DWITH_MBEDTLS_PSA_ENGINE=ON")
        endif()
        if(OPENSSL_ENGINE_BACKEND STREQUAL "pkcs11")
            list(APPEND RECOMMENDED_FLAGS
                 "-DWITH_OPENSSL_PKCS11_ENGINE=ON")
            string(CONCAT PROBE_MESSAGE
                   "Enabling crypto engine using Mbed TLS "
                   "${MBEDTLS_ENGINE_BACKEND} and OpenSSL pkcs11 "
                   "backends")
        else()
            string(CONCAT PROBE_MESSAGE
                   "Enabling crypto engine using Mbed TLS "
                   "${MBEDTLS_ENGINE_BACKEND} backend")
        endif()
    endif()
elseif(OPENSSL_ENGINE_BACKEND STREQUAL "pkcs11")
    list(APPEND RECOMMENDED_FLAGS
         "-DWITH_AVS_CRYPTO_PKI_ENGINE=ON"
         "-DWITH_OPENSSL_PKCS11_ENGINE=ON")
    set(PROBE_MESSAGE
        "Enabling crypto engine using OpenSSL pkcs11 backend")
else()
    string(CONCAT PROBE_MESSAGE
           "Leaving crypto engine disabled: no usable crypto engine backend "
           "detected")
endif()

# Return the decision to devconfig through tiny text files, so bash does not
# need to understand Mbed TLS/OpenSSL feature checks on its own.
string(REPLACE ";" "\n" RECOMMENDED_FLAGS_TEXT "${RECOMMENDED_FLAGS}")
file(WRITE "${RECOMMENDED_FLAGS_FILE}" "${RECOMMENDED_FLAGS_TEXT}\n")
file(WRITE "${PROBE_MESSAGE_FILE}" "${PROBE_MESSAGE}\n")
