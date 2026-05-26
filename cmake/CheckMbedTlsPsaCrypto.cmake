# Copyright 2026 AVSystem <avsystem@avsystem.com>
# AVSystem Commons library
# All rights reserved.

include(CheckSymbolExists)
include(CMakePushCheckState)

# Shared helper for all places that need to answer one question:
# "does the selected Mbed TLS build actually enable PSA crypto support?"
#
# The caller is expected to run find_package(MbedTLS) first, so that
# MBEDTLS_INCLUDE_DIR and MBEDTLS_BUILD_INFO_FILE already point at the headers
# that the real build would use.
function(check_mbedtls_psa_crypto_enabled OUT_VAR)
    set(${OUT_VAR} OFF PARENT_SCOPE)
    unset(${OUT_VAR} CACHE)

    if(NOT MBEDTLS_INCLUDE_DIR OR NOT MBEDTLS_BUILD_INFO_FILE)
        message(FATAL_ERROR
                "MBEDTLS_INCLUDE_DIR and MBEDTLS_BUILD_INFO_FILE must both "
                "be set; call find_package(MbedTLS) before "
                "check_mbedtls_psa_crypto_enabled()")
    endif()

    file(RELATIVE_PATH MBEDTLS_BUILD_INFO_HEADER
         "${MBEDTLS_INCLUDE_DIR}"
         "${MBEDTLS_BUILD_INFO_FILE}")

    # Use the selected Mbed TLS build-info header, because it includes the
    # configured Mbed TLS config file in 3.x builds.
    #
    # check_symbol_exists() compiles a small test that includes the header by
    # name, so CMAKE_REQUIRED_INCLUDES must point at the selected Mbed TLS
    # we use `check_symbol_exists()`. It creates and runs a temporary, mini C
    # project where it takes `CMAKE_REQUIRED_INCLUDES`, includes
    # `MBEDTLS_BUILD_INFO_HEADER` and verifies the asked switch
    # `MBEDTLS_USE_PSA_CRYPTO`. To be sure during this call that MbedTLS will
    # be found we append `MBEDTLS_INCLUDE_DIR` to the includes list, but it's
    # not actually decided at this moment whether this directory should be added
    # to the list for compiling avs_commons, so we add it temporarily.
    cmake_push_check_state()
    list(APPEND CMAKE_REQUIRED_INCLUDES "${MBEDTLS_INCLUDE_DIR}")
    unset(_MBEDTLS_USE_PSA_CRYPTO_ENABLED CACHE)
    check_symbol_exists("MBEDTLS_USE_PSA_CRYPTO"
                        "${MBEDTLS_BUILD_INFO_HEADER}"
                        _MBEDTLS_USE_PSA_CRYPTO_ENABLED)
    cmake_pop_check_state()

    set(${OUT_VAR} "${_MBEDTLS_USE_PSA_CRYPTO_ENABLED}" PARENT_SCOPE)
    unset(_MBEDTLS_USE_PSA_CRYPTO_ENABLED CACHE)
endfunction()
