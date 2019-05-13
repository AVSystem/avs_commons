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

add_library(avs_crypto STATIC
            include_public/avsystem/commons/hkdf.h)

target_include_directories(avs_crypto PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_crypto PUBLIC avs_commons_global_headers avs_utils)

avs_add_test(NAME avs_crypto
             LIBS avs_crypto
             SOURCES $<TARGET_PROPERTY:avs_crypto,SOURCES>)

if(TARGET avs_crypto_test)
    target_sources(avs_crypto_test PRIVATE src/test/hkdf.c)
endif()

# SSL
option(WITH_OPENSSL "Enable OpenSSL" OFF)
option(WITH_MBEDTLS "Enable mbed TLS" OFF)
option(WITH_TINYDTLS "Enable tinyDTLS" OFF)

set(_AVS_CRYPTO_BACKENDS "")
if(WITH_OPENSSL)
    list(APPEND _AVS_CRYPTO_BACKENDS "openssl")
endif()
if(WITH_MBEDTLS)
    list(APPEND _AVS_CRYPTO_BACKENDS "mbedtls")
endif()
if(WITH_TINYDTLS)
    list(APPEND _AVS_CRYPTO_BACKENDS "tinydtls")
endif()

list(LENGTH _AVS_CRYPTO_BACKENDS _AVS_NUM_CRYPTO_BACKENDS)
if(_AVS_NUM_CRYPTO_BACKENDS GREATER 1)
    string(REPLACE ";" ", " _AVS_CRYPTO_BACKENDS "${_AVS_CRYPTO_BACKENDS}")
    message(FATAL_ERROR "Selected ${_AVS_CRYPTO_BACKENDS} as crypto backends but only one may be used.")
endif()

if(WITH_OPENSSL)
    avs_find_library("find_package(OpenSSL REQUIRED)")
    target_sources(avs_crypto PRIVATE src/openssl/hkdf.c)
    target_link_libraries(avs_crypto PUBLIC OpenSSL::Crypto)
elseif(WITH_MBEDTLS)
    avs_find_library("
        set(CMAKE_MODULE_PATH \\\${CMAKE_MODULE_PATH} \"\\\${CMAKE_CURRENT_LIST_DIR}/cmake\")
        # Assume mbed TLS is installed to the same root as avs_commons
        set(MBEDTLS_ROOT_DIR \"\\\${CMAKE_CURRENT_LIST_DIR}/../..\" CACHE STRING \"mbed TLS installation directory\")
        set(MBEDTLS_USE_STATIC_LIBS ${MBEDTLS_USE_STATIC_LIBS})
        find_package(MbedTLS REQUIRED)")
    target_sources(avs_crypto PRIVATE src/mbedtls/hkdf.c)
    target_link_libraries(avs_crypto PUBLIC mbedcrypto)
endif()

if(WIN32)
    target_link_libraries(avs_crypto PUBLIC ws2_32)
endif()

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_crypto PUBLIC avs_log)
endif()

avs_install_export(avs_crypto crypto)
install(DIRECTORY include_public/
        COMPONENT crypto
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
