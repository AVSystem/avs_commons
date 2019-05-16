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
            include_public/avsystem/commons/hkdf.h
            include_public/avsystem/commons/aead.h)

target_include_directories(avs_crypto PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_crypto PUBLIC avs_commons_global_headers avs_utils)

avs_add_test(NAME avs_crypto
             LIBS avs_crypto
             SOURCES $<TARGET_PROPERTY:avs_crypto,SOURCES>)

if(TARGET avs_crypto_test)
    target_sources(avs_crypto_test PRIVATE
                   src/test/hkdf.c
                   src/test/aead.c)
endif()

if(WITH_OPENSSL)
    if (OPENSSL_VERSION VERSION_LESS 1.1.0)
        message(FATAL_ERROR "avs_crypto supports OpenSSL 1.1.0 or newer")
    endif()
    target_sources(avs_crypto PRIVATE
                   src/openssl/hkdf.c
                   src/openssl/aead.c)
    target_link_libraries(avs_crypto PUBLIC OpenSSL::Crypto)
elseif(WITH_MBEDTLS)
    if (MBEDTLS_VERSION VERSION_LESS 2.14.0)
        message(FATAL_ERROR "avs_crypto supports mbed TLS 2.14.0 or newer")
    endif()
    target_sources(avs_crypto PRIVATE
                   src/mbedtls/hkdf.c
                   src/mbedtls/aead.c)
    target_link_libraries(avs_crypto PUBLIC mbedcrypto)
elseif(WITH_TINYDTLS)
    message(FATAL_ERROR "avs_crypto does not support tinydtls")
else()
    message(FATAL_ERROR "No crypto backend specified")
endif()

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_crypto PUBLIC avs_log)
endif()

avs_install_export(avs_crypto crypto)
install(DIRECTORY include_public/
        COMPONENT crypto
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
