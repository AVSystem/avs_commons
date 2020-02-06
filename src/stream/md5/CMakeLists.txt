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

set(AVS_STREAM_MD5_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/stream/md5.h")

add_library(avs_stream_md5 STATIC
            ${AVS_STREAM_MD5_PUBLIC_HEADERS}
            md5_common.h
            md5_common.c)

if(WITH_OPENSSL)
    target_sources(avs_stream_md5 PRIVATE stream_openssl.c)
elseif(WITH_MBEDTLS)
    target_sources(avs_stream_md5 PRIVATE stream_mbedtls.c)
else()
    target_sources(avs_stream_md5 PRIVATE md5_impl.c)
endif()

target_include_directories(avs_stream_md5 PUBLIC
                           $<BUILD_INTERFACE:${AVS_COMMONS_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
# TODO: this should depend directly on OpenSSL/mbedtls rather than avs_net
target_link_libraries(avs_stream_md5 PUBLIC avs_stream avs_net)

avs_install_export(avs_stream_md5 stream)
install(FILES ${AVS_STREAM_MD5_PUBLIC_HEADERS}
        COMPONENT stream_md5
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons/stream)
