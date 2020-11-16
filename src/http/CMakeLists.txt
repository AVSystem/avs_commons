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

set(AVS_HTTP_PUBLIC_HEADERS
    "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/avs_http.h")

add_library(avs_http STATIC
            ${AVS_HTTP_PUBLIC_HEADERS}

            avs_auth.h
            avs_body_receivers.h
            avs_chunked.h
            avs_client.h
            avs_compression.h
            avs_content_encoding.h
            avs_headers.h
            avs_http_log.h
            avs_http_stream.h

            auth/avs_basic.c
            auth/avs_digest.c
            body_receivers/avs_chunked_body_receiver.c
            body_receivers/avs_content_length.c
            body_receivers/avs_dumb_body_receiver.c
            avs_auth.c
            avs_body_receivers.c
            avs_chunked.c
            avs_client.c
            avs_compression.c
            avs_content_encoding.c
            avs_headers_receive.c
            avs_headers_send.c
            avs_http_stream.c
            avs_stream_methods.c)

target_link_libraries(avs_http PUBLIC avs_commons_global_headers avs_algorithm avs_net_core avs_stream avs_stream_md5 avs_stream_net avs_utils avs_list avs_url)

if(WITH_AVS_HTTP_ZLIB)
    avs_find_library("find_package(ZLIB REQUIRED)")
    target_link_libraries(avs_http PUBLIC ZLIB::ZLIB)
endif()

avs_install_export(avs_http http)
install(FILES ${AVS_HTTP_PUBLIC_HEADERS}
        COMPONENT http
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons)

avs_add_test(NAME avs_http
             LIBS avs_http avs_net
             SOURCES
             $<TARGET_PROPERTY:avs_http,SOURCES>
             ${AVS_COMMONS_SOURCE_DIR}/tests/http/test_close.c
             ${AVS_COMMONS_SOURCE_DIR}/tests/http/test_http.c)
