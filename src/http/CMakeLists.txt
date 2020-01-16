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

add_library(avs_http STATIC
            include_public/avsystem/commons/http.h

            auth.h
            body_receivers.h
            chunked.h
            client.h
            content_encoding.h
            headers.h
            http_log.h
            http_stream.h
            zlib.h

            auth/basic.c
            auth/digest.c
            body_receivers/chunked_body_receiver.c
            body_receivers/content_length.c
            body_receivers/dumb_body_receiver.c
            auth.c
            body_receivers.c
            chunked.c
            client.c
            content_encoding.c
            headers_receive.c
            headers_send.c
            http_stream.c
            stream_methods.c)

target_include_directories(avs_http PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_http PUBLIC avs_commons_global_headers avs_algorithm avs_net avs_stream avs_stream_md5 avs_stream_net avs_utils avs_list)

if(WITH_AVS_HTTP_ZLIB)
    avs_find_library("find_package(ZLIB REQUIRED)")
    target_sources(avs_http PRIVATE zlib.c)
    target_link_libraries(avs_http PUBLIC ZLIB::ZLIB)
endif()

avs_install_export(avs_http http)
install(DIRECTORY include_public/
        COMPONENT http
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

avs_add_test(NAME avs_http
             LIBS avs_http
             SOURCES
             $<TARGET_PROPERTY:avs_http,SOURCES>
             ${AVS_COMMONS_SOURCE_DIR}/tests/http/test_close.c
             ${AVS_COMMONS_SOURCE_DIR}/tests/http/test_http.c)
