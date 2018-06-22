# Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

set(SOURCES
    src/auth/basic.c
    src/auth/digest.c
    src/body_receivers/chunked_body_receiver.c
    src/body_receivers/content_length.c
    src/body_receivers/dumb_body_receiver.c
    src/auth.c
    src/body_receivers.c
    src/chunked.c
    src/client.c
    src/content_encoding.c
    src/headers_receive.c
    src/headers_send.c
    src/http_stream.c
    src/stream_methods.c)

if(WITH_AVS_HTTP_ZLIB)
    set(SOURCES ${SOURCES} src/zlib.c)
endif()

set(PRIVATE_HEADERS
    src/auth.h
    src/body_receivers.h
    src/chunked.h
    src/client.h
    src/content_encoding.h
    src/headers.h
    src/http_log.h
    src/http_stream.h
    src/zlib.h)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/http.h)

set(ALL_SOURCES ${SOURCES} ${PRIVATE_HEADERS} ${PUBLIC_HEADERS})

set(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public")

set(avs_http_INCLUDE_DIRS ${INCLUDE_DIRS} PARENT_SCOPE)

include_directories(${INCLUDE_DIRS})

add_library(avs_http STATIC ${ALL_SOURCES})
avs_emit_deps(avs_http avs_algorithm avs_net avs_stream avs_utils)
if(WITH_AVS_HTTP_ZLIB)
    avs_emit_deps(avs_http ZLIB::ZLIB)
endif()

add_avs_test(avs_http ${ALL_SOURCES}
             src/test/test_close.c
             src/test/test_http.c)
if(TARGET avs_http_test)
    target_link_libraries(avs_http_test ${AVS_TARGET_DEPS_avs_http})
endif()

avs_install_export(avs_http http)
install(DIRECTORY include_public/
        COMPONENT http
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
