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

add_library(avs_coap STATIC
            include_public/avsystem/commons/coap/block_builder.h
            include_public/avsystem/commons/coap/block_utils.h
            include_public/avsystem/commons/coap/ctx.h
            include_public/avsystem/commons/coap/msg_builder.h
            include_public/avsystem/commons/coap/msg.h
            include_public/avsystem/commons/coap/msg_identity.h
            include_public/avsystem/commons/coap/msg_info.h
            include_public/avsystem/commons/coap/tx_params.h

            src/block_builder.c
            src/block_utils.c
            src/ctx.c
            src/msg_builder.c
            src/msg.c
            src/msg_info.c
            src/msg_opt.c
            src/opt.c
            src/tx_params.c)

if(WITH_AVS_COAP_MESSAGE_CACHE)
    target_sources(avs_coap PRIVATE src/msg_cache.c)
endif()

target_include_directories(avs_coap PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_coap PUBLIC avs_commons_config avs_log avs_buffer avs_utils avs_net)

avs_add_test(NAME avs_coap
             LIBS avs_coap
             SOURCES 
             $<TARGET_PROPERTY:avs_coap,SOURCES>
             src/test/ctx.c
             src/test/msg_cache.c)

avs_install_export(avs_coap coap)
install(DIRECTORY include_public/
        COMPONENT coap
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
