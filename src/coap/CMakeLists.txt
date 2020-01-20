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

add_library(avs_coap STATIC
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/block_builder.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/block_utils.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/ctx.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/msg_builder.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/msg.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/msg_identity.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/msg_info.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/msg_opt.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/opt.h"
            "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap/tx_params.h"

            block_builder.c
            block_utils.c
            ctx.c
            msg_builder.c
            msg.c
            msg_info.c
            msg_opt.c
            opt.c
            tx_params.c)

if(WITH_AVS_COAP_MESSAGE_CACHE)
    target_sources(avs_coap PRIVATE msg_cache.c)
endif()

target_include_directories(avs_coap PUBLIC
                           $<BUILD_INTERFACE:${AVS_COMMONS_SOURCE_DIR}/include_public>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(avs_coap PUBLIC avs_commons_global_headers avs_buffer avs_utils avs_net avs_list)

if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_coap PUBLIC avs_log)
endif()

avs_add_test(NAME avs_coap
             LIBS avs_coap
             SOURCES
             $<TARGET_PROPERTY:avs_coap,SOURCES>
             ${AVS_COMMONS_SOURCE_DIR}/tests/coap/ctx.c
             ${AVS_COMMONS_SOURCE_DIR}/tests/coap/msg_cache.c)
get_target_property(AVS_NET_VARIANT avs_net ALIASED_TARGET)
if(TARGET avs_coap_test)
    # NOTE: avs_coap tests require certificate support,
    # which is not implemented for the tinyDTLS backend
    if(${AVS_NET_VARIANT} STREQUAL avs_net_nosec
       OR ${AVS_NET_VARIANT} STREQUAL avs_net_tinydtls)
        target_compile_definitions(avs_coap_test PRIVATE WITHOUT_SSL)
    endif()
endif()

avs_install_export(avs_coap coap)
install(DIRECTORY "${AVS_COMMONS_SOURCE_DIR}/include_public/avsystem/commons/coap"
        COMPONENT coap
        DESTINATION ${INCLUDE_INSTALL_DIR}/avsystem/commons
        FILES_MATCHING REGEX "[.]h$")
