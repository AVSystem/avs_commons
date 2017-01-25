#
#  AVSystem Commons Library
#
#  Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/addrinfo.c
    src/api.c
    src/net.c)

if(NOT HAVE_INET_NTOP)
    set(SOURCES ${SOURCES} src/inet_ntop.c)
endif()

if(NOT HAVE_INET_PTON)
    set(SOURCES ${SOURCES} src/inet_pton.c)
endif()

if(WITH_OPENSSL)
    set(SOURCES ${SOURCES} src/openssl.c)
elseif(WITH_MBEDTLS)
    set(SOURCES ${SOURCES} src/mbedtls.c)
endif()

set(PRIVATE_HEADERS
    src/net.h
    src/lwip_compat.h)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/net.h
    include_public/avsystem/commons/socket_v_table.h)

set(ALL_SOURCES ${SOURCES} ${PRIVATE_HEADERS} ${PUBLIC_HEADERS})

set(avs_net_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public"
    CACHE INTERNAL "" FORCE)

include_directories(${avs_net_INCLUDE_DIRS})

add_library(avs_net STATIC ${ALL_SOURCES})
if(WITH_INTERNAL_LOGS)
    target_link_libraries(avs_net avs_log)
    include_directories(../log/include_public)
endif()

if(WITH_OPENSSL)
    avs_emit_deps(avs_net ssl crypto)
elseif(WITH_MBEDTLS)
    avs_emit_deps(avs_net ${MBEDTLS_LIBRARIES})
endif()

avs_install_export(avs_net net)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT net
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
