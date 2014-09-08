#
#  AVSystem Commons Library
#
#  Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/api.c
    src/net.c)

if(NOT HAVE_INET_NTOP)
    set(SOURCES ${SOURCES} src/inet_ntop.c)
endif()

set(PRIVATE_HEADERS
    src/net.h)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/net.h
    include_public/avsystem/commons/socket_v_table.h)

set(ALL_SOURCES ${SOURCES} ${PRIVATE_HEADERS} ${PUBLIC_HEADERS})

include_directories(include_public)

add_library(avs_net STATIC ${ALL_SOURCES})

install(TARGETS avs_net
        COMPONENT net
        EXPORT avs_commons-targets
        DESTINATION ${LIB_INSTALL_DIR})
install(DIRECTORY include_public/
        COMPONENT net
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")