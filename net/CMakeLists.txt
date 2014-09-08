#
#  AVSystem Commons Library
#
#  Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/socket.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/net.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

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