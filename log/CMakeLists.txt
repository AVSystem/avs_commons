#
#  AVSystem Commons Library
#
#  Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/log.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/log.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

include_directories(include_public)

add_library(avs_log STATIC ${ALL_SOURCES})

avs_install_export(avs_log log)
install(DIRECTORY include_public/
        COMPONENT log
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
