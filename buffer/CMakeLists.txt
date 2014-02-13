#
#  AVSystem Commons Library
#
#  Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/buffer.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/buffer.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

include_directories(include_public)

add_library(avs_buffer STATIC ${ALL_SOURCES})

install(TARGETS avs_buffer
        COMPONENT buffer
        EXPORT avs_commons-targets
        DESTINATION ${LIB_INSTALL_DIR})
install(DIRECTORY include_public/
        COMPONENT buffer
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

include_directories(${AVS_TEST_INCLUDE_DIRS})
add_avs_test(avs_buffer ${ALL_SOURCES})
