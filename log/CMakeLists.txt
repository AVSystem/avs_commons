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

set(INCLUDE_DIRS include_public ../list/include_public)
make_absolute_sources(ABSOLUTE_INCLUDE_DIRS ${INCLUDE_DIRS})
set(AVS_TEST_INCLUDE_DIRS "${ABSOLUTE_INCLUDE_DIRS}" PARENT_SCOPE)

include_directories(${INCLUDE_DIRS})

add_library(avs_log STATIC ${ALL_SOURCES})
target_link_libraries(avs_log avs_list)

avs_install_export(avs_log log)
install(DIRECTORY include_public/
        COMPONENT log
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

include_directories(${AVS_TEST_INCLUDE_DIRS})
add_avs_test(avs_log ${ALL_SOURCES})
