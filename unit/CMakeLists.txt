#
#  AVSystem Commons Library
#
#  Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/mock.c
    src/test.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/unit/mock_helpers.h
    include_public/avsystem/commons/unit/test.h)

macro(make_absolute_sources ABSVAR)
    set(${ABSVAR})
    foreach(SRC ${ARGN})
        set(${ABSVAR} ${${ABSVAR}} ${CMAKE_CURRENT_SOURCE_DIR}/${SRC})
    endforeach()
endmacro()

set(INCLUDE_DIRS include_public ../list/include_public)
make_absolute_sources(ABSOLUTE_INCLUDE_DIRS ${INCLUDE_DIRS})
set(AVS_TEST_INCLUDE_DIRS "${ABSOLUTE_INCLUDE_DIRS}" PARENT_SCOPE)

include_directories(${INCLUDE_DIRS})

add_library(avs_unit STATIC ${SOURCES} ${PUBLIC_HEADERS})
target_link_libraries(avs_unit avs_list)

install(TARGETS avs_unit
        COMPONENT unit
        EXPORT avs_commons-targets
        DESTINATION ${LIB_INSTALL_DIR})
install(DIRECTORY include_public/
        COMPONENT unit
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
