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

macro(add_avs_test NAME)
    add_executable(${NAME}_test EXCLUDE_FROM_ALL ${ARGN})
    target_link_libraries(${NAME}_test avs_unit)
    set_property(TARGET ${NAME}_test APPEND PROPERTY COMPILE_DEFINITIONS AVS_UNIT_TESTING)
    set_property(TARGET ${NAME}_test APPEND PROPERTY COMPILE_FLAGS "-Wno-clobbered -Wno-overlength-strings -Wno-c++-compat -Wno-sign-conversion")

    if(VALGRIND)
        set(VALGRIND_LOG ${VALGRIND} --log-file=VALGRIND.${NAME}.log)
    else()
        set(VALGRIND_LOG)
    endif()

    add_test(${NAME}_test ${VALGRIND_LOG} ${CMAKE_CURRENT_BINARY_DIR}/${NAME}_test)

    add_custom_target(${NAME}_check COMMAND ${CMAKE_CTEST_COMMAND} -V DEPENDS ${NAME}_test)
    add_dependencies(check ${NAME}_check)
endmacro()

install(TARGETS avs_unit
        COMPONENT unit
        EXPORT avs_commons-targets
        DESTINATION ${LIB_INSTALL_DIR})
install(DIRECTORY include_public/
        COMPONENT unit
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
