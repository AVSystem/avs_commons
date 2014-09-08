#
#  AVSystem Commons Library
#
#  Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

cmake_minimum_required(VERSION 2.8.1)
project(avs_commons C)
set(AVS_COMMONS_VERSION SNAPSHOT)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "AVSystem Commons Library")
set(CPACK_PACKAGE_VENDOR "AVSystem")
set(CPACK_PACKAGE_VERSION "${AVS_COMMONS_VERSION}")
set(CPACK_SOURCE_GENERATOR "TGZ")

set(CPACK_SOURCE_IGNORE_FILES
    \\\\.a\\$
    \\\\.so\\$
    \\\\.so\\\\.
    /list/avs_list_test\\$
    /buffer/avs_buffer_test\\$
    /nbproject
    \\\\.log\\$
    /CMakeFiles/
    /CMakeTmp/
    /Makefile\\$
    /CMakeCache\\\\.txt\\$
    \\\\.cmake\\$
    /compile_commands\\\\.json\\$
    /install_manifest\\\\.txt\\$
    /_CPack_Packages/
    /Testing/
    \\\\.tar\\\\.gz\\$
    \\\\.tgz\\$
    \\\\.deb\\$
    /\\\\.git)

include(CPack)

add_custom_target(dist COMMAND ${CMAKE_CPACK_COMMAND} --config ${CMAKE_BINARY_DIR}/CPackSourceConfig.cmake WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

option(WITH_EXTRA_WARNINGS "Enable extra compilation warnings" OFF)
if(WITH_EXTRA_WARNINGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c89 -pedantic -Wall -Wextra -Winit-self -Wmissing-declarations -Wc++-compat -Wsign-conversion -Wconversion -Wcast-qual -Wno-variadic-macros -Wno-long-long")
endif()

if(CMAKE_C_COMPILE_OPTIONS_PIC)
    option(WITH_PIC "Generate position-independent code" ON)
    if(WITH_PIC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_COMPILE_OPTIONS_PIC}")
    endif()
endif()

# -fvisibility, #pragma GCC visibility
file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/visibility.c "#pragma GCC visibility push(default)\nint f();\n#pragma GCC visibility push(hidden)\nint f() { return 0; }\n#pragma GCC visibility pop\nint main() { return f(); }\n\n")
try_compile(HAVE_VISIBILITY ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/visibility.c COMPILE_DEFINITIONS -Wall -Wextra -Werror -fvisibility=default)

include(CheckIncludeFiles)
check_include_files("net/if.h" AVS_HAS_NET_IF_H)

include(CheckFunctionExists)
check_function_exists(getnameinfo HAVE_GETNAMEINFO)
check_function_exists(poll HAVE_POLL)

option(WITH_LWIP "Use lwIP library for networking" OFF)

option(WITH_SOCKET_LOG "Enable socket communication logging" OFF)

include_directories(config)
include_directories(include_public)

find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE)
    option(WITH_VALGRIND "Enable usage of valgrind during unit tests" ON)
endif()
if(WITH_VALGRIND)
    execute_process(COMMAND ${VALGRIND_EXECUTABLE} --tool=helgrind --version
                    RESULT_VARIABLE HELGRIND_TEST_RESULT
                    OUTPUT_QUIET ERROR_QUIET)
    if(HELGRIND_TEST_RESULT EQUAL 0)
        option(WITH_HELGRIND "Put valgrind in helgrind mode (test for race conditions instead of memory errors)" OFF)
    endif()
    if(WITH_HELGRIND)
        set(VALGRIND_ARGS --tool=helgrind)
    else()
        set(VALGRIND_ARGS --leak-check=full --track-origins=yes)
    endif()
    set(VALGRIND ${VALGRIND_EXECUTABLE} ${VALGRIND_ARGS} -q --error-exitcode=63)
endif()

enable_testing()
add_custom_target(check)

if(NOT LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR lib)
endif()

if(NOT INCLUDE_INSTALL_DIR)
    set(INCLUDE_INSTALL_DIR include)
endif()

set(DOXYGEN_SKIP_DOT TRUE)
find_package(Doxygen)

if(DOXYGEN_FOUND)
    configure_file(doc/Doxyfile.in doc/Doxyfile @ONLY)
    add_custom_target(doc
                      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/doc/Doxyfile)
endif()

option(WITH_AVS_UNIT "AVSystem unit test library" ON)
if(WITH_AVS_UNIT)
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

    add_subdirectory(unit)
else()
    macro(add_avs_test NAME)
    endmacro()
endif()

option(WITH_AVS_BUFFER "AVSystem buffer implementation" ON)
if(WITH_AVS_BUFFER)
    add_subdirectory(buffer)
endif()

option(WITH_AVS_LIST "AVSystem generic linked list implementation" ON)
if(WITH_AVS_LIST)
    add_subdirectory(list)
endif()

option(WITH_AVS_NET "AVSystem network communication abstraction layer" ON)
if(WITH_AVS_NET)
    add_subdirectory(net)
endif()

configure_file("config/config.h.in" "config/config.h")
configure_file("include_public/avsystem/commons/defs.h.in" "include_public/avsystem/commons/defs.h")

install(EXPORT avs_commons-targets
        DESTINATION ${LIB_INSTALL_DIR}/avs_commons)
configure_file(avs_commons-config.cmake.in avs_commons-config.cmake @ONLY)
configure_file(avs_commons-version.cmake.in avs_commons-version.cmake @ONLY)
install(EXPORT avs_commons-targets DESTINATION ${LIB_INSTALL_DIR}/avs_commons)
install(FILES
        ${CMAKE_BINARY_DIR}/avs_commons-config.cmake
        ${CMAKE_BINARY_DIR}/avs_commons-version.cmake
        DESTINATION ${LIB_INSTALL_DIR}/avs_commons)
install(DIRECTORY include_public/
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
