# Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

################# DEFINITION ###################################################

cmake_minimum_required(VERSION 3.4.0)
project(avs_commons C)
set(AVS_COMMONS_VERSION SNAPSHOT)

################# DISTRIBUTION #################################################

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
    /log/avs_log_test\\$
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

################# INITIALIZATION ###############################################

set(WITH_ADDITIONAL_LIBRARY_SUFFIXES "" CACHE STRING "Additional library file name suffixes")
set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES} ${WITH_ADDITIONAL_LIBRARY_SUFFIXES})
set(CMAKE_USE_RELATIVE_PATHS TRUE)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

################# LIBRARIES ####################################################

macro(avs_emit_deps TNAME)
    target_link_libraries(${TNAME} ${ARGN})
    list(APPEND AVS_TARGET_DEPS_${TNAME} ${ARGN})
endmacro()

macro(avs_temp_name fname)
    if(${ARGC} GREATER 1) # Have to escape ARGC to correctly compare
        set(_base ${ARGV1})
    else(${ARGC} GREATER 1)
        set(_base ".cmake-tmp")
    endif(${ARGC} GREATER 1)
    set(_counter 0)
    while(EXISTS "${CMAKE_BINARY_DIR}/${_base}${_counter}")
        math(EXPR _counter "${_counter} + 1")
    endwhile(EXISTS "${CMAKE_BINARY_DIR}/${_base}${_counter}")
    set(${fname} "${CMAKE_BINARY_DIR}/${_base}${_counter}")
endmacro()

macro(avs_find_library_inner)
    avs_temp_name(_fname)
    file(WRITE ${_fname} "${avs_find_library_EXPR_NOW}")
    include(${_fname})
    file(REMOVE ${_fname})
    foreach(PROVIDED_LIB ${ARGN})
        set(LIBRARY_FIND_ROUTINE_${PROVIDED_LIB} "${avs_find_library_EXPR_STORE}")
        set(LIBRARY_FIND_ROUTINE_PROVIDES_${PROVIDED_LIB} ${ARGN})
    endforeach()
endmacro()

macro(avs_find_library_ex EXPR_NOW EXPR_STORE)
    set(avs_find_library_EXPR_NOW "${EXPR_NOW}")
    set(avs_find_library_EXPR_STORE "${EXPR_STORE}")
    avs_find_library_inner(${ARGN})
    set(avs_find_library_EXPR_NOW)
    set(avs_find_library_EXPR_STORE)
endmacro()

macro(avs_find_library EXPR)
    set(avs_find_library_EXPR_NOW "${EXPR}")
    set(avs_find_library_EXPR_STORE "${EXPR}")
    avs_find_library_inner(${ARGN})
    set(avs_find_library_EXPR_NOW)
    set(avs_find_library_EXPR_STORE)
endmacro()

set(LIBRARY_FIND_ROUTINES)
macro(avs_emit_find_dependency LIB)
    string(REPLACE ":" "_" LIB_SANITIZED "${LIB}")
    list(FIND LIBRARY_FIND_ROUTINE_EMITTED_LIBS "${LIB}" EMITTED_LIB_INDEX)
    if(EMITTED_LIB_INDEX LESS 0)
        if(LIBRARY_FIND_ROUTINE_${LIB_SANITIZED})
            set(LIBRARY_FIND_ROUTINES "${LIBRARY_FIND_ROUTINES}

${LIBRARY_FIND_ROUTINE_${LIB_SANITIZED}}")
            list(APPEND LIBRARY_FIND_ROUTINE_EMITTED_LIBS
                 ${LIBRARY_FIND_ROUTINE_PROVIDES_${LIB_SANITIZED}})
        endif()
    endif()
endmacro()

macro(avs_install_export TNAME CNAME)
    install(TARGETS ${TNAME} COMPONENT ${CNAME} EXPORT avs_commons-targets DESTINATION ${LIB_INSTALL_DIR})
    foreach(DEP ${AVS_TARGET_DEPS_${TNAME}})
        avs_emit_find_dependency(${DEP})
    endforeach()
endmacro()

# OpenSSL
avs_find_library("find_package(OpenSSL)" OpenSSL::SSL OpenSSL::Crypto)

# mbed TLS
set(MBEDTLS_TARGETS mbedtls mbedcrypto mbedx509)
avs_find_library("
    set(CMAKE_MODULE_PATH \\\${CMAKE_MODULE_PATH} \"\\\${CMAKE_CURRENT_LIST_DIR}/cmake\")
    # Assume mbed TLS is installed to the same root as avs_commons
    set(MBEDTLS_ROOT_DIR \"\\\${CMAKE_CURRENT_LIST_DIR}/../..\" CACHE STRING \"mbed TLS installation directory\")
    set(MBEDTLS_USE_STATIC_LIBS ${MBEDTLS_USE_STATIC_LIBS})
    find_package(MbedTLS)
" ${MBEDTLS_TARGETS})
set(MBEDTLS_INCLUDE_DIRS "" CACHE PATH "mbed TLS include directory")

# tinyDTLS
avs_find_library("
    set(TINYDTLS_ROOT_DIR \"${TINYDTLS_ROOT_DIR}\")
    find_package(TinyDTLS)
" tinydtls)

# zlib
avs_find_library("find_package(ZLIB)" ZLIB::ZLIB)

# SSL
option(WITH_OPENSSL "Enable OpenSSL" OFF)
option(WITH_MBEDTLS "Enable mbed TLS" OFF)
option(WITH_TINYDTLS "Enable tinyDTLS" OFF)

set(_AVS_TLS_BACKENDS "")
if(WITH_OPENSSL)
    list(APPEND _AVS_TLS_BACKENDS "openssl")
endif()
if(WITH_MBEDTLS)
    list(APPEND _AVS_TLS_BACKENDS "mbedtls")
endif()
if(WITH_TINYDTLS)
    list(APPEND _AVS_TLS_BACKENDS "tinydtls")
endif()

list(LENGTH _AVS_TLS_BACKENDS _AVS_NUM_TLS_BACKENDS)
if(_AVS_NUM_TLS_BACKENDS GREATER 1)
    string(REPLACE ";" ", " _AVS_TLS_BACKENDS "${_AVS_TLS_BACKENDS}")
    message(FATAL_ERROR "Selected ${_AVS_TLS_BACKENDS} as TLS backends but only one may be used.")
elseif(_AVS_NUM_TLS_BACKENDS GREATER 0)
    set(WITH_SSL ON)
endif()

include(CMakeDependentOption)
cmake_dependent_option(WITH_DTLS "Enable OpenSSL DTLS support" ON WITH_SSL OFF)
cmake_dependent_option(WITH_EC_KEY "Enable OpenSSL EC_KEY support" ON WITH_SSL OFF)
cmake_dependent_option(WITH_PSK "Enable pre-shared key support" ON WITH_SSL OFF)
cmake_dependent_option(WITH_X509 "Enable X.509 certificate support" ON WITH_SSL OFF)

if(${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    set(MODULES_ENABLED ON)
else()
    set(MODULES_ENABLED OFF)
endif()

if(MODULES_ENABLED OR WITH_TEST)
    set(WITH_AVS_UNIT_DEFAULT ON)
else()
    set(WITH_AVS_UNIT_DEFAULT OFF)
endif()

option(WITH_AVS_ALGORITHM "AVSystem algorithm utilities library" ${MODULES_ENABLED})
option(WITH_AVS_UNIT "AVSystem unit test library" ${WITH_AVS_UNIT_DEFAULT})
option(WITH_AVS_BUFFER "AVSystem buffer implementation" ${MODULES_ENABLED})
option(WITH_AVS_LIST "AVSystem generic linked list implementation" ${MODULES_ENABLED})
option(WITH_AVS_VECTOR "AVSystem generic vector implementation" ${MODULES_ENABLED})
option(WITH_AVS_UTILS "AVSystem various utility functions" ${MODULES_ENABLED})
option(WITH_AVS_NET "AVSystem network communication abstraction layer" ${MODULES_ENABLED})
option(WITH_AVS_STREAM "AVSystem IO stream abstraction layer" ${MODULES_ENABLED})
option(WITH_AVS_LOG "AVSystem logging framework" ${MODULES_ENABLED})
option(WITH_AVS_RBTREE "AVSystem generic red-black tree implementation" ${MODULES_ENABLED})
option(WITH_AVS_COAP "AVSystem CoAP abstraction layer" ${MODULES_ENABLED})
option(WITH_AVS_HTTP "AVSystem HTTP client" ${MODULES_ENABLED})
option(WITH_AVS_PERSISTENCE "AVSystem persistence framework" ${MODULES_ENABLED})
option(WITH_AVS_COMPAT_THREADING "Use multithreading utility compatibility layer" ${MODULES_ENABLED})

cmake_dependent_option(WITH_INTERNAL_LOGS "Enable logging from inside AVSystem Commons libraries" ON WITH_AVS_LOG OFF)
cmake_dependent_option(WITH_INTERNAL_TRACE "Enable TRACE-level logs inside AVSystem Commons libraries" OFF WITH_INTERNAL_LOGS OFF)
cmake_dependent_option(WITH_MBEDTLS_LOGS "Enable logging from mbedTLS backend library (if used)" OFF "WITH_INTERNAL_LOG;WITH_MBEDTLS" OFF)

if(WITH_AVS_LOG)
    set(AVS_LOG_MAX_LINE_LENGTH 512 CACHE INTEGER "Max length of a single log message. Longer ones will be truncated.")
    cmake_dependent_option(AVS_LOG_USE_GLOBAL_BUFFER
                           "Use global log message buffer instead of allocating one on stack. Reduces stack usage of threads that use avs_log() at the cost of synchronized access to the buffer."
                           OFF WITH_AVS_MUTEX OFF)
endif()

cmake_dependent_option(WITH_TEST "Enable unit tests of AVSystem Commons library itself" OFF WITH_AVS_UNIT OFF)
cmake_dependent_option(WITH_CXX_TESTS "Enable C++ unit tests" ON WITH_TEST OFF)
if(WITH_CXX_TESTS)
    enable_language(CXX)
endif()

set(POSIX_COMPAT_HEADER_DEFAULT "")
if(WIN32)
    set(POSIX_COMPAT_HEADER_DEFAULT "${CMAKE_CURRENT_SOURCE_DIR}/compat/winsock-posix-compat.h")
endif()

set(POSIX_COMPAT_HEADER ${POSIX_COMPAT_HEADER_DEFAULT} CACHE STRING "POSIX compatibility header path, if required")

################################################################################

option(WITH_EXTRA_WARNINGS "Enable extra compilation warnings" OFF)
if(WITH_EXTRA_WARNINGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -pedantic -Wall -Wextra -Winit-self -Wmissing-declarations -Wc++-compat -Wsign-conversion -Wconversion -Wcast-qual -Wno-variadic-macros -Wno-long-long -Wvla")
    if(WITH_CXX_TESTS)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++98 -pedantic -Wall -Wextra -Winit-self -Wmissing-declarations -Wsign-conversion -Wconversion -Wcast-qual -Wno-variadic-macros -Wno-long-long")
    endif()
endif()

option(WITH_POISONING "Poison libc symbols that shall not be used" ${WITH_TEST})

if(CMAKE_C_COMPILE_OPTIONS_PIC)
    option(WITH_PIC "Generate position-independent code" ON)
    if(WITH_PIC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_COMPILE_OPTIONS_PIC}")
        if(WITH_CXX_TESTS)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_COMPILE_OPTIONS_PIC}")
        endif()
    endif()
endif()

# -fvisibility, #pragma GCC visibility
if(NOT DEFINED HAVE_VISIBILITY)
    file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/visibility.c "#pragma GCC visibility push(default)\nint f();\n#pragma GCC visibility push(hidden)\nint f() { return 0; }\n#pragma GCC visibility pop\nint main() { return f(); }\n\n")
    try_compile(HAVE_VISIBILITY
                ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp
                ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/visibility.c
                COMPILE_DEFINITIONS -Wall -Wextra -Werror -fvisibility=default)
endif()

if(NOT DEFINED HAVE_PRAGMA_DIAGNOSTIC)
    file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/diagnostic.c "#pragma GCC diagnostic ignored \"-Wformat\"\nint main(){}\n\n")
    try_compile(HAVE_PRAGMA_DIAGNOSTIC
                ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp
                ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/diagnostic.c
                COMPILE_DEFINITIONS -Werror)
endif()

# Check for builtin GCC/Clang safe arithmetic functions
# we need to use try_compile to attempt linking
# as they might not work on Clang if -rtlib=compiler-rt is not set
file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/builtin_add_overflow.c "#include <stdint.h>\nint main() { int64_t a,b,c; return __builtin_add_overflow(a, b, &c); }\n")
file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/builtin_mul_overflow.c "#include <stdint.h>\nint main() { int64_t a,b,c; return __builtin_mul_overflow(a, b, &c); }\n")
try_compile(HAVE_BUILTIN_ADD_OVERFLOW ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/builtin_add_overflow.c)
try_compile(HAVE_BUILTIN_MUL_OVERFLOW ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/builtin_mul_overflow.c)

# C11 stdatomic
file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/c11_stdatomic.c "#include <stdatomic.h>\nint main() { volatile atomic_flag a = ATOMIC_FLAG_INIT; return atomic_flag_test_and_set(&a); }\n")
try_compile(HAVE_C11_STDATOMIC ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/c11_stdatomic.c)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/PosixFeatures.cmake)

include(TestBigEndian)
test_big_endian(AVS_COMMONS_BIG_ENDIAN)

include(CheckFunctionExists)
check_function_exists(getifaddrs HAVE_GETIFADDRS)
check_function_exists(backtrace HAVE_BACKTRACE)
check_function_exists(backtrace_symbols HAVE_BACKTRACE_SYMBOLS)

include(CheckSymbolExists)
foreach(MATH_LIBRARY_IT "" "m")
    file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/fmod.c "#include <math.h>\nint main() { volatile double a = 4.0, b = 3.2; return (int) fmod(a, b); }\n\n")
    try_compile(HAVE_MATH_LIBRARY ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/fmod.c CMAKE_FLAGS "-DLINK_LIBRARIES=${MATH_LIBRARY_IT}")
    if(HAVE_MATH_LIBRARY)
        set(MATH_LIBRARY "${MATH_LIBRARY_IT}")
        break()
    endif()
endforeach()
if(NOT HAVE_MATH_LIBRARY)
    message(FATAL_ERROR "Floating-point math functions not available")
endif()

option(WITH_IPV4 "Enable IPv4 support" ON)
option(WITH_IPV6 "Enable IPv6 support" ON)

option(WITH_SOCKET_LOG "Enable socket communication logging" OFF)

set(INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/include_public"
    "${CMAKE_CURRENT_BINARY_DIR}/include_public")

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/config"
                    "${CMAKE_CURRENT_BINARY_DIR}/config"
                    ${INCLUDE_DIRS})


find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE)
    option(WITH_VALGRIND "Enable usage of valgrind during unit tests" OFF)
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
    set(VALGRIND ${VALGRIND_EXECUTABLE} ${VALGRIND_ARGS} -q --error-exitcode=63 --suppressions=${CMAKE_CURRENT_SOURCE_DIR}/avs_commons_test.supp)
endif()

enable_testing()

if(NOT LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR lib)
endif()

if(NOT INCLUDE_INSTALL_DIR)
    set(INCLUDE_INSTALL_DIR include)
endif()

macro(make_absolute_sources ABSVAR)
    set(${ABSVAR})
    foreach(SRC ${ARGN})
        set(${ABSVAR} ${${ABSVAR}} ${CMAKE_CURRENT_SOURCE_DIR}/${SRC})
    endforeach()
endmacro()

set(MODULE_INCLUDE_DIRS)

# Named arguments:
# PATH - relative path to the module subdirectory. If not given, NAME is used instead.
# NAME - module name, used as a substring of output library name and Makefile targets
# INCLUDE_DIRS_VAR - name of the variable to append module include dirs to. If not set,
#                    MODULE_INCLUDE_DIRS is assumed.
function(add_module_with_include_dirs)
    set(options)
    set(one_value_args PATH NAME INCLUDE_DIRS_VAR)
    set(multi_value_args)
    cmake_parse_arguments(AMWID "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(NOT DEFINED AMWID_NAME)
        message(FATAL_ERROR "Required argument NAME not given")
    endif()
    if(NOT DEFINED AMWID_PATH)
        set(AMWID_PATH "${AMWID_NAME}")
    endif()
    if(NOT DEFINED INCLUDE_DIRS_VAR)
        set(AMWID_INCLUDE_DIRS_VAR MODULE_INCLUDE_DIRS)
    endif()

    add_subdirectory(${AMWID_PATH})
    include_directories(${avs_${AMWID_NAME}_INCLUDE_DIRS})

    # Append module includes to a specified variable name (i.e. MODULE_INCLUDE_DIRS_VAR).
    set(${AMWID_INCLUDE_DIRS_VAR}
        ${${AMWID_INCLUDE_DIRS_VAR}}
        ${avs_${AMWID_NAME}_INCLUDE_DIRS}
        PARENT_SCOPE)

    if(TARGET avs_${AMWID_NAME}_check)
        add_test(NAME test_avs_${AMWID_NAME}_symbols
                 COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_symbols.sh $<TARGET_FILE:avs_${AMWID_NAME}> avs_ AVS_ _avs _AVS_)
        add_dependencies(avs_commons_symbols_check avs_${AMWID_NAME})
    endif()
    file(GLOB_RECURSE MODULE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${AMWID_PATH}/*.c
                                   ${CMAKE_CURRENT_SOURCE_DIR}/${AMWID_PATH}/*.h)
    foreach(F ${MODULE_FILES})
        add_test(NAME test_${F}_visibility COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_visibility.py ${F})
        add_test(NAME test_${F}_headers COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_headers.py ${F})
    endforeach()

    avs_propagate_exports()
endfunction()

if(WITH_AVS_UNIT)
    add_module_with_include_dirs(NAME unit)
endif()

if(WITH_TEST)
    if(NOT WITH_AVS_UNIT)
        message(FATAL_ERROR "WITH_TEST requires WITH_AVS_UNIT to be enabled")
    endif()

    if(NOT EXISTS "${CMAKE_CURRENT_BINARY_DIR}/certs/client.crt.der")
        execute_process(COMMAND
                        env bash
                        "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate-certs.sh"
                        "${CMAKE_CURRENT_BINARY_DIR}/certs"
                        RESULT_VARIABLE RES)
        if(NOT ${RES} EQUAL 0)
            message(FATAL_ERROR "could not generate SSL certificates")
        endif()
    endif()

    add_custom_target(avs_commons_check)
    if(${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
        add_custom_target(check)
        add_dependencies(check avs_commons_check)
    endif()

    # license check is only possible if running in a Git working tree
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
        add_custom_target(license_check COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/tools/check-license-headers.py" --root "${CMAKE_CURRENT_SOURCE_DIR}")
        add_dependencies(avs_commons_check license_check)
    endif()

    add_custom_target(avs_commons_symbols_check COMMAND ${CMAKE_CTEST_COMMAND} -R "'^test_.*_symbols$$'" --output-on-failure)
    add_dependencies(avs_commons_check avs_commons_symbols_check)

    add_custom_target(avs_commons_visibility_check COMMAND ${CMAKE_CTEST_COMMAND} -R "'^test_.*_visibility$$'")
    add_dependencies(avs_commons_check avs_commons_visibility_check)

    add_custom_target(avs_commons_headers_check COMMAND ${CMAKE_CTEST_COMMAND} -R "'^test_.*_headers$$'")
    add_dependencies(avs_commons_check avs_commons_headers_check)

    add_custom_target(avs_install_test
                      COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/tests/test-install.sh"
                              "${CMAKE_CURRENT_SOURCE_DIR}/tests/install")

    set(_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

    add_subdirectory(tools)

    # NAME - test target name, without _test suffix
    # LIBS - libs to link to
    # SOURCES - test sources
    function(avs_add_test)
        set(options)
        set(one_value_args NAME)
        set(multi_value_args LIBS SOURCES)
        cmake_parse_arguments(AAT "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

        add_executable(${AAT_NAME}_test EXCLUDE_FROM_ALL
                       ${AAT_SOURCES})
        target_link_libraries(${AAT_NAME}_test PRIVATE avs_unit ${AAT_LIBS})
        add_dependencies(${AAT_NAME}_test dtls_echo_server)

        set_property(TARGET ${AAT_NAME}_test APPEND PROPERTY COMPILE_DEFINITIONS
                     AVS_UNIT_TESTING
                     AVS_TEST_BIN_DIR="${_BINARY_DIR}")
        set_property(TARGET ${AAT_NAME}_test APPEND PROPERTY COMPILE_FLAGS
                     "-Wno-clobbered -Wno-overlength-strings -Wno-sign-conversion -Wno-vla")

        if(VALGRIND)
            set(VALGRIND_LOG ${VALGRIND} --log-file=VALGRIND.${AAT_NAME}.log)
        else()
            set(VALGRIND_LOG)
        endif()

        add_test(NAME ${AAT_NAME}_test COMMAND ${VALGRIND_LOG} $<TARGET_FILE:${AAT_NAME}_test>)

        add_custom_target(${AAT_NAME}_check COMMAND ${CMAKE_CTEST_COMMAND} -V -R "^${AAT_NAME}_test$" DEPENDS ${AAT_NAME}_test)
        add_dependencies(avs_commons_check ${AAT_NAME}_check)
    endfunction()

    add_subdirectory(tests)
else(WITH_TEST)
    function(avs_add_test)
    endfunction()
endif(WITH_TEST)

if(WITH_AVS_ALGORITHM)
    add_module_with_include_dirs(NAME algorithm)
endif()

if(WITH_AVS_BUFFER)
    add_module_with_include_dirs(NAME buffer)
endif()

if(WITH_AVS_LIST)
    add_module_with_include_dirs(NAME list)
endif()

if(WITH_AVS_VECTOR)
    add_module_with_include_dirs(NAME vector)
endif()

if(WITH_AVS_UTILS)
    add_module_with_include_dirs(NAME utils)
endif()

if(WITH_AVS_NET)
    if(WITH_OPENSSL)
        if(NOT OPENSSL_FOUND)
            message(FATAL_ERROR "OpenSSL libraries not found")
        endif()

        set(WITH_OPENSSL_CUSTOM_CIPHERS OFF CACHE STRING "Customized OpenSSL cipher suite list")

    elseif(WITH_MBEDTLS)
        if(NOT MBEDTLS_FOUND)
            message(FATAL_ERROR "mbed TLS libraries not found")
        endif()
        separate_arguments(MBEDTLS_INCLUDE_DIRS)
        if(MBEDTLS_INCLUDE_DIRS)
            include_directories(${MBEDTLS_INCLUDE_DIRS})
        endif()
    elseif(WITH_TINYDTLS)
        if (NOT TINYDTLS_FOUND)
            message(FATAL_ERROR "tinyDTLS libraries not found")
        endif()
    endif()

    add_module_with_include_dirs(NAME net)
endif()

if(WITH_AVS_STREAM)
    add_module_with_include_dirs(NAME stream)
endif()

if(WITH_AVS_LOG)
    add_module_with_include_dirs(NAME log)
endif()

if (WITH_AVS_RBTREE)
    add_module_with_include_dirs(NAME rbtree)
endif()

cmake_dependent_option(WITH_AVS_COAP_MESSAGE_CACHE
                       "Enable support for message caching to detect and automatically handle duplicate messages"
                       ON WITH_AVS_COAP OFF)
cmake_dependent_option(WITH_AVS_COAP_NET_STATS
                       "Enable support for measuring some CoAP socket statistics"
                       ON WITH_AVS_COAP OFF)

if(WITH_AVS_COAP)
    add_module_with_include_dirs(NAME coap)
endif()

cmake_dependent_option(WITH_AVS_HTTP_ZLIB
                       "Enable support for HTTP compression using zlib"
                       ON WITH_AVS_HTTP OFF)
if(WITH_AVS_HTTP)
    add_module_with_include_dirs(NAME http)
    if(WITH_AVS_HTTP_ZLIB)
        if(NOT ZLIB_FOUND)
            message(FATAL_ERROR "zlib not found")
        endif()
        if(ZLIB_INCLUDE_DIRS)
            separate_arguments(ZLIB_INCLUDE_DIRS)
            include_directories(${ZLIB_INCLUDE_DIRS})
        endif()
    endif()
endif()

if(WITH_AVS_PERSISTENCE)
    add_module_with_include_dirs(NAME persistence)
endif()

if(WITH_AVS_COMPAT_THREADING)
    add_module_with_include_dirs(NAME compat_threading
                                 PATH compat/threading)
endif()

# API documentation
set(DOXYGEN_SKIP_DOT TRUE)
find_package(Doxygen)

if(DOXYGEN_FOUND)
    set(DOXYGEN_INPUT_PATHS ${MODULE_INCLUDE_DIRS})
    # doxygen expects whitespace-separated list, cmake stores them as
    # semicolon-separated strings
    string(REPLACE ";" " " DOXYGEN_INPUT_PATHS "${DOXYGEN_INPUT_PATHS}")
    configure_file(doc/Doxyfile.in doc/Doxyfile @ONLY)
    add_custom_target(avs_commons_doc
                      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/doc/Doxyfile)

    if(${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
        add_custom_target(doc)
        add_dependencies(doc avs_commons_doc)
    endif()
endif()

# Export general avs_commons includes as well as module level includes.
if(NOT ${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    set(avs_commons_INCLUDE_DIRS ${INCLUDE_DIRS} ${MODULE_INCLUDE_DIRS} PARENT_SCOPE)
endif()

configure_file("config/avs_commons_config.h.in" "config/avs_commons_config.h")
configure_file("config/avs_commons_posix_config.h.in" "config/avs_commons_posix_config.h")
configure_file("include_public/avsystem/commons/defs.h.in"
               "include_public/avsystem/commons/defs.h")

configure_file(avs_commons-config.cmake.in avs_commons-config.cmake @ONLY)
configure_file(avs_commons-version.cmake.in avs_commons-version.cmake @ONLY)
install(EXPORT avs_commons-targets DESTINATION ${LIB_INSTALL_DIR}/avs_commons)
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/avs_commons-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/avs_commons-version.cmake
        DESTINATION ${LIB_INSTALL_DIR}/avs_commons)
install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindMbedTLS.cmake
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindTinyDTLS.cmake
        DESTINATION ${LIB_INSTALL_DIR}/avs_commons/cmake)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include_public/"
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include_public/"
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")
