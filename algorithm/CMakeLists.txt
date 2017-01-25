#
#  AVSystem Commons Library
#
#  Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/base64.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/base64.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

set(avs_algorithm_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public"
    CACHE INTERNAL "" FORCE)

include_directories(${avs_algorithm_INCLUDE_DIRS})

add_library(avs_algorithm STATIC ${ALL_SOURCES})

avs_install_export(avs_algorithm algorithm)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT algorithm
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

include_directories(${AVS_TEST_INCLUDE_DIRS})
add_avs_test(avs_algorithm ${ALL_SOURCES})
