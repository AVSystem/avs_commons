#
#  AVSystem Commons Library
#
#  Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/vector.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/vector.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

set(avs_vector_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public"
    CACHE INTERNAL "" FORCE)

include_directories(${avs_vector_INCLUDE_DIRS})

add_library(avs_vector STATIC ${ALL_SOURCES})

avs_install_export(avs_vector vector)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT vector
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

include_directories(${AVS_TEST_INCLUDE_DIRS})
add_avs_test(avs_vector ${ALL_SOURCES})
