#
#  AVSystem Commons Library
#
#  Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
#
#  This code is free and open source software licensed under the MIT License.
#  See the LICENSE file for details.
#

set(SOURCES
    src/rbtree.c)

set(PUBLIC_HEADERS
    include_public/avsystem/commons/rbtree.h)

set(ALL_SOURCES ${SOURCES} ${PUBLIC_HEADERS})

set(avs_rbtree_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include_public"
    CACHE INTERNAL "" FORCE)

include_directories(${avs_rbtree_INCLUDE_DIRS})

add_library(avs_rbtree STATIC ${ALL_SOURCES})

avs_install_export(avs_rbtree rbtree)
avs_propagate_exports()
install(DIRECTORY include_public/
        COMPONENT rbtree
        DESTINATION ${INCLUDE_INSTALL_DIR}
        FILES_MATCHING REGEX "[.]h$")

include_directories(${AVS_TEST_INCLUDE_DIRS}
                    "../unit/include_public")
add_avs_test(avs_rbtree ${ALL_SOURCES})
