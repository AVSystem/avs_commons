# Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

#.rst:
# FindTinyDTLS
# -----------
#
# Find the tinyDTLS encryption library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``tinydtls``
#   The tinyDTLS ``tinydtls`` library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``TINYDTLS_FOUND``
#   System has the tinyDTLS library.
# ``TINYDTLS_INCLUDE_DIR``
#   The tinyDTLS include directory.
# ``TINYDTLS_LIBRARIES``
#   All tinyDTLS libraries.
#
# ``TINYDTLS_VERSION``
#   This is set to ``$major.$minor.$patch``.
# ``TINYDTLS_VERSION_MAJOR``
#   Set to major tinyDTLS version number.
# ``TINYDTLS_VERSION_MINOR``
#   Set to minor tinyDTLS version number.
# ``TINYDTLS_VERSION_PATCH``
#   Set to patch tinyDTLS version number.
#
# Hints
# ^^^^^
#
# Set ``TINYDTLS_ROOT_DIR`` to the root directory of an tinyDTLS installation.

if(TINYDTLS_ROOT_DIR)
    set(_EXTRA_FIND_ARGS "NO_CMAKE_FIND_ROOT_PATH")
endif()

find_path(TINYDTLS_INCLUDE_DIR
          NAMES tinydtls/dtls.h
          PATH_SUFFIXES include
          HINTS ${TINYDTLS_ROOT_DIR}
          ${_EXTRA_FIND_ARGS})

# based on https://github.com/ARMmbed/mbedtls/issues/298
if(TINYDTLS_INCLUDE_DIR AND EXISTS "${TINYDTLS_INCLUDE_DIR}/tinydtls/dtls_config.h")
    file(STRINGS "${TINYDTLS_INCLUDE_DIR}/tinydtls/dtls_config.h" VERSION_STRING_LINE
         REGEX "^#define PACKAGE_VERSION[ \\t\\n\\r]+\"[^\"]*\"$")

    string(REGEX REPLACE "^#define PACKAGE_VERSION[ \\t\\n\\r]+\"([^\"]*)\"$" "\\1"
           TINYDTLS_VERSION "${VERSION_STRING_LINE}")

    string(REGEX REPLACE "([0-9]+).*" "\\1" TINYDTLS_VERSION_MAJOR "${TINYDTLS_VERSION}")
    string(REGEX REPLACE "([0-9]+).([0-9]+).*" "\\2" TINYDTLS_VERSION_MINOR "${TINYDTLS_VERSION}")
    string(REGEX REPLACE "([0-9]+).([0-9]+).([0-9]+)" "\\3" TINYDTLS_VERSION_PATCH "${TINYDTLS_VERSION}")
endif()

find_library(TINYDTLS_LIBRARIES
             NAMES tinydtls
             PATH_SUFFIXES lib
             HINTS ${TINYDTLS_ROOT_DIR}
             ${_EXTRA_FIND_ARGS})

if (TINYDTLS_LIBRARIES)
    set(TINYDTLS_FOUND TRUE)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(tinyDTLS
                                  FOUND_VAR TINYDTLS_FOUND
                                  REQUIRED_VARS
                                        TINYDTLS_INCLUDE_DIR
                                        TINYDTLS_LIBRARIES
                                        TINYDTLS_VERSION
                                  VERSION_VAR TINYDTLS_VERSION)

if(NOT TARGET tinydtls)
    add_library(tinydtls UNKNOWN IMPORTED)
    set_target_properties(tinydtls PROPERTIES
                          INTERFACE_INCLUDE_DIRECTORIES "${TINYDTLS_INCLUDE_DIR}"
                          IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                          IMPORTED_LOCATION "${TINYDTLS_LIBRARIES}")
endif()
