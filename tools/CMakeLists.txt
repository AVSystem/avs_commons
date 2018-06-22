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

if(NOT TARGET OpenSSL::SSL OR NOT TARGET OpenSSL::Crypto)
    message(FATAL_ERROR "OpenSSL libraries are required for unit tests")
endif()

add_executable(dtls_echo_server EXCLUDE_FROM_ALL dtls_echo_server.c)
set_target_properties(dtls_echo_server PROPERTIES
                      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRRENT_BINARY_DIR}"
                      COMPILE_FLAGS "-w")
target_link_libraries(dtls_echo_server OpenSSL::SSL OpenSSL::Crypto)
