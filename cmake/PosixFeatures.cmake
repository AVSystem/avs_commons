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

set(STORED_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS}")
if(NOT APPLE)
    set(CMAKE_REQUIRED_DEFINITIONS
        ${CMAKE_REQUIRED_DEFINITIONS} -D_POSIX_C_SOURCE=200809L)
endif()

include(CheckIncludeFiles)
check_include_files("net/if.h" AVS_COMMONS_HAVE_NET_IF_H)

include(CheckFunctionExists)
check_function_exists(getifaddrs AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETIFADDRS)

include(CheckSymbolExists)
check_symbol_exists("gai_strerror" "netdb.h" AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GAI_STRERROR)
check_symbol_exists("getnameinfo" "netdb.h" AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETNAMEINFO)
check_symbol_exists("inet_ntop" "arpa/inet.h" AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_INET_NTOP)
check_symbol_exists("poll" "poll.h" AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_POLL)
check_symbol_exists("recvmsg" "sys/socket.h" AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_RECVMSG)

# When _POSIX_C_SOURCE is defined, but none of _BSD_SOURCE, _SVID_SOURCE and
# _GNU_SOURCE, some toolchains (e.g. default GCC on Ubuntu 16.04 or CentOS 7)
# define IN6_IS_ADDR_V4MAPPED using s6_addr32 symbol that is undefined.
# That makes simple check_symbol_exists() succeed despite it being unusable.
if(NOT DEFINED AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_IN6_IS_ADDR_V4MAPPED)
    message(STATUS "Checking if IN6_IS_ADDR_V4MAPPED is usable")
    file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/in6_is_addr_v4mapped.c
         "#include <netinet/in.h>\nint main() { struct in6_addr addr = {0}; IN6_IS_ADDR_V4MAPPED(&addr); return 0; }\n")
    try_compile(AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_IN6_IS_ADDR_V4MAPPED
                ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp
                ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/in6_is_addr_v4mapped.c
                COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS})
endif()
if(AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_IN6_IS_ADDR_V4MAPPED)
    message(STATUS "Checking if IN6_IS_ADDR_V4MAPPED is usable - yes")
else()
    message(STATUS "Checking if IN6_IS_ADDR_V4MAPPED is usable - no")
endif()

set(CMAKE_REQUIRED_DEFINITIONS "${STORED_REQUIRED_DEFINITIONS}")
