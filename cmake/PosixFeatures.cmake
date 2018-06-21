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

set(STORED_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS}")
if(NOT APPLE)
    set(CMAKE_REQUIRED_DEFINITIONS
        ${CMAKE_REQUIRED_DEFINITIONS} -D_POSIX_C_SOURCE=200809L)
endif()

include(CheckIncludeFiles)
check_include_files("sys/select.h" HAVE_SYS_SELECT_H)
check_include_files("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_files("sys/time.h" HAVE_SYS_TIME_H)
check_include_files("sys/types.h" HAVE_SYS_TYPES_H)
check_include_files("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_files("fcntl.h" HAVE_FCNTL_H)
check_include_files("net/if.h" HAVE_NET_IF_H)
check_include_files("netdb.h" HAVE_NETDB_H)
check_include_files("netinet/in.h" HAVE_NETINET_IN_H)
check_include_files("poll.h" HAVE_POLL_H)
check_include_files("strings.h" HAVE_STRINGS_H)
check_include_files("unistd.h" HAVE_UNISTD_H)

include(CheckTypeSize)
set(CMAKE_EXTRA_INCLUDE_FILES "time.h")
check_type_size("struct timespec" STRUCT_TIMESPEC)
check_type_size("clockid_t" CLOCKID_T)
set(CMAKE_EXTRA_INCLUDE_FILES "sys/time.h")
check_type_size("struct timeval" STRUCT_TIMEVAL)
set(CMAKE_EXTRA_INCLUDE_FILES "sys/types.h")
check_type_size("ssize_t" SSIZE_T)
set(CMAKE_EXTRA_INCLUDE_FILES "sys/socket.h")
check_type_size("socklen_t" SOCKLEN_T)
set(CMAKE_EXTRA_INCLUDE_FILES "netdb.h")
check_type_size("struct addrinfo" STRUCT_ADDRINFO)
set(CMAKE_EXTRA_INCLUDE_FILES)

include(CheckSymbolExists)
check_symbol_exists("F_GETFL" "fcntl.h" HAVE_F_GETFL)
check_symbol_exists("F_SETFL" "fcntl.h" HAVE_F_SETFL)
check_symbol_exists("IF_NAMESIZE" "net/if.h" HAVE_IF_NAMESIZE)
check_symbol_exists("INET6_ADDRSTRLEN" "netinet/in.h" HAVE_INET6_ADDRSTRLEN)
check_symbol_exists("INET_ADDRSTRLEN" "netinet/in.h" HAVE_INET_ADDRSTRLEN)
check_symbol_exists("O_NONBLOCK" "fcntl.h" HAVE_O_NONBLOCK)
check_symbol_exists("CLOCK_REALTIME" "time.h" HAVE_CLOCK_REALTIME)

check_symbol_exists("clock_gettime" "time.h" HAVE_CLOCK_GETTIME)
check_symbol_exists("fcntl" "fcntl.h" HAVE_FCNTL)
check_symbol_exists("freeaddrinfo" "netdb.h" HAVE_FREEADDRINFO)
check_symbol_exists("gai_strerror" "netdb.h" HAVE_GAI_STRERROR)
check_symbol_exists("getaddrinfo" "netdb.h" HAVE_GETADDRINFO)
check_symbol_exists("getnameinfo" "netdb.h" HAVE_GETNAMEINFO)
check_symbol_exists("inet_ntop" "arpa/inet.h" HAVE_INET_NTOP)
check_symbol_exists("inet_pton" "arpa/inet.h" HAVE_INET_PTON)
check_symbol_exists("poll" "poll.h" HAVE_POLL)
check_symbol_exists("select" "sys/select.h" HAVE_SELECT)
check_symbol_exists("strcasecmp" "strings.h" HAVE_STRCASECMP)
check_symbol_exists("strncasecmp" "strings.h" HAVE_STRNCASECMP)
check_symbol_exists("strtok_r" "string.h" HAVE_STRTOK_R)
check_symbol_exists("htons" "arpa/inet.h" HAVE_HTONS)
check_symbol_exists("ntohs" "arpa/inet.h" HAVE_NTOHS)
check_symbol_exists("htonl" "arpa/inet.h" HAVE_HTONL)
check_symbol_exists("htonl" "arpa/inet.h" HAVE_HTONL)
check_symbol_exists("recvmsg" "sys/socket.h" HAVE_RECVMSG)
check_symbol_exists("close" "unistd.h" HAVE_CLOSE)

# When _POSIX_C_SOURCE is defined, but none of _BSD_SOURCE, _SVID_SOURCE and
# _GNU_SOURCE, some toolchains (e.g. default GCC on Ubuntu 16.04 or CentOS 7)
# define IN6_IS_ADDR_V4MAPPED using s6_addr32 symbol that is undefined.
# That makes simple check_symbol_exists() succeed despite it being unusable.
message(STATUS "Checking if IN6_IS_ADDR_V4MAPPED is usable")
file(WRITE ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/in6_is_addr_v4mapped.c
     "#include <netinet/in.h>\nint main() { struct in6_addr addr; IN6_IS_ADDR_V4MAPPED(&addr); return 0; }\n")
try_compile(HAVE_IN6_IS_ADDR_V4MAPPED
            ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp
            ${CMAKE_BINARY_DIR}/CMakeFiles/CMakeTmp/in6_is_addr_v4mapped.c
            COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS})
if(HAVE_IN6_IS_ADDR_V4MAPPED)
    message(STATUS "Checking if IN6_IS_ADDR_V4MAPPED is usable - yes")
else()
    message(STATUS "Checking if IN6_IS_ADDR_V4MAPPED is usable - no")
endif()

set(CMAKE_REQUIRED_DEFINITIONS "${STORED_REQUIRED_DEFINITIONS}")
