/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define HAVE_GETIFADDRS
#define HAVE_BACKTRACE
#define HAVE_BACKTRACE_SYMBOLS
#define HAVE_POLL

#define WITH_IPV4
#define WITH_IPV6

#if !defined(WITH_IPV4) && !defined(WITH_IPV6)
#error "At least one IP protocol version must be enabled"
#endif

#ifdef WITH_IPV4
# define IPV4_AVAILABLE 1
#else
# define IPV4_AVAILABLE 0
#endif

#ifdef WITH_IPV6
# define IPV6_AVAILABLE 1
#else
# define IPV6_AVAILABLE 0
#endif

#ifdef WITH_IPV6
# define AVS_ADDRSTRLEN INET6_ADDRSTRLEN
#elif defined(WITH_IPV4)
# define AVS_ADDRSTRLEN INET_ADDRSTRLEN
#endif

#define WITH_SSL
#define WITH_DTLS
#define WITH_EC_KEY
#define WITH_PSK

#define WITH_AVS_LOG
#define WITH_SOCKET_LOG

/* #undef WITH_OPENSSL_CUSTOM_CIPHERS */

#define WITH_VALGRIND
#ifdef WITH_VALGRIND
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
#include <valgrind/helgrind.h>
#include <stdint.h>
extern void *sbrk (intptr_t __delta);
#else
#define RUNNING_ON_VALGRIND 0
#define VALGRIND_HG_DISABLE_CHECKING(addr, len) ((void) 0)
#define VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(addr, len) ((void) 0)
#endif

#ifndef AVS_UNIT_TESTING
#define HAVE_VISIBILITY
#endif

#if defined(HAVE_VISIBILITY)
/* set default visibility for external symbols */
#pragma GCC visibility push(default)
#define VISIBILITY_SOURCE_BEGIN         _Pragma("GCC visibility push(hidden)")
#define VISIBILITY_PRIVATE_HEADER_BEGIN _Pragma("GCC visibility push(hidden)")
#define VISIBILITY_PRIVATE_HEADER_END   _Pragma("GCC visibility pop")
#else
#define VISIBILITY_SOURCE_BEGIN
#define VISIBILITY_PRIVATE_HEADER_BEGIN
#define VISIBILITY_PRIVATE_HEADER_END
#endif

#define WITH_INTERNAL_LOGS

#define WITH_INTERNAL_TRACE

/* #undef WITH_MBEDTLS_LOGS */

#define WITH_AVS_COAP_MESSAGE_CACHE

#define WITH_AVS_COAP_NET_STATS

#define WITH_AVS_HTTP_ZLIB
