/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#ifndef COMPAT_H
#define COMPAT_H

/*
 * Example implementation of a POSIX_COMPAT_HEADER file required for non-POSIX
 * platforms that use LwIP 1.4.1.
 *
 * Contains all types/macros/symbols not defined in core C that are required
 * to compile avs_commons library.
 */

#include "lwipopts.h"

/* Provides htons/ntohs/htonl/ntohl */
#include "lwip/inet.h"

/* Provides e.g. LWIP_VERSION_* macros used in net_impl.c */
#include "lwip/init.h"

/*
 * Provides:
 * - POSIX-compatible socket API, socklen_t,
 * - fcntl, F_GETFL, F_SETFL, O_NONBLOCK,
 * - select, struct fd_set, FD_SET, FD_CLEAR, FD_ISSET
 */
#include "lwip/sockets.h"

/* Provides getaddrinfo/freeaddrinfo/struct addrinfo */
#include "lwip/netdb.h"

#if defined(HAVE_GAI_STRERROR) && defined(HAVE_NETDB_H)
#    include <netdb.h>
#else
const char *gai_strerror(int errcode);
#endif

/* for time_t */
#include <time.h>

#ifndef HAVE_STRUCT_TIMESPEC
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
#endif

#ifndef HAVE_CLOCKID_T
typedef int clockid_t;
#endif

#ifndef HAVE_CLOCK_GETTIME
int clock_gettime(clockid_t clk_id, struct timespec *tp);
#endif

#ifndef CLOCK_REALTIME
#    define CLOCK_REALTIME 0
#endif

#if defined(HAVE_STRCASECMP) && defined(HAVE_STRINGS_H)
#    include <strings.h>
#else
int strcasecmp(const char *s1, const char *s2);
#endif

#if defined(HAVE_STRNCASECMP) && defined(HAVE_STRINGS_H)
#    include <strings.h>
#else
int strncasecmp(const char *s1, const char *s2, size_t n);
#endif

#if defined(HAVE_STRTOK_R)
#    include <string.h>
#else
char *strtok_r(char *str, const char *delim, char **saveptr);
#endif

#if defined(AVS_COMMONS_WITH_IPV4)
#    if defined(HAVE_INET_ADDRSTRLEN) && defined(HAVE_NETINET_IN_H)
#        include <netinet/in.h>
#    elif !defined(INET_ADDRSTRLEN)
#        define INET_ADDRSTRLEN sizeof("255.255.255.255")
#    endif
#endif

#if defined(AVS_COMMONS_WITH_IPV6)
#    if defined(HAVE_INET6_ADDRSTRLEN) && defined(HAVE_NETINET_IN_H)
#        include <netinet/in.h>
#    elif !defined(INET6_ADDRSTRLEN)
#        define INET6_ADDRSTRLEN \
            sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#    endif
#endif

#ifndef HAVE_STRDUP
char *strdup(const char *s);
#endif

/* optional */
#if defined(HAVE_INET_PTON) && defined(HAVE_ARPA_INET_H)
#    include <arpa/inet.h>
#endif

/* optional */
#if defined(HAVE_INET_NTOP) && defined(HAVE_ARPA_INET_H)
#    include <arpa/inet.h>
#endif

#if defined(HAVE_IF_NAMESIZE) && defined(HAVE_NET_IF_H)
#    include <net/if.h>
#else
#    define IF_NAMESIZE 16
#endif

/* optional */
#if defined(HAVE_RECVMSG) && defined(HAVE_SYS_SOCKET_H)
#    include <sys/socket.h>
#endif

typedef int sockfd_t;

#endif /* COMPAT_H */
