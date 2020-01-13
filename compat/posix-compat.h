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
 * platforms.
 *
 * Contains all types/macros/symbols not defined in core C that are required
 * to compile avs_commons library.
 */

#if defined(HAVE_SSIZE_T) && defined(HAVE_SYS_TYPES_H)
#    include <sys/types.h>
#else
typedef ptrdiff_t ssize_t;
#endif

/* for time_t */
#include <time.h>

#ifndef HAVE_STRUCT_TIMESPEC
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
#endif

#if defined(HAVE_STRUCT_TIMEVAL) && defined(HAVE_SYS_TIME_H)
#    include <sys/time.h>
#else
struct timeval {
    time_t tv_sec;
    long tv_usec;
};
#endif

#ifndef HAVE_CLOCKID_T
typedef int clockid_t;
#endif

#ifndef HAVE_CLOCK_GETTIME
int clock_gettime(clockid_t clk_id, struct timespec *tp);
#endif

#ifndef CLOCK_REALTIME
#    define CLOCK_REALTIME 0 /* TODO */
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

#if defined(HAVE_CLOSE) && defined(HAVE_UNISTD_H)
#    include <unistd.h>
#else
int close(int fd);
#endif

#if defined(AVS_COMMONS_WITH_IPV4)
#    if defined(HAVE_INET_ADDRSTRLEN) && defined(HAVE_NETINET_IN_H)
#        include <netinet/in.h>
#    else
#        define INET_ADDRSTRLEN sizeof("255.255.255.255")
#    endif
#endif

#if defined(AVS_COMMONS_WITH_IPV6)
#    if defined(HAVE_INET6_ADDRSTRLEN) && defined(HAVE_NETINET_IN_H)
#        include <netinet/in.h>
#    else
#        define INET6_ADDRSTRLEN \
            sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#    endif
#endif

#if defined(HAVE_SOCKLEN_T) && defined(HAVE_SYS_SOCKET_H)
#    include <sys/socket.h>
#else
typedef size_t socklen_t;
#endif

#if defined(HAVE_STRUCT_ADDRINFO) && defined(HAVE_NETDB_H)
#    include <netdb.h>
#else
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};
#endif

#if defined(HAVE_GETADDRINFO) && defined(HAVE_NETDB_H)
#    include <netdb.h>
#else
int getaddrinfo(const char *node,
                const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res);
#endif

#if defined(HAVE_FREEADDRINFO) && defined(HAVE_NETDB_H)
#    include <netdb.h>
#else
int freeaddrinfo(struct addrinfo *res);
#endif

#if defined(HAVE_GAI_STRERROR) && defined(HAVE_NETDB_H)
#    include <netdb.h>
#else
const char *gai_strerror(int errcode);
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

#if defined(HAVE_FCNTL) && defined(HAVE_FCNTL_H)
#    include <fcntl.h>
#else
int fcntl(int fd, int cmd, ... /* arg */);
#endif

#if defined(HAVE_F_GETFL) && defined(HAVE_FCNTL_H)
#    include <fcntl.h>
#else
#    define F_GETFL 3 /* TODO */
#endif

#if defined(HAVE_F_SETFL) && defined(HAVE_FCNTL_H)
#    include <fcntl.h>
#else
#    define F_SETFL 4 /* TODO */
#endif

#if defined(HAVE_O_NONBLOCK) && defined(HAVE_FCNTL_H)
#    include <fcntl.h>
#else
#    define O_NONBLOCK 00004000 /* TODO */
#endif

/* Either poll() or select() is required */
#if defined(HAVE_POLL)
#    if defined(HAVE_POLL_H)
#        include <poll.h>
#    else
#        define POLLIN 0x001  /* TODO */
#        define POLLOUT 0x004 /* TODO */
#        define POLLERR 0x008 /* TODO */
#        define POLLHUP 0x010 /* TODO */

typedef unsigned long int nfds_t;

struct pollfd {
    int fd;
    short int events;
    short int revents;
};

int poll(struct pollfd *fds, nfds_t nfds, int timeout);
#    endif
#else /* HAVE_POLL */
#    if defined(HAVE_SELECT) && defined(HAVE_SYS_SELECT_H)
#        include <sys/select.h>
#    else
/* TODO: definition of this type should be compatible with select()
 * implementation */
typedef struct {
    unsigned long fds_bits[1024 / (CHAR_BIT * sizeof(long))];
} fd_set;

#        define FD_ISSET(fd, set) 0      /* TODO */
#        define FD_SET(fd, set) (void) 0 /* TODO */
#        define FD_ZERO(set) (void) 0    /* TODO */

int select(int nfds,
           fd_set *readfds,
           fd_set *writefds,
           fd_set *exceptfds,
           struct timeval *timeout);
#    endif
#endif /* TODO */

/* TODO: definitions for htons/ntohs/htonl/ntohl rely on __BYTE_ORDER__ macro
 * which is a GNU extension */

#if defined(HAVE_HTONS) && defined(HAVE_ARPA_INET_H)
#    include <arpa/inet.h>
#else
#    if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ \
            || __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
#        define htons(x) ((uint16_t) (x))
#    elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#        define htons(x) \
            ((uint16_t) ((((x) &0x00FF) << 8) | ((x) &0xFF00) >> 8))
#    else
#        error "Unsupported endianness"
#    endif
#endif

#if defined(HAVE_NTOHS) && defined(HAVE_ARPA_INET_H)
#    include <arpa/inet.h>
#else
#    define ntohs htons
#endif

#if defined(HAVE_HTONL) && defined(HAVE_ARPA_INET_H)
#    include <arpa/inet.h>
#else
#    if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#        define htonl(x) ((uint32_t) (x))
#    elif __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
#        define htonl(x)                         \
            ((((uint32_t) (x) &0x00FF00FF) << 8) \
             | (((uint32_t) (x) &0xFF00FF00) >> 8))
#    elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#        define htonl(x)                           \
            ((((uint32_t) (x) &0x000000FF) << 24)  \
             | (((uint32_t) (x) &0x0000FF00) << 8) \
             | (((uint32_t) (x) &0x00FF0000) >> 8) \
             | (((uint32_t) (x) &0xFF000000) >> 24))
#    else
#        error "Unsupported endianness"
#    endif
#endif

#if defined(HAVE_NTOHL) && defined(HAVE_ARPA_INET_H)
#    include <arpa/inet.h>
#else
#    define ntohl htonl
#endif

/* optional */
#if defined(HAVE_RECVMSG) && defined(HAVE_SYS_SOCKET_H)
#    include <sys/socket.h>
#endif

// Some socket implementations (e.g. Winsock) are mostly POSIX-like, but don't
// use int as socket type. That's why we define this additional special type.
typedef int sockfd_t;

#endif /* COMPAT_H */
