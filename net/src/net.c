/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */


#include <config.h>

#ifdef WITH_LWIP
#   undef LWIP_COMPAT_SOCKETS
#   define LWIP_COMPAT_SOCKETS 1
#   include "lwipopts.h"
#   include "lwip/netdb.h"
#   include "lwip/socket.h"
#else
#   ifndef _POSIX_SOURCE
#   define _POSIX_SOURCE
#   endif
#   include <fcntl.h>
#   include <netdb.h>
#   include <unistd.h>
#   ifdef HAVE_POLL
#       include <poll.h>
#   else
#       include <sys/select.h>
#   endif
#   include <sys/socket.h>
#   include <sys/types.h>
#   include <arpa/inet.h>
#endif

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

#define NET_CONNECT_TIMEOUT      1000 * 10

int _avs_net_create_tcp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return -1;
}

int _avs_net_create_udp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return -1;
}

static struct addrinfo *detach_preferred(struct addrinfo **list_ptr,
                                         const void *preferred_addr,
                                         socklen_t preferred_addr_len) {
    for (; *list_ptr; list_ptr = &(*list_ptr)->ai_next) {
        if ((*list_ptr)->ai_addrlen == preferred_addr_len
                && memcmp((*list_ptr)->ai_addr, preferred_addr,
                          preferred_addr_len) == 0) {
            struct addrinfo *retval = *list_ptr;
            *list_ptr = retval->ai_next;
            retval->ai_next = NULL;
            return retval;
        }
    }
    return NULL;
}

static void half_addrinfo(struct addrinfo *list,
                          struct addrinfo **part2_ptr) {
    size_t length = 0;
    struct addrinfo *ptr = list;
    assert(list);
    assert(list->ai_next);
    while (ptr) {
        ++length;
        ptr = ptr->ai_next;
    }
    length /= 2;
    while (--length) {
        list = list->ai_next;
    }
    *part2_ptr = list->ai_next;
    list->ai_next = NULL;
}

static void randomize_addrinfo_list(struct addrinfo **list_ptr,
                                    unsigned *random_seed) {
    struct addrinfo *part1 = NULL;
    struct addrinfo *part2 = NULL;
    struct addrinfo **list_end_ptr = NULL;
    if (!list_ptr || !*list_ptr || !(*list_ptr)->ai_next) {
        /* zero or one element */
        return;
    }
    part1 = *list_ptr;
    half_addrinfo(part1, &part2);
    *list_ptr = NULL;
    list_end_ptr = list_ptr;
    randomize_addrinfo_list(&part1, random_seed);
    randomize_addrinfo_list(&part2, random_seed);
    while (part1 && part2) {
#warning "FIXME"
        if (rand_r(random_seed) % 2) {
            *list_end_ptr = part1;
            part1 = part1->ai_next;
        } else {
            *list_end_ptr = part2;
            part2 = part2->ai_next;
        }
        (*list_end_ptr)->ai_next = NULL;
        list_end_ptr = &(*list_end_ptr)->ai_next;
    }
    if (part1) {
        *list_end_ptr = part1;
    } else {
        *list_end_ptr = part2;
    }
}

static struct addrinfo *get_addrinfo_net(int socket_type,
                                         const char *localaddr,
                                         const char *port,
                                         int addr_family,
                                         int flags,
                                         const avs_net_socket_raw_resolved_endpoint_t *preferred_endpoint) {
    int error;
    struct addrinfo hint, *info = NULL;

    memset((void *) &hint, 0, sizeof (hint));
    hint.ai_family = addr_family;
    hint.ai_flags = AI_NUMERICSERV | flags;
    hint.ai_socktype = socket_type;

    if ((error = getaddrinfo(localaddr, port, &hint, &info))) {
        return NULL;
    } else {
        unsigned seed = (unsigned) time(NULL);
        struct addrinfo *preferred = NULL;
        if (preferred_endpoint) {
            preferred = detach_preferred(&info, preferred_endpoint->data,
                                         preferred_endpoint->size);
        }
        randomize_addrinfo_list(&info, &seed);
        if (preferred) {
            preferred->ai_next = info;
            return preferred;
        }
        return info;
    }
}

static short wait_until_ready(int sockfd, int timeout, char in, char out) {
#ifdef HAVE_POLL
    struct pollfd p;
    short events = (short) ((in ? POLLIN : 0) | (out ? POLLOUT : 0));
    p.fd = sockfd;
    p.events = events;
    p.revents = 0;
    if (poll(&p, 1, timeout) != 1
            || (p.revents & (POLLHUP | POLLERR))) {
        return 0;
    }
    return p.revents & events;
#else
    fd_set infds;
    fd_set outfds;
    fd_set errfds;
    struct timeval timeval_timeout;
    timeval_timeout.tv_sec = timeout / 1000;
    timeval_timeout.tv_usec = 1000 * (timeout % 1000);
    FD_ZERO(&infds);
    FD_ZERO(&outfds);
    FD_ZERO(&errfds);
    if (in) {
        FD_SET(sockfd, &infds);
    }
    if (out) {
        FD_SET(sockfd, &outfds);
    }
    FD_SET(sockfd, &errfds);
    if (select(sockfd + 1, &infds, &outfds, &errfds, &timeval_timeout) <= 0
            || FD_ISSET(sockfd, &errfds)) {
        return 0;
    }
    return (in && FD_ISSET(sockfd, &infds)) || (out && FD_ISSET(sockfd, &outfds));
#endif
}

static int connect_with_timeout(int sockfd,
                                struct sockaddr *ai_addr,
                                socklen_t ai_addrlen) {
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        return -1;
    }
    connect(sockfd, ai_addr, ai_addrlen);
    if (!wait_until_ready(sockfd, NET_CONNECT_TIMEOUT, 1, 1)) {
        errno = ETIMEDOUT;
        return -1;
    } else {
        int error_code = 0;
        socklen_t length = sizeof(error_code);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error_code, &length)) {
            return -1;
        }
        if (error_code) {
            errno = error_code;
            return -1;
        }
    }
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) & ~O_NONBLOCK) == -1) {
        return -1;
    }
    return 0;
}

static int get_af(avs_net_af_t addr_family) {
    switch (addr_family) {
    case AVS_NET_AF_INET4:
        return AF_INET;
    case AVS_NET_AF_INET6:
        return AF_INET6;
    case AVS_NET_AF_UNSPEC:
    default:
        return AF_UNSPEC;
    }
}

static int get_string_ip(const struct sockaddr *addr,
                         char *buffer, size_t buffer_size) {
    const void *addr_data;
    socklen_t addrlen;

    switch(addr->sa_family) {
        case AF_INET:
            addr_data = &((const struct sockaddr_in *)addr)->sin_addr;
            addrlen = INET_ADDRSTRLEN;
            break;

        case AF_INET6:
            addr_data = &((const struct sockaddr_in6 *)addr)->sin6_addr;
            addrlen = INET6_ADDRSTRLEN;
            break;

        default:
            return -1;
    }

    if (buffer_size < addrlen) {
        return -1;
    } else {
#warning "FIXME"
        return inet_ntop(addr->sa_family, addr_data, buffer, addrlen)
                == NULL ? -1 : 0;
    }
}

int avs_net_local_address_for_target_host(const char *target_host,
                                          avs_net_af_t addr_family,
                                          char *address_buffer,
                                          size_t buffer_size) {
    static const char *DUMMY_PORT = "1337";
    struct addrinfo *info = NULL, *address = NULL;
    int result = -1;

    info = get_addrinfo_net(SOCK_DGRAM, target_host, DUMMY_PORT,
                            get_af(addr_family), 0, NULL);
    for (address = info;
            result != 0 && address != NULL;
            address = address->ai_next) {

        int test_socket = socket(address->ai_family, address->ai_socktype,
                                 address->ai_protocol);

        if (test_socket >= 0
                && !connect_with_timeout(test_socket, address->ai_addr,
                                         address->ai_addrlen)) {
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);

            if (!getsockname(test_socket, (struct sockaddr *)&addr, &addrlen)) {
                result = get_string_ip((struct sockaddr *)&addr,
                                       address_buffer, buffer_size);
            }
        }
        close(test_socket);
    }

    freeaddrinfo(info);
    return result;
}
