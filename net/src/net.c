/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <config.h>

#ifdef WITH_LWIP
#   undef LWIP_COMPAT_SOCKETS
#   define LWIP_COMPAT_SOCKETS 1
#   include "lwipopts.h"
#   include "lwip/netdb.h"
#   include "lwip/socket.h"
#else
#   include <fcntl.h>
#   include <netdb.h>
#   include <unistd.h>
#   ifdef HAVE_POLL
#       include <poll.h>
#   else
#       include <sys/select.h>
#   endif
#   include <sys/ioctl.h>
#   include <sys/socket.h>
#   include <sys/types.h>
#   include <arpa/inet.h>
#endif

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

#include "addrinfo.h"
#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#define NET_SEND_TIMEOUT         1000 * 30 /* 30 sec timeout */
#define NET_CONNECT_TIMEOUT      1000 * 10
#define NET_ACCEPT_TIMEOUT       1000 * 5
#define NET_LISTEN_BACKLOG       1024

#ifdef HAVE_INET_NTOP
#define _avs_inet_ntop inet_ntop
#else
const char *_avs_inet_ntop(int af, const void *src, char *dst, socklen_t size);
#endif

#ifdef HAVE_INET_PTON
#define _avs_inet_pton inet_pton
#else
int _avs_inet_pton(int af, const char *src, void *dst);
#endif

#ifdef HAVE_RAND_R
#define _avs_rand_r rand_r
#else
#warning "rand_r not available, please provide int _avs_rand_r(unsigned int *)"
int _avs_rand_r(unsigned int *seedp);
#endif

typedef union {
    struct sockaddr         addr;
    struct sockaddr_in      addr_in;
    struct sockaddr_in6     addr_in6;
    struct sockaddr_storage addr_storage;
} sockaddr_union_t;

static int connect_net(avs_net_abstract_socket_t *net_socket,
                       const char* host,
                       const char *port);
static int send_net(avs_net_abstract_socket_t *net_socket,
                    const void* buffer,
                    size_t buffer_length);
static int send_to_net(avs_net_abstract_socket_t *socket,
                       size_t *out,
                       const void *buffer,
                       size_t buffer_length,
                       const char *host,
                       const char *port);
static int receive_net(avs_net_abstract_socket_t *net_socket_,
                       size_t *out,
                       void *buffer,
                       size_t buffer_length);
static int receive_from_net(avs_net_abstract_socket_t *net_socket,
                            size_t *out,
                            void *message_buffer, size_t buffer_size,
                            char *host, size_t host_size,
                            char *port, size_t port_size);
static int bind_net(avs_net_abstract_socket_t *net_socket,
                    const char *localaddr,
                    const char *port);
static int accept_net(avs_net_abstract_socket_t *server_net_socket,
                      avs_net_abstract_socket_t *new_net_socket);
static int close_net(avs_net_abstract_socket_t *net_socket);
static int shutdown_net(avs_net_abstract_socket_t* net_socket);
static int cleanup_net(avs_net_abstract_socket_t **net_socket);
static int system_socket_net(avs_net_abstract_socket_t *net_socket,
                             const void **out);
static int interface_name_net(avs_net_abstract_socket_t *socket,
                              avs_net_socket_interface_name_t *if_name);
static int remote_host_net(avs_net_abstract_socket_t *socket,
                           char *out_buffer, size_t out_buffer_size);
static int remote_port_net(avs_net_abstract_socket_t *socket,
                           char *out_buffer, size_t out_buffer_size);
static int local_port_net(avs_net_abstract_socket_t *socket,
                           char *out_buffer, size_t out_buffer_size);
static int get_opt_net(avs_net_abstract_socket_t *net_socket,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value);
static int set_opt_net(avs_net_abstract_socket_t *net_socket,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t option_value);

static int unimplemented() {
    return -1;
}

static const avs_net_socket_v_table_t net_vtable = {
    connect_net,
    (avs_net_socket_decorate_t) unimplemented,
    send_net,
    send_to_net,
    receive_net,
    receive_from_net,
    bind_net,
    accept_net,
    close_net,
    shutdown_net,
    cleanup_net,
    system_socket_net,
    interface_name_net,
    remote_host_net,
    remote_port_net,
    local_port_net,
    get_opt_net,
    set_opt_net
};

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    int                                    socket;
    int                                    type;
    avs_net_socket_state_t                 state;
    char                                   host[NET_MAX_HOSTNAME_SIZE];
    char                                   port[NET_PORT_SIZE];
    avs_net_socket_configuration_t         configuration;

    int recv_timeout;
} avs_net_socket_t;

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
        if (_avs_rand_r(random_seed) % 2) {
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
#ifdef HAVE_GAI_STRERROR
        LOG(ERROR, "%s", gai_strerror(error));
#else
        LOG(ERROR, "getaddrinfo() error %d", error);
#endif
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

static int remote_host_net(avs_net_abstract_socket_t *socket_,
                           char *out_buffer, size_t out_buffer_size) {
    avs_net_socket_t *socket = (avs_net_socket_t *) socket_;
    int retval;
    if (socket->socket < 0) {
        return -1;
    }
    retval = snprintf(out_buffer, out_buffer_size, "%s", socket->host);
    return (retval < 0 || (size_t) retval >= out_buffer_size) ? -1 : 0;
}

static int remote_port_net(avs_net_abstract_socket_t *socket_,
                           char *out_buffer, size_t out_buffer_size) {
    avs_net_socket_t *socket = (avs_net_socket_t *) socket_;
    int retval;
    if (socket->socket < 0) {
        return -1;
    }
    retval = snprintf(out_buffer, out_buffer_size, "%s", socket->port);
    return (retval < 0 || (size_t) retval >= out_buffer_size) ? -1 : 0;
}

static int system_socket_net(avs_net_abstract_socket_t *net_socket,
                             const void **out) {
    *out = &((const avs_net_socket_t *) net_socket)->socket;
    return *out ? 0 : -1;
}

static int close_net(avs_net_abstract_socket_t *net_socket_) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    if (net_socket->socket >= 0) {
        close(net_socket->socket);
        net_socket->socket = -1;
        net_socket->state = AVS_NET_SOCKET_STATE_CLOSED;
    }
    return 0;
}

static int cleanup_net(avs_net_abstract_socket_t **net_socket) {
    close_net(*net_socket);
    free(*net_socket);
    *net_socket = NULL;
    return 0;
}

static int shutdown_net(avs_net_abstract_socket_t *net_socket_) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    int retval = shutdown(net_socket->socket, SHUT_RDWR);
    net_socket->state = AVS_NET_SOCKET_STATE_SHUTDOWN;
    return retval;
}

static sa_family_t get_socket_family(int fd) {
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    if (!getsockname(fd, &addr.addr, &addrlen)) {
        return addr.addr.sa_family;
    } else {
        return AF_UNSPEC;
    }
}

#if !defined(IP_TRANSPARENT) && defined(__linux__)
#define IP_TRANSPARENT 19
#endif

#if !defined(IPV6_TRANSPARENT) && defined(__linux__)
#define IPV6_TRANSPARENT 75
#endif

static int configure_socket(avs_net_socket_t *net_socket) {
    LOG(TRACE, "configuration '%s' 0x%02x 0x%02x",
        net_socket->configuration.interface_name,
        net_socket->configuration.dscp,
        net_socket->configuration.priority);
    if (net_socket->configuration.interface_name[0]) {
        if (setsockopt(net_socket->socket,
                       SOL_SOCKET,
                       SO_BINDTODEVICE,
                       net_socket->configuration.interface_name,
                       (socklen_t)
                       strlen(net_socket->configuration.interface_name))) {
            LOG(ERROR, "setsockopt error: %s", strerror(errno));
            return -1;
        }
    }
    if (net_socket->configuration.priority) {
        /* SO_PRIORITY accepts int as argument */
        int priority = net_socket->configuration.priority;
        socklen_t length = sizeof(priority);
        if (setsockopt(net_socket->socket,
                       SOL_SOCKET, SO_PRIORITY, &priority, length)) {
            LOG(ERROR, "setsockopt error: %s", strerror(errno));
            return -1;
        }
    }
    if (net_socket->configuration.dscp) {
        uint8_t tos;
        socklen_t length = sizeof(tos);
        if (getsockopt(net_socket->socket, IPPROTO_IP, IP_TOS, &tos, &length)) {
            LOG(ERROR, "getsockopt error: %s", strerror(errno));
            return -1;
        }
        tos &= 0x03; /* clear first 6 bits */
        tos |= (uint8_t) (net_socket->configuration.dscp << 2);
        if (setsockopt(net_socket->socket, IPPROTO_IP, IP_TOS, &tos, length)) {
            LOG(ERROR, "setsockopt error: %s", strerror(errno));
            return -1;
        }
    }
    if (net_socket->configuration.transparent) {
        int value = 1;
        switch (get_socket_family(net_socket->socket)) {
        case AF_INET:
#ifdef IP_TRANSPARENT
            if (setsockopt(net_socket->socket, SOL_IP, IP_TRANSPARENT,
                           &value, sizeof(value)))
#endif
            {
                return -1;
            }
            break;

        case AF_INET6:
#ifdef IPV6_TRANSPARENT
            if (setsockopt(net_socket->socket, SOL_IPV6, IPV6_TRANSPARENT,
                           &value, sizeof(value)))
#endif
            {
                return -1;
            }
            break;

        default:
            return -1;
        }
    }
    return 0;
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

static int is_stream(avs_net_socket_t *net_socket) {
    return (net_socket->type == SOCK_STREAM
            || net_socket->type == SOCK_SEQPACKET);
}

static void unwrap_4in6(char *host) {
    const char *last_colon = strrchr(host, ':');
    if (last_colon) {
    /* this is an IPv6 address */
        if (strchr(host, '.')) {
            /* but actually a wrapped IPv4, retain only the v4 part */
            memmove(host, last_colon + 1, strlen(last_colon));
        }
    }
}

static int host_port_to_string(const struct sockaddr *sa, socklen_t salen,
                               char *host, socklen_t hostlen,
                               char *serv, socklen_t servlen) {
    int result = -1;
#ifdef HAVE_GETNAMEINFO
    result = getnameinfo(sa, salen, host, hostlen, serv, servlen,
                         NI_NUMERICHOST | NI_NUMERICSERV);
#else
    const void *addr_ptr = NULL;
    const uint16_t *port_ptr = NULL;
    if (sa->sa_family == AF_INET) {
        if (salen >= sizeof(struct sockaddr_in)) {
            addr_ptr = &((const struct sockaddr_in *) sa)->sin_addr;
            port_ptr = &((const struct sockaddr_in *) sa)->sin_port;
            result = 0;
        }
    } else if (sa->sa_family == AF_INET6) {
        if (salen >= sizeof(struct sockaddr_in6)) {
            addr_ptr = &((const struct sockaddr_in6 *) sa)->sin6_addr;
            port_ptr = &((const struct sockaddr_in6 *) sa)->sin6_port;
            result = 0;
        }
    }
    if (!result) {
        int retval;
        result = (!_avs_inet_ntop(sa->sa_family, addr_ptr, host, hostlen)
                || (retval = snprintf(serv, servlen, "%" PRIu16, *port_ptr)) < 0
                || (size_t) retval >= servlen) ? -1 : 0;
    }
#endif
    if (result) {
        LOG(ERROR, "Could not stringify socket address");
    } else {
        host[hostlen - 1] = '\0';
        serv[servlen - 1] = '\0';
        unwrap_4in6(host);
    }
    return result;
}

static int connect_net(avs_net_abstract_socket_t *net_socket_,
                       const char *host,
                       const char *port) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    struct addrinfo *info = NULL, *address = NULL;

    if (net_socket->socket >= 0) {
        LOG(ERROR, "socket is already connected or bound");
        return -1;
    }

    LOG(TRACE, "connecting to [%s]:%s", host, port);

    info = get_addrinfo_net(net_socket->type, host, port, AF_UNSPEC, 0,
                            net_socket->configuration.preferred_endpoint);
    for (address = info; address != NULL; address = address->ai_next) {
        if ((net_socket->socket = socket(address->ai_family,
                                         address->ai_socktype,
                                         address->ai_protocol)) < 0) {
            LOG(ERROR, "cannot create socket: %s", strerror(errno));
            continue;
        }
        if (configure_socket(net_socket)) {
            LOG(WARNING, "socket configuration problem");
            close(net_socket->socket);
            continue;
        }
        LOG(TRACE, "connect to [%s]:%s", host, port);
        if (connect_with_timeout(net_socket->socket,
                                 address->ai_addr,
                                 address->ai_addrlen) < 0
                || (is_stream(net_socket)
                && send_net(net_socket_, NULL, 0) < 0)
                || host_port_to_string(address->ai_addr, address->ai_addrlen,
                                       net_socket->host,
                                       sizeof(net_socket->host),
                                       net_socket->port,
                                       sizeof(net_socket->port))) {
            LOG(ERROR, "cannot establish connection to [%s]:%s: %s",
                host, port, strerror(errno));
            close(net_socket->socket);
            continue;
        } else {
            /* SUCCESS */
            net_socket->state = AVS_NET_SOCKET_STATE_CONSUMING;
            /* store address affinity */
            if (net_socket->configuration.preferred_endpoint) {
                if (address->ai_addrlen > UINT8_MAX) {
                    net_socket->configuration.preferred_endpoint->size = 0;
                } else {
                    net_socket->configuration.preferred_endpoint->size
                            = (uint8_t) address->ai_addrlen;
                    memcpy(net_socket->configuration.preferred_endpoint->data,
                           address->ai_addr, address->ai_addrlen);
                }
            }
            freeaddrinfo(info);
            return 0;
        }
    }
    freeaddrinfo(info);
    net_socket->socket = -1;
    LOG(ERROR, "connect_net failed");
    return -1;
}

static int send_net(avs_net_abstract_socket_t *net_socket_,
                    const void *buffer,
                    size_t buffer_length) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    size_t bytes_sent = 0;

    /* send at least one datagram, even if zero-length - hence do..while */
    do {
        ssize_t result;
        if (!wait_until_ready(net_socket->socket, NET_SEND_TIMEOUT, 0, 1)) {
            LOG(ERROR, "timeout (send)");
            return -1;
        }
        result = send(net_socket->socket, ((const char *) buffer) + bytes_sent,
                      buffer_length - bytes_sent, MSG_NOSIGNAL);
        if (result < 0) {
            LOG(ERROR, "%d:%s", (int) result, strerror(errno));
            return -1;
        } else if (buffer_length != 0 && result == 0) {
            LOG(ERROR, "send returned 0");
            break;
        } else {
            bytes_sent += (size_t) result;
        }
        /* call send() multiple times only if the socket is stream-oriented */
    } while (is_stream(net_socket) && bytes_sent < buffer_length);

    if (bytes_sent < buffer_length) {
        LOG(ERROR, "sending fail (%lu/%lu)",
            (unsigned long) bytes_sent, (unsigned long) buffer_length);
        return -1;
    } else {
        /* SUCCESS */
        return 0;
    }
}

static int send_to_net(avs_net_abstract_socket_t *net_socket_,
                       size_t *out,
                       const void *buffer,
                       size_t buffer_length,
                       const char *host,
                       const char *port) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    struct addrinfo *info = get_addrinfo_net(net_socket->type,
                                             host, port, AF_UNSPEC, 0, NULL);
    ssize_t result;

    if (!info) {
        return -1;
    }

    result = sendto(net_socket->socket, buffer, buffer_length,
                    0, info->ai_addr, info->ai_addrlen);
    freeaddrinfo(info);
    if (result < 0) {
        *out = 0;
        return (int) result;
    } else {
        *out = (size_t) result;
        return 0;
    }
}

static int receive_net(avs_net_abstract_socket_t *net_socket_,
                       size_t *out,
                       void *buffer,
                       size_t buffer_length) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    if (!wait_until_ready(net_socket->socket, net_socket->recv_timeout, 1, 0)) {
        *out = 0;
        return -1;
    } else {
        ssize_t recv_out = recv(net_socket->socket, buffer, buffer_length,
                                MSG_NOSIGNAL);
        if (recv_out < 0) {
            *out = 0;
            return (int) recv_out;
        } else {
            *out = (size_t) recv_out;
            return 0;
        }
    }
}

static int receive_from_net(avs_net_abstract_socket_t *net_socket_,
                            size_t *out,
                            void *message_buffer, size_t buffer_size,
                            char *host, size_t host_size,
                            char *port, size_t port_size) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    sockaddr_union_t sender_addr;
    socklen_t addrlen = sizeof(sender_addr);

    assert(host);
    assert(port);
    host[0] = '\0';
    port[0] = '\0';

    if (!wait_until_ready(net_socket->socket,
                          AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT, 1, 0)) {
        *out = 0;
        return -1;
    } else {
        ssize_t result = recvfrom(net_socket->socket,
                                  message_buffer, buffer_size, 0,
                                  &sender_addr.addr, &addrlen);
        if (result < 0) {
            *out = 0;
            return -1;
        } else {
            *out = (size_t) result;
            if (result > 0) {
                return host_port_to_string(&sender_addr.addr, addrlen,
                                           host, (socklen_t) host_size,
                                           port, (socklen_t) port_size);
            }
            return 0;
        }
    }
}

static int create_listening_socket(avs_net_socket_t *net_socket,
                                   const struct sockaddr *addr,
                                   socklen_t addrlen) {
    int retval = -1;
    int val = 1;
    if ((net_socket->socket = socket(addr->sa_family, net_socket->type, 0))
            < 0) {
        LOG(ERROR, "cannot create system socket: %s", strerror(errno));
        goto create_listening_socket_error;
    }
    if (is_stream(net_socket)
            && setsockopt(net_socket->socket,
                          SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val))) {
        LOG(ERROR, "can't set socket opt");
        goto create_listening_socket_error;
    }
    if (configure_socket(net_socket)) {
        goto create_listening_socket_error;
    }
    if (bind(net_socket->socket, addr, addrlen) < 0) {
        LOG(ERROR, "bind error: %s", strerror(errno));
        retval = -2;
        goto create_listening_socket_error;
    }
    if (is_stream(net_socket)
            && listen(net_socket->socket, NET_LISTEN_BACKLOG) < 0) {
        LOG(ERROR, "listen error: %s", strerror(errno));
        retval = -3;
        goto create_listening_socket_error;
    }
    return 0;
create_listening_socket_error:
    close_net((avs_net_abstract_socket_t *) net_socket);
    return retval;
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

static const char *get_af_name(avs_net_af_t af) {
    switch (af) {
    case AVS_NET_AF_INET4:
        return "AF_INET";
    case AVS_NET_AF_INET6:
        return "AF_INET6";
    case AVS_NET_AF_UNSPEC:
    default:
        return "AF_UNSPEC";
    }
}

static int try_bind(avs_net_socket_t *net_socket, avs_net_af_t family,
                    const char *localaddr, const char *port) {
    struct addrinfo *info = NULL;
    sockaddr_union_t addr_storage;
    const struct sockaddr *addr = NULL;
    int af = get_af(family);
    socklen_t addrlen;
    int retval = -1;
    if (net_socket->configuration.address_family != AVS_NET_AF_UNSPEC
            && net_socket->configuration.address_family != family) {
        return -1;
    }
    if (localaddr || port) {
        info = get_addrinfo_net(net_socket->type, localaddr, port,
                                af, AI_ADDRCONFIG | AI_PASSIVE, NULL);
        if (info) {
            addr = info->ai_addr;
            addrlen = info->ai_addrlen;
        }
    } else {
        memset(&addr_storage, 0, sizeof(addr_storage));
        addr_storage.addr.sa_family = (sa_family_t) af;
        addr = &addr_storage.addr;
        addrlen = sizeof(addr_storage);
    }
    if (!addr) {
        LOG(WARNING, "Cannot get %s address info for %s",
            get_af_name(family), localaddr ? localaddr : "(null)");
        goto bind_net_end;
    }
    net_socket->state = AVS_NET_SOCKET_STATE_LISTENING;
    retval = create_listening_socket(net_socket, addr, addrlen);
bind_net_end:
    if (info) {
        freeaddrinfo(info);
    }
    return retval;
}

static int bind_net(avs_net_abstract_socket_t *net_socket_,
                    const char *localaddr,
                    const char *port) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    int retval = -1;

    if (net_socket->socket >= 0) {
        LOG(ERROR, "socket is already connected or bound");
        return -1;
    }

    retval = try_bind(net_socket, AVS_NET_AF_INET6, localaddr, port);
    if (retval) {
        retval = try_bind(net_socket, AVS_NET_AF_INET4, localaddr, port);
    }
    return retval;
}

static int accept_net(avs_net_abstract_socket_t *server_net_socket_,
                      avs_net_abstract_socket_t *new_net_socket_) {
    avs_net_socket_t *server_net_socket =
            (avs_net_socket_t *) server_net_socket_;
    avs_net_socket_t *new_net_socket =
            (avs_net_socket_t *) new_net_socket_;

    if (new_net_socket->socket >= 0) {
        LOG(ERROR, "socket is already connected or bound");
        return -1;
    }

    if (wait_until_ready(server_net_socket->socket,
                         NET_ACCEPT_TIMEOUT, 1, 0)) {
        sockaddr_union_t remote_address;
        socklen_t remote_address_length = sizeof(remote_address);

        new_net_socket->socket = accept(server_net_socket->socket,
                                        &remote_address.addr,
                                        &remote_address_length);
        if (new_net_socket->socket >= 0) {
            if (host_port_to_string(&remote_address.addr,
                                    remote_address_length, new_net_socket->host,
                                    sizeof(new_net_socket->host),
                                    new_net_socket->port,
                                    sizeof(new_net_socket->port)) < 0) {
                close_net(new_net_socket_);
                return -1;
            }
            new_net_socket->state = AVS_NET_SOCKET_STATE_SERVING;
            return 0;
        }
    }
    return -1;
}

static int check_configuration(const avs_net_socket_configuration_t *configuration) {
    if (strlen(configuration->interface_name) >= IF_NAMESIZE) {
        LOG(ERROR, "interface name too long <%s>",
            configuration->interface_name);
        return -1;

    }
    if (configuration->dscp >= 64) {
        LOG(ERROR, "bad DSCP value <%x>", (unsigned) configuration->dscp);
        return -1;
    }
    if (configuration->priority > 7) {
        LOG(ERROR, "bad priority value <%d>",
            (unsigned) configuration->priority);
        return -1;
    }
    return 0;
}

static void
store_configuration(avs_net_socket_t *socket,
                    const avs_net_socket_configuration_t *configuration) {
    memcpy(&socket->configuration, configuration, sizeof(*configuration));
    LOG(TRACE, "stored socket configuration");
}

static int create_net_socket(avs_net_abstract_socket_t **socket,
                             int socket_type,
                             const void *socket_configuration) {
    static const avs_net_socket_t new_socket
            = { &net_vtable, -1, 0, AVS_NET_SOCKET_STATE_CLOSED, "", "",
                { 0, 0, 0, "", NULL, AVS_NET_AF_UNSPEC },
                AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT };
    avs_net_socket_t *net_socket = NULL;

    net_socket = (avs_net_socket_t *) malloc(sizeof (avs_net_socket_t));
    if (net_socket) {
        const avs_net_socket_configuration_t *configuration =
                (const avs_net_socket_configuration_t *) socket_configuration;

        VALGRIND_HG_DISABLE_CHECKING(&net_socket->socket,
                                     sizeof(net_socket->socket));

        memcpy(net_socket, &new_socket, sizeof (new_socket));
        net_socket->type = socket_type;
        *socket = (avs_net_abstract_socket_t *) net_socket;

        if (configuration) {
            if (check_configuration(configuration)) {
                free(*socket);
                *socket = NULL;
                return -1;
            } else {
                store_configuration((avs_net_socket_t*) *socket, configuration);
            }
        } else {
            LOG(TRACE, "no additional socket configuration");
        }
        return 0;
    } else {
        return -1;
    }
}

int _avs_net_create_tcp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return create_net_socket(socket, SOCK_STREAM, socket_configuration);
}

int _avs_net_create_udp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return create_net_socket(socket, SOCK_DGRAM, socket_configuration);
}

static avs_net_af_t get_avs_af(int af) {
    switch (af) {
    case AF_INET:
        return AVS_NET_AF_INET4;
    case AF_INET6:
        return AVS_NET_AF_INET6;
    default:
        return AVS_NET_AF_UNSPEC;
    }
}

static int get_string_ip(const sockaddr_union_t *addr,
                         char *buffer, size_t buffer_size) {
    const void *addr_data;
    socklen_t addrlen;

    switch(addr->addr.sa_family) {
        case AF_INET:
            addr_data = &addr->addr_in.sin_addr;
            addrlen = INET_ADDRSTRLEN;
            break;

        case AF_INET6:
            addr_data = &addr->addr_in6.sin6_addr;
            addrlen = INET6_ADDRSTRLEN;
            break;

        default:
            return -1;
    }

    if (buffer_size < (size_t) addrlen) {
        return -1;
    } else {
        return _avs_inet_ntop(addr->addr.sa_family, addr_data, buffer, addrlen)
                == NULL ? -1 : 0;
    }
}

static int get_string_port(const sockaddr_union_t *addr,
                           char *buffer, size_t buffer_size) {
    uint16_t port;
    int retval;

    switch(addr->addr.sa_family) {
        case AF_INET:
            port = addr->addr_in.sin_port;
            break;

        case AF_INET6:
            port = addr->addr_in6.sin6_port;
            break;

        default:
            return -1;
    }

    retval = snprintf(buffer, buffer_size, "%u", ntohs(port));
    return (retval < 0 || (size_t) retval >= buffer_size) ? -1 : 0;
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
            sockaddr_union_t addr;
            socklen_t addrlen = sizeof(addr);

            if (!getsockname(test_socket, &addr.addr, &addrlen)) {
                result = get_string_ip(&addr, address_buffer, buffer_size);
            }
        }
        close(test_socket);
    }

    freeaddrinfo(info);
    return result;
}

static int local_port_net(avs_net_abstract_socket_t *socket,
                          char *out_buffer, size_t out_buffer_size) {
    const avs_net_socket_t *net_socket = (const avs_net_socket_t *) socket;
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    if (!getsockname(net_socket->socket, &addr.addr, &addrlen)) {
        return get_string_port(&addr, out_buffer, out_buffer_size);
    } else {
        return -1;
    }
}

static int get_opt_net(avs_net_abstract_socket_t *net_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
        out_option_value->recv_timeout = net_socket->recv_timeout;
        return 0;
    case AVS_NET_SOCKET_OPT_STATE:
        out_option_value->state = net_socket->state;
        return 0;
    case AVS_NET_SOCKET_OPT_ADDR_FAMILY:
        out_option_value->addr_family =
                get_avs_af(get_socket_family(net_socket->socket));
        return 0;
    case AVS_NET_SOCKET_OPT_MTU:
    {
        int mtu, retval;
        socklen_t dummy = sizeof(mtu);
        switch (get_socket_family(net_socket->socket)) {
#ifdef IP_MTU
        case AF_INET:
            retval = getsockopt(net_socket->socket, IPPROTO_IP, IP_MTU,
                                &mtu, &dummy);
            break;
#endif
#ifdef IPV6_MTU
        case AF_INET6:
            retval = getsockopt(net_socket->socket, IPPROTO_IPV6, IPV6_MTU,
                                &mtu, &dummy);
            break;
#endif
        default:
            retval = -1;
        }
        if (retval < 0 || mtu < 0) {
            return -1;
        } else {
            out_option_value->mtu = mtu;
            return 0;
        }
    }
    default:
        LOG(ERROR, "get_opt_net: unknown or unsupported option key");
        return -1;
    }
}

static int set_opt_net(avs_net_abstract_socket_t *net_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t option_value) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
        net_socket->recv_timeout = option_value.recv_timeout;
        return 0;
    default:
        LOG(ERROR, "set_opt_net: unknown or unsupported option key");
        return -1;
    }
}

static int ifaddr_ip_equal(const struct sockaddr *left,
                           const struct sockaddr *right) {
    size_t offset;
    size_t length;
    int family_diff = left->sa_family - right->sa_family;

    if (family_diff) {
        return family_diff;
    }

    switch(left->sa_family) {
        case AF_INET:
            offset = offsetof(struct sockaddr_in, sin_addr);
            length = 4;
            break;

        case AF_INET6:
            offset = offsetof(struct sockaddr_in6, sin6_addr);
            length = 16;
            break;

        default:
            return -1;
    }

    return memcmp(((const char *) left) + offset,
                  ((const char *) right) + offset, length);
}

static int find_interface(const struct sockaddr *addr,
                          avs_net_socket_interface_name_t *if_name) {
#define TRY_ADDRESS(tried_addr, tried_name) \
    do { \
        if (ifaddr_ip_equal(addr, tried_addr) == 0) { \
            retval = snprintf(*if_name, sizeof(*if_name), "%s", tried_name); \
            if (retval > 0) { \
                retval = ((size_t) retval >= sizeof(*if_name)) ? -1 : 0; \
            } \
            goto interface_name_end; \
        } \
    } while (0)
#ifdef HAVE_GETIFADDRS
    int retval = -1;
    struct ifaddrs *ifaddrs = NULL;
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddrs)) {
        goto interface_name_end;
    }
    for (ifaddr = ifaddrs; ifaddr; ifaddr = ifaddr->ifa_next) {
        if (ifaddr->ifa_addr) {
            TRY_ADDRESS(ifaddr->ifa_addr, ifaddr->ifa_name);
        }
    }
interface_name_end:
    if (ifaddrs) {
        freeifaddrs(ifaddrs);
    }
    return retval;
#elif defined(SIOCGIFCONF)
#ifndef _SIZEOF_ADDR_IFREQ
#define _SIZEOF_ADDR_IFREQ sizeof
#endif
    int retval = -1;
    int null_socket;
    struct ifconf conf;
    size_t blen = 32 * sizeof(struct ifconf [1]);
    struct ifreq *reqs = NULL;
    struct ifreq *req;
    if ((null_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        goto interface_name_end;
    }
interface_name_retry:
    reqs = (struct ifreq *) realloc(reqs, blen);
    conf.ifc_req = reqs;
    conf.ifc_len = (int) blen;
    if (ioctl(null_socket, SIOCGIFCONF, &conf) < 0) {
        goto interface_name_end;
    }
    if ((size_t) conf.ifc_len == blen) {
        blen *= 2;
        goto interface_name_retry;
    }
    for (req = reqs; req < reqs + blen;
            req = (struct ifreq *)(((char *) req) + _SIZEOF_ADDR_IFREQ(*req))) {
        TRY_ADDRESS(&req->ifr_addr, req->ifr_name);
    }
interface_name_end:
    free(reqs);
    close(null_socket);
    return retval;
#elif defined(WITH_LWIP)
#error "TODO"
#else
    return -1;
#endif
#undef TRY_ADDRESS
}

static int interface_name_net(avs_net_abstract_socket_t *socket_,
                              avs_net_socket_interface_name_t *if_name) {
    avs_net_socket_t *socket = (avs_net_socket_t *) socket_;
    if (socket->configuration.interface_name[0]) {
        memcpy(*if_name,
               socket->configuration.interface_name,
               sizeof (*if_name));
        return 0;
    } else {
        sockaddr_union_t addr;
        socklen_t addrlen = sizeof(addr);
        if (getsockname(socket->socket, &addr.addr, &addrlen)) {
            return -1;
        }
        return find_interface(&addr.addr, if_name);
    }
}

static int validate_ip_address(avs_net_af_t family, const char *ip_address) {
    union {
        struct in_addr sa4;
        struct in6_addr sa6;
    } sa;
    if (_avs_inet_pton(get_af(family), ip_address, &sa) < 1) {
        return -1;
    }
    return 0;
}

int avs_net_validate_ip_address(avs_net_af_t family, const char *ip_address) {
    if (family == AVS_NET_AF_INET4 || family == AVS_NET_AF_INET6) {
        return validate_ip_address(family, ip_address);
    } else {
        return (validate_ip_address(AVS_NET_AF_INET4, ip_address) == 0
                || validate_ip_address(AVS_NET_AF_INET6, ip_address) == 0)
                ? 0 : -1;
    }
}
