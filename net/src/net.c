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
#include <ifaddrs.h>

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

#ifdef HAVE_INET_NTOP
#define _avs_inet_ntop inet_ntop
#else
const char *_avs_inet_ntop(int af, const void *src, char *dst, socklen_t size);
#endif

#ifdef HAVE_RAND_R
#define _avs_rand_r rand_r
#else
#warning "rand_r not available, please provide int _avs_rand_r(unsigned int *)"
int _avs_rand_r(unsigned int *seedp);
#endif

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

static int configure_socket(avs_net_socket_t *net_socket) {
    if (net_socket->configuration.interface_name[0]) {
        if (setsockopt(net_socket->socket,
                       SOL_SOCKET,
                       SO_BINDTODEVICE,
                       net_socket->configuration.interface_name,
                       (socklen_t)
                       strlen(net_socket->configuration.interface_name))) {
            return -1;
        }
    }
    if (net_socket->configuration.priority) {
        /* SO_PRIORITY accepts int as argument */
        int priority = net_socket->configuration.priority;
        socklen_t length = sizeof(priority);
        if (setsockopt(net_socket->socket,
                       SOL_SOCKET, SO_PRIORITY, &priority, length)) {
            return -1;
        }
    }
    if (net_socket->configuration.dscp) {
        uint8_t tos;
        socklen_t length = sizeof(tos);
        if (getsockopt(net_socket->socket, IPPROTO_IP, IP_TOS, &tos, &length)) {
            return -1;
        }
        tos &= 0x03; /* clear first 6 bits */
        tos |= (uint8_t) (net_socket->configuration.dscp << 2);
        if (setsockopt(net_socket->socket, IPPROTO_IP, IP_TOS, &tos, length)) {
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

static int connect_net(avs_net_abstract_socket_t *net_socket_,
                       const char *host,
                       const char *port) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    struct addrinfo *info = NULL, *address = NULL;

    if (net_socket->socket >= 0) {
        return -1;
    }

    strncpy(net_socket->host, host, sizeof(net_socket->host) - 1);
    net_socket->host[sizeof(net_socket->host) - 1] = '\0';
    strncpy(net_socket->port, port, sizeof(net_socket->port) - 1);
    net_socket->port[sizeof(net_socket->port) - 1] = '\0';

    info = get_addrinfo_net(net_socket->type,
                            net_socket->host, net_socket->port, AF_UNSPEC, 0,
                            net_socket->configuration.preferred_endpoint);
    for (address = info; address != NULL; address = address->ai_next) {
        if ((net_socket->socket = socket(address->ai_family,
                                         address->ai_socktype,
                                         address->ai_protocol)) < 0) {
            continue;
        }
        if (configure_socket(net_socket)) {
            close(net_socket->socket);
            continue;
        }
        if (connect_with_timeout(net_socket->socket,
                                 address->ai_addr,
                                 address->ai_addrlen) < 0
                || (is_stream(net_socket)
                && send_net(net_socket_, NULL, 0) < 0)) {
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
            return -1;
        }
        result = send(net_socket->socket, ((const char *) buffer) + bytes_sent,
                      buffer_length - bytes_sent, MSG_NOSIGNAL);
        if (result < 0) {
            return -1;
        } else if (buffer_length != 0 && result == 0) {
            break;
        } else {
            bytes_sent += (size_t) result;
        }
        /* call send() multiple times only if the socket is stream-oriented */
    } while (is_stream(net_socket) && bytes_sent < buffer_length);

    if (bytes_sent < buffer_length) {
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

static int host_port_to_string(const struct sockaddr *sa, socklen_t salen,
                               char *host, socklen_t hostlen,
                               char *serv, socklen_t servlen) {
#ifdef HAVE_GETNAMEINFO
    return getnameinfo(sa, salen, host, hostlen, serv, servlen,
                       NI_NUMERICHOST | NI_NUMERICSERV);
#else
    const void *addr_ptr = NULL;
    const uint16_t *port_ptr = NULL;
    int retval;
    if (sa->sa_family == AF_INET) {
        if (salen < sizeof(struct sockaddr_in)) {
            return -1;
        }
        addr_ptr = &((const struct sockaddr_in *) sa)->sin_addr;
        port_ptr = &((const struct sockaddr_in *) sa)->sin_port;
    } else if (sa->sa_family == AF_INET6) {
        if (salen < sizeof(struct sockaddr_in6)) {
            return -1;
        }
        addr_ptr = &((const struct sockaddr_in6 *) sa)->sin6_addr;
        port_ptr = &((const struct sockaddr_in6 *) sa)->sin6_port;
    } else {
        return -1;
    }
    return (!_avs_inet_ntop(sa->sa_family, addr_ptr, host, hostlen)
            || (retval = snprintf(serv, servlen, "%" PRIu16, *port_ptr)) < 0
            || (size_t) retval >= servlen) ? -1 : 0;
#endif
}

static int receive_from_net(avs_net_abstract_socket_t *net_socket_,
                            size_t *out,
                            void *message_buffer, size_t buffer_size,
                            char *host, size_t host_size,
                            char *port, size_t port_size) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    struct sockaddr_storage sender_addr;
    socklen_t addrlen = sizeof (sender_addr);

    if (host) {
        host[0] = '\0';
    }
    if (port) {
        port[0] = '\0';
    }

    if (!wait_until_ready(net_socket->socket,
                          AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT, 1, 0)) {
        *out = 0;
        return -1;
    } else {
        ssize_t result = recvfrom(net_socket->socket,
                                  message_buffer, buffer_size, 0,
                                  (struct sockaddr *) &sender_addr, &addrlen);
        if (result < 0) {
            *out = 0;
            return -1;
        } else {
            *out = (size_t) result;
            if (result > 0 && (host || port)) {
                return host_port_to_string((struct sockaddr *) &sender_addr,
                                           addrlen, host, (socklen_t) host_size,
                                           port, (socklen_t) port_size);
            }
            return 0;
        }
    }
}

static int bind_net(avs_net_abstract_socket_t *net_socket_,
                    const char *localaddr,
                    const char *port) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    struct addrinfo *info = NULL;
    int val = 1;

    if (net_socket->socket >= 0) {
        return -1;
    }

    info = get_addrinfo_net(net_socket->type, localaddr, port,
                            AF_INET6, AI_ADDRCONFIG | AI_PASSIVE, NULL);
    if (!info) {
        info = get_addrinfo_net(net_socket->type, localaddr, port,
                                AF_INET, AI_ADDRCONFIG | AI_PASSIVE, NULL);
    }
    if (!info) {
        return -1;
    }

    if ((net_socket->socket = socket(info->ai_family,
                                     info->ai_socktype,
                                     info->ai_protocol)) < 0) {
        freeaddrinfo(info);
        return -1;
    }
    if (is_stream(net_socket)
            && setsockopt(net_socket->socket,
                          SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val))) {
        freeaddrinfo(info);
        close_net(net_socket_);
        return -1;
    }
    if (bind(net_socket->socket, info->ai_addr, info->ai_addrlen) < 0) {
        freeaddrinfo(info);
        close_net(net_socket_);
        return -2;
    }
    if (is_stream(net_socket) && listen(net_socket->socket, 1) < 0) {
        freeaddrinfo(info);
        close_net(net_socket_);
        return -3;
    }
    freeaddrinfo(info);
    net_socket->state = AVS_NET_SOCKET_STATE_LISTENING;
    return 0;
}

static int accept_net(avs_net_abstract_socket_t *server_net_socket_,
                      avs_net_abstract_socket_t *new_net_socket_) {
    avs_net_socket_t *server_net_socket =
            (avs_net_socket_t *) server_net_socket_;
    avs_net_socket_t *new_net_socket =
            (avs_net_socket_t *) new_net_socket_;

    if (new_net_socket->socket >= 0) {
        return -1;
    }

    if (wait_until_ready(server_net_socket->socket,
                         NET_ACCEPT_TIMEOUT, 1, 0)) {
        struct sockaddr_storage remote_address;
        socklen_t remote_address_length = sizeof(remote_address);

        new_net_socket->socket = accept(server_net_socket->socket,
                                        (struct sockaddr *) &remote_address,
                                        &remote_address_length);
        if (new_net_socket->socket >= 0) {
            if (host_port_to_string((struct sockaddr *) &remote_address,
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
        return -1;

    }
    if (configuration->dscp >= 64) {
        return -1;
    }
    if (configuration->priority > 7) {
        return -1;
    }
    return 0;
}

static void
store_configuration(avs_net_socket_t *socket,
                    const avs_net_socket_configuration_t *configuration) {
    memcpy(&socket->configuration, configuration, sizeof(*configuration));
}

static int create_net_socket(avs_net_abstract_socket_t **socket,
                             int socket_type,
                             const void *socket_configuration) {
    static const avs_net_socket_t new_socket
            = { &net_vtable, -1, 0, AVS_NET_SOCKET_STATE_CLOSED, "", "",
                { 0, 0, "", NULL }, AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT };
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
        return _avs_inet_ntop(addr->sa_family, addr_data, buffer, addrlen)
                == NULL ? -1 : 0;
    }
}

static int get_string_port(const struct sockaddr *addr,
                           char *buffer, size_t buffer_size) {
    in_port_t port;
    int retval;

    switch(addr->sa_family) {
        case AF_INET:
            port = ((const struct sockaddr_in *)addr)->sin_port;
            break;

        case AF_INET6:
            port = ((const struct sockaddr_in6 *)addr)->sin6_port;
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

static int local_port_net(avs_net_abstract_socket_t *socket,
                          char *out_buffer, size_t out_buffer_size) {
    const avs_net_socket_t *net_socket = (const avs_net_socket_t *) socket;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof (addr);

    if (!getsockname(net_socket->socket, (struct sockaddr *) &addr, &addrlen)) {
        return get_string_port((struct sockaddr *)&addr,
                               out_buffer, out_buffer_size);
    } else {
        return -1;
    }
}

static int get_opt_net(avs_net_abstract_socket_t *net_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    if (option_key == AVS_NET_SOCKET_OPT_STATE) {
        out_option_value->state = net_socket->state;
    } else {
        return -1;
    }
    return 0;
}

static int set_opt_net(avs_net_abstract_socket_t *net_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t option_value) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    if (option_key == AVS_NET_SOCKET_OPT_RECV_TIMEOUT) {
        net_socket->recv_timeout = option_value.recv_timeout;
    } else {
        return -1;
    }
    return 0;
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
            TRY_ADDRESS(ifaddr->ifa_addr);
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
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        if (getsockname(socket->socket, (struct sockaddr *) &addr, &addrlen)) {
            return -1;
        }
        return find_interface((const struct sockaddr *) &addr, if_name);
    }
}
