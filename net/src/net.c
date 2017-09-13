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

#define _AVS_NEED_POSIX_SOCKET

#include <config.h>
#include <posix-config.h>

#include <avsystem/commons/utils.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

#include "compat.h"
#include "net.h"

VISIBILITY_SOURCE_BEGIN

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

typedef union {
    struct sockaddr         addr;
    struct sockaddr_storage addr_storage;

#ifdef WITH_IPV4
    struct sockaddr_in      addr_in;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
    struct sockaddr_in6     addr_in6;
#endif /* WITH_IPV6 */
} sockaddr_union_t;

/**
 * We don't want to use types such as <c>struct sockaddr</c> in public API types
 * such as @ref avs_net_resolved_endpoint_t, because we don't want to expose
 * POSIX-specific types in completely portable API.
 *
 * But we need to access it as such, while at the same time, accessing it
 * through casts violates strict-aliasing rules, which is technically UB and may
 * cause some weird and hard-to-debug errors on some platforms/compilers.
 *
 * So we are declaring this type, to be layout-compatible with
 * @ref avs_net_resolved_endpoint_t, but allow us to access
 * <c>struct sockaddr</c> without explicit casts.
 */
typedef struct {
    union {
        uint8_t size;
        char padding[offsetof(avs_net_resolved_endpoint_t, data)];
    } header;
    struct sockaddr addr;
} sockaddr_endpoint_t;

/**
 * Here are static assertions that ensure that @ref sockaddr_endpoint_t is
 * indeed layout-compatible with @ref avs_net_resolved_endpoint_t.
 */
AVS_STATIC_ASSERT(offsetof(sockaddr_endpoint_t, header)
                          == offsetof(avs_net_resolved_endpoint_t, size),
                  sockaddr_endpoint_size_offset);
AVS_STATIC_ASSERT(sizeof(((sockaddr_endpoint_t) {
                              .header = { .size = 0 } }).header.size)
                          == sizeof(((avs_net_resolved_endpoint_t) {
                                         .size = 0 }).size),
                  sockaddr_endpoint_size_size);
AVS_STATIC_ASSERT(offsetof(sockaddr_endpoint_t, addr)
                          == offsetof(avs_net_resolved_endpoint_t, data),
                  sockaddr_endpoint_offset);

/**
 * And here is the union that allows us to mix Commons' APIs that use
 * @ref avs_net_resolved_endpoint_t and POSIX APIs that use
 * <c>struct sockaddr</c>.
 */
typedef union {
    avs_net_resolved_endpoint_t api_ep;
    sockaddr_endpoint_t sockaddr_ep;
} sockaddr_endpoint_union_t;

static int connect_net(avs_net_abstract_socket_t *net_socket,
                       const char* host,
                       const char *port);
static int send_net(avs_net_abstract_socket_t *net_socket,
                    const void* buffer,
                    size_t buffer_length);
static int send_to_net(avs_net_abstract_socket_t *socket,
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
static int remote_hostname_net(avs_net_abstract_socket_t *socket,
                               char *out_buffer, size_t out_buffer_size);
static int remote_port_net(avs_net_abstract_socket_t *socket,
                           char *out_buffer, size_t out_buffer_size);
static int local_host_net(avs_net_abstract_socket_t *socket,
                          char *out_buffer, size_t out_buffer_size);
static int local_port_net(avs_net_abstract_socket_t *socket,
                          char *out_buffer, size_t out_buffer_size);
static int get_opt_net(avs_net_abstract_socket_t *net_socket,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value);
static int set_opt_net(avs_net_abstract_socket_t *net_socket,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t option_value);
static int errno_net(avs_net_abstract_socket_t *net_socket);

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
    remote_hostname_net,
    remote_port_net,
    local_host_net,
    local_port_net,
    get_opt_net,
    set_opt_net,
    errno_net
};

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    int socket;
    avs_net_socket_type_t type;
    avs_net_socket_state_t state;
    char remote_hostname[NET_MAX_HOSTNAME_SIZE];
    char remote_port[NET_PORT_SIZE];
    avs_net_socket_configuration_t configuration;

    avs_net_timeout_t recv_timeout;
    volatile int error_code;
} avs_net_socket_t;

int _avs_net_get_af(avs_net_af_t addr_family) {
    switch (addr_family) {
#ifdef WITH_IPV4
    case AVS_NET_AF_INET4:
        return AF_INET;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
    case AVS_NET_AF_INET6:
        return AF_INET6;
#endif /* WITH_IPV6 */

    case AVS_NET_AF_UNSPEC:
    default:
        return AF_UNSPEC;
    }
}

#if defined(WITH_IPV4) && defined(WITH_IPV6)
static bool is_v4mapped(const struct sockaddr_in6 *addr) {
#ifdef HAVE_IN6_IS_ADDR_V4MAPPED
    return IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr);
#else
    static const uint8_t V4MAPPED_ADDR_HEADER[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
    };
    return memcmp(addr->sin6_addr.s6_addr, V4MAPPED_ADDR_HEADER,
                  sizeof(V4MAPPED_ADDR_HEADER)) == 0;
#endif
}

static int unmap_v4mapped(sockaddr_union_t *addr) {
    if (addr->addr.sa_family != AF_INET6 || !is_v4mapped(&addr->addr_in6)) {
        return -1;
    } else {
        struct sockaddr_in unmapped;
        memset(&unmapped, 0, sizeof(unmapped));
        unmapped.sin_family = AF_INET;
        unmapped.sin_port = addr->addr_in6.sin6_port;
        memcpy(&unmapped.sin_addr, &addr->addr_in6.sin6_addr.s6_addr[12], 4);
        addr->addr_in = unmapped;
        return 0;
    }
}
#else // defined(WITH_IPV4) && defined(WITH_IPV6)
#define unmap_v4mapped(Addr) (-1)
#endif // defined(WITH_IPV4) && defined(WITH_IPV6)

static const char *get_af_name(avs_net_af_t af) {
    switch (af) {
#ifdef WITH_IPV4
    case AVS_NET_AF_INET4:
        return "AF_INET";
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
    case AVS_NET_AF_INET6:
        return "AF_INET6";
#endif /* WITH_IPV6 */

    case AVS_NET_AF_UNSPEC:
    default:
        return "AF_UNSPEC";
    }
}

static int get_string_ip(const sockaddr_union_t *addr,
                         char *buffer, size_t buffer_size) {
    const void *addr_data;
    socklen_t addrlen;

    switch(addr->addr.sa_family) {
#ifdef WITH_IPV4
        case AF_INET:
            addr_data = &addr->addr_in.sin_addr;
            addrlen = INET_ADDRSTRLEN;
            break;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
        case AF_INET6:
            addr_data = &addr->addr_in6.sin6_addr;
            addrlen = INET6_ADDRSTRLEN;
            break;
#endif /* WITH_IPV6 */

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
    switch(addr->addr.sa_family) {
#ifdef WITH_IPV4
        case AF_INET:
            port = addr->addr_in.sin_port;
            break;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
        case AF_INET6:
            port = addr->addr_in6.sin6_port;
            break;
#endif /* WITH_IPV6 */

        default:
            return -1;
    }

    return avs_simple_snprintf(buffer, buffer_size, "%u", ntohs(port)) < 0 ? -1
                                                                           : 0;
}

static int remote_host_net(avs_net_abstract_socket_t *socket,
                           char *out_buffer, size_t out_buffer_size) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) socket;
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    errno = 0;
    if (!getpeername(net_socket->socket, &addr.addr, &addrlen)) {
        (void)unmap_v4mapped(&addr);
        int result = get_string_ip(&addr, out_buffer, out_buffer_size);
        net_socket->error_code = (result ? ERANGE : 0);
        return result;
    } else {
        net_socket->error_code = errno;
        return -1;
    }
}

static int remote_hostname_net(avs_net_abstract_socket_t *socket_,
                               char *out_buffer, size_t out_buffer_size) {
    avs_net_socket_t *socket = (avs_net_socket_t *) socket_;
    if (!socket->remote_hostname[0]) {
        socket->error_code = (socket->socket < 0 ? EBADF : ENOBUFS);
        return -1;
    }
    if (avs_simple_snprintf(out_buffer, out_buffer_size, "%s",
                            socket->remote_hostname) < 0) {
        socket->error_code = ERANGE;
        return -1;
    } else {
        socket->error_code = 0;
        return 0;
    }
}

static int remote_port_net(avs_net_abstract_socket_t *socket_,
                           char *out_buffer, size_t out_buffer_size) {
    avs_net_socket_t *socket = (avs_net_socket_t *) socket_;
    if (!socket->remote_port[0]) {
        socket->error_code = (socket->socket < 0 ? EBADF : ENOBUFS);
        return -1;
    }
    if (avs_simple_snprintf(out_buffer, out_buffer_size, "%s",
                            socket->remote_port) < 0) {
        socket->error_code = ERANGE;
        return -1;
    } else {
        socket->error_code = 0;
        return 0;
    }
}

static int system_socket_net(avs_net_abstract_socket_t *net_socket_,
                             const void **out) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    if (net_socket->socket >= 0) {
        *out = &net_socket->socket;
        net_socket->error_code = 0;
        return 0;
    } else {
        net_socket->error_code = EBADF;
        return -1;
    }
}

static void close_net_raw(avs_net_socket_t *net_socket) {
    if (net_socket->socket >= 0) {
        close(net_socket->socket);
        net_socket->socket = -1;
        net_socket->state = AVS_NET_SOCKET_STATE_CLOSED;
    }
}

static int close_net(avs_net_abstract_socket_t *net_socket_) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    close_net_raw(net_socket);
    net_socket->error_code = 0;
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
    int retval;
    errno = 0;
    retval = shutdown(net_socket->socket, SHUT_RDWR);
    net_socket->error_code = errno;
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

#ifdef WITH_IPV6
/**
 * Differs from get_socket_family() by the fact that if the socket is AF_INET6
 * at the kernel level, but is connected to an IPv4-mapped address, it returns
 * AF_INET.
 */
static sa_family_t get_connection_family(int fd) {
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    if (getpeername(fd, &addr.addr, &addrlen)) {
        return get_socket_family(fd);
#if defined(WITH_IPV4) && defined(WITH_IPV6)
    } else if (addr.addr.sa_family == AF_INET6
            && is_v4mapped(&addr.addr_in6)) {
        return AF_INET;
#endif
    } else {
        return addr.addr.sa_family;
    }
}
#endif // WITH_IPV6

#if !defined(IP_TRANSPARENT) && defined(__linux__)
#define IP_TRANSPARENT 19
#endif

#if !defined(IPV6_TRANSPARENT) && defined(__linux__)
#define IPV6_TRANSPARENT 75
#endif

static int configure_socket(avs_net_socket_t *net_socket) {
    errno = 0;
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
            net_socket->error_code = errno;
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
            net_socket->error_code = errno;
            LOG(ERROR, "setsockopt error: %s", strerror(errno));
            return -1;
        }
    }
    if (net_socket->configuration.dscp) {
#ifdef IP_TOS
        uint8_t tos;
        socklen_t length = sizeof(tos);
        if (getsockopt(net_socket->socket, IPPROTO_IP, IP_TOS, &tos, &length)) {
            net_socket->error_code = errno;
            LOG(ERROR, "getsockopt error: %s", strerror(errno));
            return -1;
        }
        tos &= 0x03; /* clear first 6 bits */
        tos |= (uint8_t) (net_socket->configuration.dscp << 2);
        if (setsockopt(net_socket->socket, IPPROTO_IP, IP_TOS, &tos, length)) {
            net_socket->error_code = errno;
            LOG(ERROR, "setsockopt error: %s", strerror(errno));
            return -1;
        }
#else // IP_TOS
        net_socket->error_code = EINVAL;
        return -1;
#endif// IP_TOS
    }
    if (net_socket->configuration.transparent) {
        int value = 1;
        errno = EINVAL;
        switch (get_socket_family(net_socket->socket)) {
#ifdef WITH_IPV4
        case AF_INET:
#ifdef IP_TRANSPARENT
            if (setsockopt(net_socket->socket, SOL_IP, IP_TRANSPARENT,
                           &value, sizeof(value)))
#endif
            {
                net_socket->error_code = errno;
                return -1;
            }
            break;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
        case AF_INET6:
#ifdef IPV6_TRANSPARENT
            if (setsockopt(net_socket->socket, SOL_IPV6, IPV6_TRANSPARENT,
                           &value, sizeof(value)))
#endif
            {
                net_socket->error_code = errno;
                return -1;
            }
            break;
#endif /* WITH_IPV6 */

        default:
            (void) value;
            net_socket->error_code = EINVAL;
            return -1;
        }
    }
    net_socket->error_code = 0;
    return 0;
}

static short wait_until_ready(int sockfd, avs_net_timeout_t timeout,
                              char in, char out, char err) {
#ifdef HAVE_POLL
    struct pollfd p;
    short events = (short) ((in ? POLLIN : 0) | (out ? POLLOUT : 0));
    p.fd = sockfd;
    p.events = events;
    p.revents = 0;
    if (poll(&p, 1, timeout) != 1) {
        return 0;
    }
    if (err) {
        events = (short) (events | POLLHUP | POLLERR);
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

#if LWIP_VERSION_MAJOR < 2
// LwIP < 2.0 lacks cast to unsigned inside FD_* macros
# define AVS_FD_SET(fd, set) FD_SET((unsigned)(fd), (set))
# define AVS_FD_ISSET(fd, set) FD_ISSET((unsigned)(fd), (set))
#else
# define AVS_FD_SET FD_SET
# define AVS_FD_ISSET FD_ISSET
#endif // LWIP_VERSION_MAJOR < 2

    if (in) {
        AVS_FD_SET(sockfd, &infds);
    }
    if (out) {
        AVS_FD_SET(sockfd, &outfds);
    }
    AVS_FD_SET(sockfd, &errfds);
    if (select(sockfd + 1, &infds, &outfds, &errfds,
               timeout >= 0 ? &timeval_timeout : NULL) <= 0) {
        return 0;
    }
    return (err && AVS_FD_ISSET(sockfd, &errfds))
            || (in && AVS_FD_ISSET(sockfd, &infds))
            || (out && AVS_FD_ISSET(sockfd, &outfds));
#undef AVS_FD_SET
#undef AVS_FD_ISSET

#endif
}

static int connect_with_timeout(int sockfd,
                                const sockaddr_endpoint_union_t *endpoint,
                                char is_stream) {
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        return -1;
    }
    if (connect(sockfd, &endpoint->sockaddr_ep.addr,
                endpoint->sockaddr_ep.header.size) == -1
            && errno != EINPROGRESS) { // see man connect for details
        return -1;
    }
    if (!wait_until_ready(sockfd, NET_CONNECT_TIMEOUT, 1, 1, is_stream)) {
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
#else /* HAVE_GETNAMEINFO */
    const void *addr_ptr = NULL;
    const uint16_t *port_ptr = NULL;

# ifdef WITH_IPV4
    if (sa->sa_family == AF_INET) {
        if (salen >= sizeof(struct sockaddr_in)) {
            addr_ptr = &((const struct sockaddr_in *) sa)->sin_addr;
            port_ptr = &((const struct sockaddr_in *) sa)->sin_port;
            result = 0;
        }
    }
# endif /* WITH_IPV4 */

# ifdef WITH_IPV6
    if (sa->sa_family == AF_INET6) {
        if (salen >= sizeof(struct sockaddr_in6)) {
            addr_ptr = &((const struct sockaddr_in6 *) sa)->sin6_addr;
            port_ptr = &((const struct sockaddr_in6 *) sa)->sin6_port;
            result = 0;
        }
    }
# endif /* WITH_IPV6 */

    if (!result) {
        if (host) {
            result = (!_avs_inet_ntop(sa->sa_family, addr_ptr, host, hostlen)
                    ? -1 : 0);
        }
        if (!result && serv) {
            result = avs_simple_snprintf(serv, servlen, "%" PRIu16, *port_ptr)
                                     < 0
                             ? -1
                             : 0;
        }
    }
#endif /* HAVE_GETNAMEINFO */
    if (result) {
        LOG(ERROR, "Could not stringify socket address");
        if (!errno) {
            errno = ENOSPC;
        }
    } else {
        if (host) {
            host[hostlen - 1] = '\0';
            unwrap_4in6(host);
        }
        if (serv) {
            serv[servlen - 1] = '\0';
        }
        errno = 0;
    }
    return result;
}

int _avs_net_get_socket_type(avs_net_socket_type_t socket_type) {
    switch (socket_type) {
    case AVS_NET_TCP_SOCKET:
    case AVS_NET_SSL_SOCKET:
        return SOCK_STREAM;
    case AVS_NET_UDP_SOCKET:
    case AVS_NET_DTLS_SOCKET:
        return SOCK_DGRAM;
    default:
        return 0;
    }
}

static avs_net_af_t get_avs_af(int af) {
    switch (af) {
#ifdef WITH_IPV4
    case AF_INET:
        return AVS_NET_AF_INET4;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
    case AF_INET6:
        return AVS_NET_AF_INET6;
#endif /* WITH_IPV6 */

    default:
        return AVS_NET_AF_UNSPEC;
    }
}

static int get_other_family(avs_net_af_t *out, avs_net_af_t in) {
    switch (in) {
    case AVS_NET_AF_INET4:
        *out = AVS_NET_AF_INET6;
        return 0;
    case AVS_NET_AF_INET6:
        *out = AVS_NET_AF_INET4;
        return 0;
    default:
        return -1;
    }
}

static avs_net_addrinfo_t *
resolve_addrinfo_for_socket(avs_net_socket_t *net_socket,
                            const char *host,
                            const char *port,
                            bool use_preferred_endpoint,
                            bool use_preferred_family) {
    avs_net_af_t family = net_socket->configuration.address_family;
    if (family == AVS_NET_AF_UNSPEC) {
        if (use_preferred_family) {
            family = net_socket->configuration.preferred_family;
        } else if (get_other_family(
                &family, net_socket->configuration.preferred_family)) {
            return NULL;
        }
    } else if (!use_preferred_family) {
        return NULL;
    }
    int resolve_flags = 0;

    if (net_socket->socket >= 0) {
        avs_net_af_t socket_family =
                get_avs_af(get_socket_family(net_socket->socket));
        if (socket_family == AVS_NET_AF_INET6) {
            if (family != AVS_NET_AF_INET6) {
                resolve_flags |= AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED;
            }
        } else if (socket_family != family) {
            if (family == AVS_NET_AF_UNSPEC) {
                family = socket_family;
            } else if (socket_family != AVS_NET_AF_UNSPEC) {
                return NULL;
            }
        }
        if (family == AVS_NET_AF_UNSPEC) {
            if (socket_family == AVS_NET_AF_INET6) {
                resolve_flags |= AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED;
            }
            family = socket_family;
        } else if (socket_family != AVS_NET_AF_UNSPEC
                && socket_family != family) {
            return NULL;
        }
    }

    return avs_net_addrinfo_resolve_ex(
            net_socket->type, family, host, port, resolve_flags,
            use_preferred_endpoint
                    ? net_socket->configuration.preferred_endpoint : NULL);
}

static int try_connect_open_socket(avs_net_socket_t *net_socket,
                                   const sockaddr_endpoint_union_t *address) {
    char socket_is_stream = (net_socket->type == AVS_NET_TCP_SOCKET);
    if (connect_with_timeout(net_socket->socket, address, socket_is_stream) < 0
            || (socket_is_stream
                    && send_net((avs_net_abstract_socket_t *) net_socket,
                                NULL, 0) < 0)) {
        net_socket->error_code = errno;
        return -1;
    } else {
        /* SUCCESS */
        net_socket->state = AVS_NET_SOCKET_STATE_CONNECTED;
        /* store address affinity */
        if (net_socket->configuration.preferred_endpoint) {
            *net_socket->configuration.preferred_endpoint = address->api_ep;
        }
        net_socket->error_code = 0;
        return 0;
    }
}

static int try_connect(avs_net_socket_t *net_socket,
                       const sockaddr_endpoint_union_t *address) {
    char socket_was_already_open = (net_socket->socket >= 0);
    int retval = 0;
    if (!socket_was_already_open) {
        if ((net_socket->socket = socket(
                address->sockaddr_ep.addr.sa_family,
                _avs_net_get_socket_type(net_socket->type), 0)) < 0) {
            net_socket->error_code = errno;
            LOG(ERROR, "cannot create socket: %s", strerror(errno));
            retval = -1;
        } else if (configure_socket(net_socket)) {
            LOG(WARNING, "socket configuration problem");
            retval = -1;
        }
    }
    if (!retval) {
        retval = try_connect_open_socket(net_socket, address);
    }
    if (retval && !socket_was_already_open && net_socket->socket >= 0) {
        close(net_socket->socket);
        net_socket->socket = -1;
    }
    return retval;
}

static int connect_net(avs_net_abstract_socket_t *net_socket_,
                       const char *host,
                       const char *port) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    avs_net_addrinfo_t *info = NULL;
    int result = 0;

    if (net_socket->socket >= 0) {
        if (net_socket->type != AVS_NET_UDP_SOCKET
                || net_socket->state != AVS_NET_SOCKET_STATE_BOUND) {
            LOG(ERROR, "socket is already connected or bound");
            net_socket->error_code = EISCONN;
            return -1;
        }
    }

    LOG(TRACE, "connecting to [%s]:%s", host, port);

    errno = 0;
    net_socket->error_code = EPROTO;
    if ((info = resolve_addrinfo_for_socket(net_socket, host, port,
                                            false, true))) {
        sockaddr_endpoint_union_t address;
        while (!(result = avs_net_addrinfo_next(info, &address.api_ep))) {
            if (!try_connect(net_socket, &address)) {
                goto success;
            }
        }
    }
    avs_net_addrinfo_delete(&info);
    if ((info = resolve_addrinfo_for_socket(net_socket, host, port,
                                            false, false))) {
        sockaddr_endpoint_union_t address;
        while (!(result = avs_net_addrinfo_next(info, &address.api_ep))) {
            if (!try_connect(net_socket, &address)) {
                goto success;
            }
        }
    }
    avs_net_addrinfo_delete(&info);
    LOG(ERROR, "cannot establish connection to [%s]:%s: %s",
        host, port, strerror(net_socket->error_code));
    return result < 0 ? result : -1;
success:
    avs_net_addrinfo_delete(&info);

    if (avs_simple_snprintf(net_socket->remote_hostname,
                            sizeof(net_socket->remote_hostname),
                            "%s", host) < 0) {
        LOG(WARNING, "Hostname %s is too long, not storing", host);
        net_socket->remote_hostname[0] = '\0';
    }
    if (avs_simple_snprintf(net_socket->remote_port,
                            sizeof(net_socket->remote_port), "%s", port) < 0) {
        LOG(WARNING, "Port %s is too long, not storing", port);
        net_socket->remote_port[0] = '\0';
    }
    return 0;
}

static int send_net(avs_net_abstract_socket_t *net_socket_,
                    const void *buffer,
                    size_t buffer_length) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    size_t bytes_sent = 0;

    /* send at least one datagram, even if zero-length - hence do..while */
    do {
        ssize_t result;
        if (!wait_until_ready(net_socket->socket, NET_SEND_TIMEOUT, 0, 1, 1)) {
            LOG(ERROR, "timeout (send)");
            net_socket->error_code = ETIMEDOUT;
            return -1;
        }
        errno = 0;
        result = send(net_socket->socket, ((const char *) buffer) + bytes_sent,
                      buffer_length - bytes_sent, MSG_NOSIGNAL);
        if (result < 0) {
            net_socket->error_code = errno;
            LOG(ERROR, "%d:%s", (int) result, strerror(errno));
            return -1;
        } else if (buffer_length != 0 && result == 0) {
            LOG(ERROR, "send returned 0");
            break;
        } else {
            bytes_sent += (size_t) result;
        }
        /* call send() multiple times only if the socket is stream-oriented */
    } while (net_socket->type == AVS_NET_TCP_SOCKET
            && bytes_sent < buffer_length);

    if (bytes_sent < buffer_length) {
        LOG(ERROR, "sending fail (%lu/%lu)",
            (unsigned long) bytes_sent, (unsigned long) buffer_length);
        net_socket->error_code = EIO;
        return -1;
    } else {
        /* SUCCESS */
        net_socket->error_code = 0;
        return 0;
    }
}

static int send_to_net(avs_net_abstract_socket_t *net_socket_,
                       const void *buffer,
                       size_t buffer_length,
                       const char *host,
                       const char *port) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    avs_net_addrinfo_t *info = NULL;
    sockaddr_endpoint_union_t address;
    ssize_t result = -1;

    if (!(info = resolve_addrinfo_for_socket(net_socket, host, port,
                                             false, true))
            || (result = (ssize_t) avs_net_addrinfo_next(info,
                                                         &address.api_ep))) {
        net_socket->error_code = EPROTO;
    } else {
        errno = 0;
        result = sendto(net_socket->socket, buffer, buffer_length, 0,
                        &address.sockaddr_ep.addr,
                        address.sockaddr_ep.header.size);
        net_socket->error_code = errno;
    }

    avs_net_addrinfo_delete(&info);
    if (result < 0) {
        return (int) result;
    } else if ((size_t) result != buffer_length) {
        LOG(ERROR, "send_to fail (%lu/%lu)",
            (unsigned long) result, (unsigned long) buffer_length);
        net_socket->error_code = EIO;
        return -1;
    } else {
        return 0;
    }
}

#ifndef HAVE_RECVMSG

/* (2017-01-03) LwIP does not implement recvmsg call, try to simulate it using
 * plain recv(), with a little hack to try to detect truncated packets. */
static ssize_t recvfrom_impl(avs_net_socket_t *net_socket,
                             void *buffer,
                             size_t buffer_length,
                             struct sockaddr *src_addr,
                             socklen_t *addrlen) {
    ssize_t recv_out;

    errno = 0;
    recv_out = recvfrom(net_socket->socket, buffer, buffer_length, MSG_NOSIGNAL,
                        src_addr, addrlen);

    if (net_socket->type == AVS_NET_UDP_SOCKET
            && recv_out > 0
            && (size_t)recv_out == buffer_length) {
        /* Buffer entirely filled - data possibly truncated. This will
         * incorrectly reject packets that have exactly buffer_length
         * bytes, but we have no means of distinguishing the edge case
         * without recvmsg.
         * This does only apply to datagram sockets (in our case: UDP). */
        errno = EMSGSIZE;
    }

    return recv_out;
}

#else /* HAVE_RECVMSG */

static ssize_t recvfrom_impl(avs_net_socket_t *net_socket,
                             void *buffer,
                             size_t buffer_length,
                             struct sockaddr *src_addr,
                             socklen_t *addrlen) {
    ssize_t recv_out;
    struct iovec iov = {
        .iov_base = buffer,
        .iov_len = buffer_length
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_name = src_addr,
        .msg_namelen = addrlen ? *addrlen : 0
    };


    errno = 0;
    recv_out = recvmsg(net_socket->socket, &msg, 0);

    if (msg.msg_flags & MSG_TRUNC) {
        /* message too long to fit in the buffer */
        errno = EMSGSIZE;
        recv_out = ((size_t)recv_out <= buffer_length) ? recv_out
                                                       : (ssize_t)buffer_length;
    }

    if (addrlen) {
        *addrlen = msg.msg_namelen;
    }
    return recv_out;
}

#endif /* HAVE_RECVMSG */

static int receive_net(avs_net_abstract_socket_t *net_socket_,
                       size_t *out,
                       void *buffer,
                       size_t buffer_length) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    if (!wait_until_ready(net_socket->socket, net_socket->recv_timeout,
                          1, 0, 1)) {
        net_socket->error_code = ETIMEDOUT;
        *out = 0;
        return -1;
    } else {
        ssize_t recv_out = recvfrom_impl(net_socket, buffer, buffer_length,
                                         NULL, NULL);
        net_socket->error_code = errno;
        if (recv_out < 0) {
            *out = 0;
            return (int) recv_out;
        } else {
            *out = (size_t) recv_out;
            return errno ? -1 : 0;
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

    if (!wait_until_ready(net_socket->socket, net_socket->recv_timeout,
                          1, 0, 1)) {
        net_socket->error_code = ETIMEDOUT;
        *out = 0;
        return -1;
    } else {
        ssize_t recv_result = recvfrom_impl(net_socket,
                                            message_buffer, buffer_size,
                                            &sender_addr.addr, &addrlen);
        net_socket->error_code = errno;
        if (recv_result < 0) {
            *out = 0;
            return -1;
        } else {
            int retval = errno ? -1 : 0;
            int sub_retval;

            errno = 0;
            sub_retval = host_port_to_string(&sender_addr.addr, addrlen,
                                             host, (socklen_t) host_size,
                                             port, (socklen_t) port_size);
            if (!net_socket->error_code) {
                net_socket->error_code = errno;
            }

            *out = (size_t) recv_result;
            return retval ? retval : sub_retval;
        }
    }
}

static int create_listening_socket(avs_net_socket_t *net_socket,
                                   const struct sockaddr *addr,
                                   socklen_t addrlen) {
    int retval = -1;
    int reuse_addr = net_socket->configuration.reuse_addr;
    if (reuse_addr != 0 && reuse_addr != 1) {
        errno = EINVAL;
        return -1;
    }
    errno = 0;
    if ((net_socket->socket = socket(addr->sa_family,
                                     _avs_net_get_socket_type(net_socket->type),
                                     0)) < 0) {
        net_socket->error_code = errno;
        LOG(ERROR, "cannot create system socket: %s", strerror(errno));
        goto create_listening_socket_error;
    }
    if (setsockopt(net_socket->socket, SOL_SOCKET, SO_REUSEADDR, &reuse_addr,
                   sizeof(reuse_addr))) {
        net_socket->error_code = errno;
        LOG(ERROR, "can't set socket opt");
        goto create_listening_socket_error;
    }
    if (configure_socket(net_socket)) {
        goto create_listening_socket_error;
    }
    if (bind(net_socket->socket, addr, addrlen) < 0) {
        net_socket->error_code = errno;
        LOG(ERROR, "bind error: %s", strerror(errno));
        retval = -2;
        goto create_listening_socket_error;
    }
    if (net_socket->type == AVS_NET_TCP_SOCKET
            && listen(net_socket->socket, NET_LISTEN_BACKLOG) < 0) {
        net_socket->error_code = errno;
        LOG(ERROR, "listen error: %s", strerror(errno));
        retval = -3;
        goto create_listening_socket_error;
    }
    net_socket->error_code = 0;
    return 0;
create_listening_socket_error:
    close_net_raw(net_socket);
    return retval;
}

static int try_bind(avs_net_socket_t *net_socket, avs_net_af_t family,
                    const char *localaddr, const char *port) {
    avs_net_addrinfo_t *info = NULL;
    sockaddr_endpoint_union_t address;
    int retval = -1;
    if (net_socket->configuration.address_family != AVS_NET_AF_UNSPEC
            && net_socket->configuration.address_family != family) {
        net_socket->error_code = EINVAL;
        return -1;
    }
    if (!port) {
        port = "0";
    }
    if (!(info = avs_net_addrinfo_resolve_ex(
                    net_socket->type, family, localaddr, port,
                    AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE, NULL))
            || (retval = avs_net_addrinfo_next(info, &address.api_ep))) {
        LOG(WARNING, "Cannot get %s address info for %s",
            get_af_name(family), localaddr ? localaddr : "(null)");
        net_socket->error_code = EINVAL;
        goto bind_net_end;
    }
    net_socket->state = AVS_NET_SOCKET_STATE_BOUND;
    retval = create_listening_socket(net_socket, &address.sockaddr_ep.addr,
                                     address.sockaddr_ep.header.size);
bind_net_end:
    avs_net_addrinfo_delete(&info);
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

#ifdef WITH_IPV6
    retval = try_bind(net_socket, AVS_NET_AF_INET6, localaddr, port);
    if (retval)
#endif /* WITH_IPV6 */
    {
#ifdef WITH_IPV4
        retval = try_bind(net_socket, AVS_NET_AF_INET4, localaddr, port);
#endif /* WITH_IPV4 */
    }
    return retval;
}

static int accept_net(avs_net_abstract_socket_t *server_net_socket_,
                      avs_net_abstract_socket_t *new_net_socket_) {
    sockaddr_union_t remote_address;
    socklen_t remote_address_length = sizeof(remote_address);
    avs_net_socket_t *server_net_socket =
            (avs_net_socket_t *) server_net_socket_;
    avs_net_socket_t *new_net_socket =
            (avs_net_socket_t *) new_net_socket_;

    assert(server_net_socket->operations == &net_vtable);
    if (new_net_socket->operations != &net_vtable
            || new_net_socket->type != server_net_socket->type) {
        LOG(ERROR, "accept_net() called with socket of invaild type");
        server_net_socket->error_code = EINVAL;
        return -1;
    }

    if (new_net_socket->socket >= 0) {
        LOG(ERROR, "socket is already connected or bound");
        server_net_socket->error_code = EISCONN;
        return -1;
    }

    if (!wait_until_ready(server_net_socket->socket,
                          NET_ACCEPT_TIMEOUT, 1, 0, 1)) {
        server_net_socket->error_code = ETIMEDOUT;
        return -1;
    }

    errno = 0;
    new_net_socket->socket = accept(server_net_socket->socket,
                                    &remote_address.addr,
                                    &remote_address_length);
    if (new_net_socket->socket < 0) {
        server_net_socket->error_code = errno;
        return -1;
    }

    if (host_port_to_string(&remote_address.addr,
                            remote_address_length,
                            new_net_socket->remote_hostname,
                            sizeof(new_net_socket->remote_hostname),
                            new_net_socket->remote_port,
                            sizeof(new_net_socket->remote_port)) < 0) {
        server_net_socket->error_code = errno;
        close_net_raw(new_net_socket);
        return -1;
    }
    new_net_socket->state = AVS_NET_SOCKET_STATE_ACCEPTED;
    server_net_socket->error_code = 0;
    new_net_socket->error_code = 0;
    return 0;
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
                             avs_net_socket_type_t socket_type,
                             const void *socket_configuration) {
    const avs_net_socket_v_table_t *const VTABLE_PTR = &net_vtable;
    const avs_net_socket_configuration_t *configuration =
            (const avs_net_socket_configuration_t *) socket_configuration;
    avs_net_socket_t *net_socket =
            (avs_net_socket_t *) calloc(1, sizeof (avs_net_socket_t));
    if (!net_socket) {
        return -1;
    }

    memcpy((void *) (intptr_t) &net_socket->operations,
           &VTABLE_PTR, sizeof(VTABLE_PTR));
    net_socket->socket = -1;
    net_socket->type = socket_type;
    net_socket->recv_timeout = AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT;

    VALGRIND_HG_DISABLE_CHECKING(&net_socket->socket,
                                 sizeof(net_socket->socket));
    VALGRIND_HG_DISABLE_CHECKING(&net_socket->error_code,
                                 sizeof(net_socket->error_code));

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
}

int _avs_net_create_tcp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return create_net_socket(socket, AVS_NET_TCP_SOCKET, socket_configuration);
}

int _avs_net_create_udp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return create_net_socket(socket, AVS_NET_UDP_SOCKET, socket_configuration);
}

int avs_net_local_address_for_target_host(const char *target_host,
                                          avs_net_af_t addr_family,
                                          char *address_buffer,
                                          size_t buffer_size) {
    int result = -1;
    sockaddr_endpoint_union_t address;
    avs_net_addrinfo_t *info =
            avs_net_addrinfo_resolve(AVS_NET_UDP_SOCKET, addr_family,
                                     target_host, AVS_NET_RESOLVE_DUMMY_PORT,
                                     NULL);
    if (!info) {
        return -1;
    }
    while (!(result = avs_net_addrinfo_next(info, &address.api_ep))) {
        int test_socket = socket(address.sockaddr_ep.addr.sa_family, SOCK_DGRAM,
                                 0);

        if (test_socket >= 0) {
            if (!connect_with_timeout(test_socket, &address, 0)) {
                sockaddr_union_t addr;
                socklen_t addrlen = sizeof(addr);

                if (!getsockname(test_socket, &addr.addr, &addrlen)) {
                    result = get_string_ip(&addr, address_buffer, buffer_size);
                }
            }

            close(test_socket);
        }

        if (!result) {
            break;
        }
    }
    avs_net_addrinfo_delete(&info);
    return result <= 0 ? result : -1;;
}

static int local_host_net(avs_net_abstract_socket_t *socket,
                          char *out_buffer, size_t out_buffer_size) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) socket;
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    errno = 0;
    if (!getsockname(net_socket->socket, &addr.addr, &addrlen)) {
        (void)unmap_v4mapped(&addr);
        int result = get_string_ip(&addr, out_buffer, out_buffer_size);
        net_socket->error_code = (result ? ERANGE : 0);
        return result;
    } else {
        net_socket->error_code = errno;
        return -1;
    }
}

static int local_port_net(avs_net_abstract_socket_t *socket,
                          char *out_buffer, size_t out_buffer_size) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) socket;
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    errno = 0;
    if (!getsockname(net_socket->socket, &addr.addr, &addrlen)) {
        int result = get_string_port(&addr, out_buffer, out_buffer_size);
        net_socket->error_code = (result ? ERANGE : 0);
        return result;
    } else {
        net_socket->error_code = errno;
        return -1;
    }
}

static int get_mtu(avs_net_socket_t *net_socket, int *out_mtu) {
    if (net_socket->configuration.forced_mtu > 0) {
        *out_mtu = net_socket->configuration.forced_mtu;
        return 0;
    }

    int mtu = -1, retval = -1;
    socklen_t dummy = sizeof(mtu);
    switch (get_socket_family(net_socket->socket)) {
#if defined(WITH_IPV4) && defined(IP_MTU)
    case AF_INET:
        errno = 0;
        retval = getsockopt(net_socket->socket, IPPROTO_IP, IP_MTU,
                            &mtu, &dummy);
        net_socket->error_code = errno;
        break;
#endif /* defined(WITH_IPV4) && defined(IP_MTU) */

#if defined(WITH_IPV6) && defined(IPV6_MTU)
    case AF_INET6:
        errno = 0;
        retval = getsockopt(net_socket->socket, IPPROTO_IPV6, IPV6_MTU,
                            &mtu, &dummy);
        net_socket->error_code = errno;
        break;
#endif /* defined(WITH_IPV6) && defined(IPV6_MTU) */

    default:
        (void) dummy;
        net_socket->error_code = EINVAL;
        retval = -1;
    }
    if (retval < 0 || mtu < 0) {
        return -1;
    } else {
        *out_mtu = mtu;
        return 0;
    }
}

static int get_fallback_inner_mtu(avs_net_socket_t *socket) {
    assert(socket->socket >= 0);
#ifdef WITH_IPV6
    if (get_connection_family(socket->socket) == AF_INET6) { /* IPv6 */
        return 1232; /* 1280 - 48 */
    } else
#endif
    { /* probably IPv4 */
        (void) socket;
        return 548; /* 576 - 28 */
    }
}

static int get_udp_overhead(avs_net_socket_t *net_socket, int *out) {
    net_socket->error_code = 0;
    switch (get_socket_family(net_socket->socket)) {
#ifdef WITH_IPV4
    case AF_INET:
        *out = 28; /* 20 for IP + 8 for UDP */
        return 0;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
    case AF_INET6:
        *out = 48; /* 40 for IPv6 + 8 for UDP */
        return 0;
#endif /* WITH_IPV6 */

    default:
        net_socket->error_code = EINVAL;
        return -1;
    }
}

static int get_inner_mtu(avs_net_socket_t *net_socket, int *out_mtu) {
    if (net_socket->type != AVS_NET_UDP_SOCKET) {
        LOG(ERROR,
            "get_opt_net: inner MTU calculation unimplemented for TCP");
        return -1;
    }
    if (!get_mtu(net_socket, out_mtu)) {
        int retval, udp_overhead;
        if ((retval = get_udp_overhead(net_socket, &udp_overhead))) {
            return retval;
        }
        *out_mtu -= udp_overhead;
        if (*out_mtu < 0) {
            *out_mtu = 0;
        }
    } else {
        net_socket->error_code = 0;
        *out_mtu = get_fallback_inner_mtu(net_socket);
    }
    return 0;
}

static int get_opt_net(avs_net_abstract_socket_t *net_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value) {
    avs_net_socket_t *net_socket = (avs_net_socket_t *) net_socket_;
    net_socket->error_code = 0;
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
        return get_mtu(net_socket, &out_option_value->mtu);
    case AVS_NET_SOCKET_OPT_INNER_MTU:
        return get_inner_mtu(net_socket, &out_option_value->mtu);
    default:
        LOG(ERROR, "get_opt_net: unknown or unsupported option key");
        net_socket->error_code = EINVAL;
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
        net_socket->error_code = 0;
        return 0;
    default:
        LOG(ERROR, "set_opt_net: unknown or unsupported option key");
        net_socket->error_code = EINVAL;
        return -1;
    }
}

static int errno_net(avs_net_abstract_socket_t *net_socket) {
    return ((avs_net_socket_t *) net_socket)->error_code;
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
#ifdef WITH_IPV4
        case AF_INET:
            offset = offsetof(struct sockaddr_in, sin_addr);
            length = 4;
            break;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
        case AF_INET6:
            offset = offsetof(struct sockaddr_in6, sin6_addr);
            length = 16;
            break;
#endif /* WITH_IPV6 */

        default:
            return -1;
    }

    return memcmp(((const char *) left) + offset,
                  ((const char *) right) + offset, length);
}

static int find_interface(const struct sockaddr *addr,
                          avs_net_socket_interface_name_t *if_name) {
#define TRY_ADDRESS(TriedAddr, TriedName) \
    do { \
        if ((TriedAddr) && (TriedName) \
                && ifaddr_ip_equal(addr, (TriedAddr)) == 0) { \
            retval = avs_simple_snprintf(*if_name, sizeof(*if_name), \
                                         "%s", (TriedName)) < 0 ? -1 : 0; \
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
        TRY_ADDRESS(ifaddr->ifa_addr, ifaddr->ifa_name);
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
    if (!(req = (struct ifreq *) realloc(reqs, blen))) {
        goto interface_name_end;
    } else {
        reqs = req;
    }
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
#else
    (void) addr;
    (void) if_name;
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
    } else {
        sockaddr_union_t addr;
        socklen_t addrlen = sizeof(addr);
        errno = 0;
        if (getsockname(socket->socket, &addr.addr, &addrlen)
                || find_interface(&addr.addr, if_name)) {
            socket->error_code = errno;
            return -1;
        }
    }
    socket->error_code = 0;
    return 0;
}

static int validate_ip_address(avs_net_af_t family, const char *ip_address) {
    union {
#ifdef WITH_IPV4
        struct in_addr sa4;
#endif /* WITH_IPV4 */

#ifdef WITH_IPV6
        struct in6_addr sa6;
#endif /* WITH_IPV6 */
    } sa;
    if (_avs_inet_pton(_avs_net_get_af(family), ip_address, &sa) < 1) {
        return -1;
    }
    return 0;
}

int avs_net_validate_ip_address(avs_net_af_t family, const char *ip_address) {
    if ((IPV4_AVAILABLE && (family == AVS_NET_AF_INET4))
            || ((IPV6_AVAILABLE && (family == AVS_NET_AF_INET6)))) {
        return validate_ip_address(family, ip_address);
    } else {
        return ((IPV4_AVAILABLE
                    && (validate_ip_address(AVS_NET_AF_INET4, ip_address) == 0))
                || (IPV6_AVAILABLE
                    && (validate_ip_address(AVS_NET_AF_INET6, ip_address) == 0)))
               ? 0 : -1;
    }
}

int avs_net_resolved_endpoint_get_host_port(
        const avs_net_resolved_endpoint_t *endp,
        char *host, size_t hostlen,
        char *serv, size_t servlen) {
    return host_port_to_string((const struct sockaddr *) &endp->data,
                               endp->size,
                               host, (socklen_t) hostlen,
                               serv, (socklen_t) servlen);
}

int avs_net_resolved_endpoint_get_host(const avs_net_resolved_endpoint_t *endp,
                                       char *host, size_t hostlen) {
    return avs_net_resolved_endpoint_get_host_port(endp,
                                                   host, hostlen, NULL, 0);
}
