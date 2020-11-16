/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/avs_commons_config.h>

#if defined(AVS_COMMONS_WITH_AVS_NET) \
        && defined(AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET)

#    include <avs_commons_posix_init.h>

#    include <errno.h>

#    include <avsystem/commons/avs_errno_map.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_utils.h>

#    include <assert.h>
#    include <inttypes.h>
#    include <stdarg.h>
#    include <stdio.h>
#    include <string.h>
#    include <time.h>

#    ifdef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETIFADDRS
#        include <ifaddrs.h>
#    endif

#    include "avs_compat.h"

VISIBILITY_SOURCE_BEGIN

#    ifndef INET_ADDRSTRLEN
#        define INET_ADDRSTRLEN 16
#    endif

#    ifdef AVS_COMMONS_NET_WITH_IPV4
#        define IPV4_AVAILABLE 1
#    else
#        define IPV4_AVAILABLE 0
#    endif

#    ifdef AVS_COMMONS_NET_WITH_IPV6
#        define IPV6_AVAILABLE 1
#    else
#        define IPV6_AVAILABLE 0
#    endif

static const avs_time_duration_t NET_SEND_TIMEOUT = { 30, 0 };
static const avs_time_duration_t NET_CONNECT_TIMEOUT = { 10, 0 };
static const avs_time_duration_t NET_ACCEPT_TIMEOUT = { 5, 0 };

#    define NET_LISTEN_BACKLOG 1024

#    ifdef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_INET_NTOP
#        define _avs_inet_ntop inet_ntop
#    else
const char *_avs_inet_ntop(int af, const void *src, char *dst, socklen_t size);
#    endif

typedef union {
    struct sockaddr addr;
    struct sockaddr_storage addr_storage;

#    ifdef AVS_COMMONS_NET_WITH_IPV4
    struct sockaddr_in addr_in;
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */

#    ifdef AVS_COMMONS_NET_WITH_IPV6
    struct sockaddr_in6 addr_in6;
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */
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
                              .header = {
                                  .size = 0
                              }
                          })
                                 .header.size)
                          == sizeof(((avs_net_resolved_endpoint_t) {
                                         .size = 0
                                     })
                                            .size),
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

typedef enum {
    PREFERRED_FAMILY_ONLY,
    PREFERRED_FAMILY_BLOCKED
} preferred_family_mode_t;

static avs_error_t
connect_net(avs_net_socket_t *net_socket, const char *host, const char *port);
static avs_error_t send_net(avs_net_socket_t *net_socket,
                            const void *buffer,
                            size_t buffer_length);
static avs_error_t send_to_net(avs_net_socket_t *socket,
                               const void *buffer,
                               size_t buffer_length,
                               const char *host,
                               const char *port);
static avs_error_t receive_net(avs_net_socket_t *net_socket_,
                               size_t *out,
                               void *buffer,
                               size_t buffer_length);
static avs_error_t receive_from_net(avs_net_socket_t *net_socket,
                                    size_t *out,
                                    void *message_buffer,
                                    size_t buffer_size,
                                    char *host,
                                    size_t host_size,
                                    char *port,
                                    size_t port_size);
static avs_error_t
bind_net(avs_net_socket_t *net_socket, const char *localaddr, const char *port);
static avs_error_t accept_net(avs_net_socket_t *server_net_socket,
                              avs_net_socket_t *new_net_socket);
static avs_error_t close_net(avs_net_socket_t *net_socket);
static avs_error_t shutdown_net(avs_net_socket_t *net_socket);
static avs_error_t cleanup_net(avs_net_socket_t **net_socket);
static const void *system_socket_net(avs_net_socket_t *net_socket);
static avs_error_t interface_name_net(avs_net_socket_t *socket,
                                      avs_net_socket_interface_name_t *if_name);
static avs_error_t remote_host_net(avs_net_socket_t *socket,
                                   char *out_buffer,
                                   size_t out_buffer_size);
static avs_error_t remote_hostname_net(avs_net_socket_t *socket,
                                       char *out_buffer,
                                       size_t out_buffer_size);
static avs_error_t remote_port_net(avs_net_socket_t *socket,
                                   char *out_buffer,
                                   size_t out_buffer_size);
static avs_error_t local_host_net(avs_net_socket_t *socket,
                                  char *out_buffer,
                                  size_t out_buffer_size);
static avs_error_t local_port_net(avs_net_socket_t *socket,
                                  char *out_buffer,
                                  size_t out_buffer_size);
static avs_error_t get_opt_net(avs_net_socket_t *net_socket,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t *out_option_value);
static avs_error_t set_opt_net(avs_net_socket_t *net_socket,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t option_value);

static const avs_net_socket_v_table_t net_vtable = {
    .connect = connect_net,
    .send = send_net,
    .send_to = send_to_net,
    .receive = receive_net,
    .receive_from = receive_from_net,
    .bind = bind_net,
    .accept = accept_net,
    .close = close_net,
    .shutdown = shutdown_net,
    .cleanup = cleanup_net,
    .get_system_socket = system_socket_net,
    .get_interface_name = interface_name_net,
    .get_remote_host = remote_host_net,
    .get_remote_hostname = remote_hostname_net,
    .get_remote_port = remote_port_net,
    .get_local_host = local_host_net,
    .get_local_port = local_port_net,
    .get_opt = get_opt_net,
    .set_opt = set_opt_net
};

typedef struct {
    const avs_net_socket_v_table_t *const operations;
    sockfd_t socket;
    avs_net_socket_type_t type;
    avs_net_socket_state_t state;
    char remote_hostname[NET_MAX_HOSTNAME_SIZE];
    char remote_port[NET_PORT_SIZE];
    avs_net_socket_configuration_t configuration;

    uint64_t bytes_received;
    uint64_t bytes_sent;

    avs_time_duration_t recv_timeout;
} net_socket_impl_t;

#    if defined(AVS_COMMONS_NET_WITH_IPV4) && defined(AVS_COMMONS_NET_WITH_IPV6)
static bool is_v4mapped(const struct sockaddr_in6 *addr) {
#        ifdef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_IN6_IS_ADDR_V4MAPPED
    return IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr);
#        else
    static const uint8_t V4MAPPED_ADDR_HEADER[] = { 0, 0, 0, 0, 0,    0,
                                                    0, 0, 0, 0, 0xFF, 0xFF };
    return memcmp(addr->sin6_addr.s6_addr, V4MAPPED_ADDR_HEADER,
                  sizeof(V4MAPPED_ADDR_HEADER))
           == 0;
#        endif
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
#    else // defined(AVS_COMMONS_NET_WITH_IPV4) &&
          // defined(AVS_COMMONS_NET_WITH_IPV6)
#        define unmap_v4mapped(Addr) (-1)
#    endif // defined(AVS_COMMONS_NET_WITH_IPV4) &&
           // defined(AVS_COMMONS_NET_WITH_IPV6)

static const char *get_af_name(avs_net_af_t af) {
    switch (af) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
    case AVS_NET_AF_INET4:
        return "AF_INET";
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */

#    ifdef AVS_COMMONS_NET_WITH_IPV6
    case AVS_NET_AF_INET6:
        return "AF_INET6";
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

    case AVS_NET_AF_UNSPEC:
    default:
        return "AF_UNSPEC";
    }
}

static avs_error_t failure_from_errno(void) {
    avs_errno_t err = avs_map_errno(errno);
    if (err == AVS_NO_ERROR) {
        err = AVS_UNKNOWN_ERROR;
    }
    return avs_errno(err);
}

static avs_error_t
get_string_ip(const sockaddr_union_t *addr, char *buffer, size_t buffer_size) {
    const void *addr_data;
    socklen_t addrlen;

    switch (addr->addr.sa_family) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
    case AF_INET:
        addr_data = &addr->addr_in.sin_addr;
        addrlen = INET_ADDRSTRLEN;
        break;
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */

#    ifdef AVS_COMMONS_NET_WITH_IPV6
    case AF_INET6:
        addr_data = &addr->addr_in6.sin6_addr;
        addrlen = INET6_ADDRSTRLEN;
        break;
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

    default:
        return avs_errno(AVS_ERANGE);
    }

    if (buffer_size < (size_t) addrlen) {
        return avs_errno(AVS_ERANGE);
    } else if (_avs_inet_ntop(addr->addr.sa_family, addr_data, buffer, addrlen)
               == NULL) {
        return failure_from_errno();
    } else {
        return AVS_OK;
    }
}

static int get_string_port(const sockaddr_union_t *addr,
                           char *buffer,
                           size_t buffer_size) {
    uint16_t port;
    switch (addr->addr.sa_family) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
    case AF_INET:
        port = addr->addr_in.sin_port;
        break;
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */

#    ifdef AVS_COMMONS_NET_WITH_IPV6
    case AF_INET6:
        port = addr->addr_in6.sin6_port;
        break;
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

    default:
        return -1;
    }

    return avs_simple_snprintf(buffer, buffer_size, "%u", ntohs(port)) < 0 ? -1
                                                                           : 0;
}

static avs_error_t remote_host_net(avs_net_socket_t *socket,
                                   char *out_buffer,
                                   size_t out_buffer_size) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) socket;
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    errno = 0;
    if (!getpeername(net_socket->socket, &addr.addr, &addrlen)) {
        (void) unmap_v4mapped(&addr);
        return get_string_ip(&addr, out_buffer, out_buffer_size);
    } else {
        return failure_from_errno();
    }
}

static avs_error_t remote_hostname_net(avs_net_socket_t *socket_,
                                       char *out_buffer,
                                       size_t out_buffer_size) {
    net_socket_impl_t *socket = (net_socket_impl_t *) socket_;
    if (!socket->remote_hostname[0]) {
        return avs_errno(socket->socket == INVALID_SOCKET ? AVS_EBADF
                                                          : AVS_ENOBUFS);
    }
    if (avs_simple_snprintf(out_buffer, out_buffer_size, "%s",
                            socket->remote_hostname)
            < 0) {
        return avs_errno(AVS_ERANGE);
    } else {
        return AVS_OK;
    }
}

static avs_error_t remote_port_net(avs_net_socket_t *socket_,
                                   char *out_buffer,
                                   size_t out_buffer_size) {
    net_socket_impl_t *socket = (net_socket_impl_t *) socket_;
    if (!socket->remote_port[0]) {
        return avs_errno(socket->socket == INVALID_SOCKET ? AVS_EBADF
                                                          : AVS_ENOBUFS);
    }
    if (avs_simple_snprintf(out_buffer, out_buffer_size, "%s",
                            socket->remote_port)
            < 0) {
        return avs_errno(AVS_ERANGE);
    } else {
        return AVS_OK;
    }
}

static const void *system_socket_net(avs_net_socket_t *net_socket_) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    if (net_socket->socket != INVALID_SOCKET) {
        return &net_socket->socket;
    } else {
        return NULL;
    }
}

static void close_net_raw(net_socket_impl_t *net_socket) {
    if (net_socket->socket != INVALID_SOCKET) {
        close(net_socket->socket);
        net_socket->socket = INVALID_SOCKET;
        net_socket->state = AVS_NET_SOCKET_STATE_CLOSED;
    }
    net_socket->remote_hostname[0] = '\0';
    net_socket->remote_port[0] = '\0';
}

static avs_error_t close_net(avs_net_socket_t *net_socket_) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    close_net_raw(net_socket);
    return AVS_OK;
}

static avs_error_t cleanup_net(avs_net_socket_t **net_socket) {
    close_net(*net_socket);
    avs_free(*net_socket);
    *net_socket = NULL;
    return AVS_OK;
}

static avs_error_t shutdown_net(avs_net_socket_t *net_socket_) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    int retval;
    errno = 0;
    retval = shutdown(net_socket->socket, SHUT_RDWR);
    net_socket->state = AVS_NET_SOCKET_STATE_SHUTDOWN;
    return retval ? failure_from_errno() : AVS_OK;
}

static sa_family_t get_socket_family(sockfd_t fd) {
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    if (!getsockname(fd, &addr.addr, &addrlen)) {
        return addr.addr.sa_family;
    } else {
        return AF_UNSPEC;
    }
}

#    ifdef AVS_COMMONS_NET_WITH_IPV6
/**
 * Differs from get_socket_family() by the fact that if the socket is AF_INET6
 * at the kernel level, but is connected to an IPv4-mapped address, it returns
 * AF_INET.
 */
static sa_family_t get_connection_family(sockfd_t fd) {
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    if (getpeername(fd, &addr.addr, &addrlen)) {
        return get_socket_family(fd);
#        if defined(AVS_COMMONS_NET_WITH_IPV4) \
                && defined(AVS_COMMONS_NET_WITH_IPV6)
    } else if (addr.addr.sa_family == AF_INET6 && is_v4mapped(&addr.addr_in6)) {
        return AF_INET;
#        endif
    } else {
        return addr.addr.sa_family;
    }
}
#    endif // AVS_COMMONS_NET_WITH_IPV6

#    if !defined(IP_TRANSPARENT) && defined(__linux__)
#        define IP_TRANSPARENT 19
#    endif

#    if !defined(IPV6_TRANSPARENT) && defined(__linux__)
#        define IPV6_TRANSPARENT 75
#    endif

static avs_error_t configure_socket(net_socket_impl_t *net_socket) {
    errno = 0;
    LOG(TRACE, _("configuration '") "%s" _("' 0x") "%02x" _(" 0x") "%02x",
        net_socket->configuration.interface_name,
        net_socket->configuration.dscp, net_socket->configuration.priority);
    if (fcntl(net_socket->socket, F_SETFL, O_NONBLOCK) == -1) {
        avs_error_t err = failure_from_errno();
        LOG(ERROR,
            _("Could not switch socket to non-blocking mode (fcntl "
              "error: ") "%s" _(")"),
            avs_strerror((avs_errno_t) err.code));
        return err;
    }
    if (net_socket->configuration.interface_name[0]) {
        if (setsockopt(net_socket->socket, SOL_SOCKET, SO_BINDTODEVICE,
                       net_socket->configuration.interface_name,
                       (socklen_t) strlen(
                               net_socket->configuration.interface_name))) {
            avs_error_t err = failure_from_errno();
            LOG(ERROR, _("setsockopt error: ") "%s",
                avs_strerror((avs_errno_t) err.code));
            return err;
        }
    }
    if (net_socket->configuration.priority) {
        /* SO_PRIORITY accepts int as argument */
        int priority = net_socket->configuration.priority;
        socklen_t length = sizeof(priority);
        if (setsockopt(net_socket->socket, SOL_SOCKET, SO_PRIORITY, &priority,
                       length)) {
            avs_error_t err = failure_from_errno();
            LOG(ERROR, _("setsockopt error: ") "%s",
                avs_strerror((avs_errno_t) err.code));
            return err;
        }
    }
    if (net_socket->configuration.dscp) {
#    ifdef IP_TOS
        uint8_t tos;
        socklen_t length = sizeof(tos);
        if (getsockopt(net_socket->socket, IPPROTO_IP, IP_TOS, &tos, &length)) {
            avs_error_t err = failure_from_errno();
            LOG(ERROR, _("getsockopt error: ") "%s",
                avs_strerror((avs_errno_t) err.code));
            return err;
        }
        tos &= 0x03; /* clear first 6 bits */
        tos |= (uint8_t) (net_socket->configuration.dscp << 2);
        if (setsockopt(net_socket->socket, IPPROTO_IP, IP_TOS, &tos, length)) {
            avs_error_t err = failure_from_errno();
            LOG(ERROR, _("setsockopt error: ") "%s",
                avs_strerror((avs_errno_t) err.code));
            return err;
        }
#    else  // IP_TOS
        return avs_errno(AVS_EINVAL);
#    endif // IP_TOS
    }
    if (net_socket->configuration.transparent) {
        int value = 1;
        int retval = -1;
        errno = EINVAL;
        switch (get_socket_family(net_socket->socket)) {
#    if defined(AVS_COMMONS_NET_WITH_IPV4) && defined(IP_TRANSPARENT)
        case AF_INET:
            retval = setsockopt(net_socket->socket, SOL_IP, IP_TRANSPARENT,
                                &value, sizeof(value));
            break;
#    endif /* defined(AVS_COMMONS_NET_WITH_IPV4) && defined(IP_TRANSPARENT) */

#    if defined(AVS_COMMONS_NET_WITH_IPV6) && defined(IPV6_TRANSPARENT)
        case AF_INET6:
            retval = setsockopt(net_socket->socket, SOL_IPV6, IPV6_TRANSPARENT,
                                &value, sizeof(value));
            break;
#    endif /* defined(AVS_COMMONS_NET_WITH_IPV6) && defined(IPV6_TRANSPARENT) \
            */

        default:
            (void) value;
            errno = EINVAL;
            break;
        }

        if (retval) {
            return failure_from_errno();
        }
    }

    return AVS_OK;
}

// These are flags intended to be passed to wait_until_ready() family's
// flags argument.
#    define AVS_POLLIN (1 << 0)
#    define AVS_POLLOUT (1 << 1)
// NOTE: Passing AVS_POLLERR will cause an actual POLLERR condition to be
// treated as success. The inteded use case is so that such call will be
// immediately followed (directly or using call_when_ready() by some other
// socket call, that will return the actual error.
#    define AVS_POLLERR (1 << 2)

static avs_error_t wait_until_ready_internal(sockfd_t sockfd,
                                             avs_time_duration_t timeout,
                                             int flags) {
#    ifdef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_POLL
    struct pollfd p;
    short events = 0;
    if (flags & AVS_POLLIN) {
        events = (short) (events | POLLIN);
    }
    if (flags & AVS_POLLOUT) {
        events = (short) (events | POLLOUT);
    }
    p.fd = sockfd;
    p.events = events;
    p.revents = 0;
    int64_t timeout_ms;
    if (avs_time_duration_to_scalar(&timeout_ms, AVS_TIME_MS, timeout)
            || timeout_ms > INT_MAX) {
        timeout_ms = -1;
    } else if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    errno = 0;
    int result = poll(&p, 1, (int) timeout_ms);
    if (result == 0) {
        return avs_errno(AVS_ETIMEDOUT);
    }
    if (result != 1) {
        return failure_from_errno();
    }
    if (flags & AVS_POLLERR) {
        events = (short) (events | POLLHUP | POLLERR);
    }
    if (p.revents & events) {
        return avs_errno(AVS_NO_ERROR);
    } else if (p.revents & POLLHUP) {
        return avs_errno(AVS_ECONNRESET);
    } else {
        return avs_errno(AVS_ECONNABORTED);
    }
#    else
    fd_set infds;
    fd_set outfds;
    fd_set errfds;
    struct timeval timeval_timeout;
    if (timeout.seconds < 0) {
        timeval_timeout.tv_sec = 0;
        timeval_timeout.tv_usec = 0;
    } else {
        // When LWIP_TIMEVAL_PRIVATE is used, the timeval::tv_sec is long
        // even though it normally should be time_t. Separate cast is
        // added to avoid any kind of implicit conversion warnings.
#        if LWIP_TIMEVAL_PRIVATE
        timeval_timeout.tv_sec = (long) timeout.seconds;
#        else
        timeval_timeout.tv_sec = (time_t) timeout.seconds;
#        endif // LWIP_TIMEVAL_PRIVATE
        timeval_timeout.tv_usec = timeout.nanoseconds / 1000;
    }
    FD_ZERO(&infds);
    FD_ZERO(&outfds);
    FD_ZERO(&errfds);

#        ifdef AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
// LwIP implementation of FD_SET (and others) is a bit clumsy. No matter what we
// do, it finally assigns an `int` to the `unsigned char`, which GCC really
// doesn't like.
#            pragma GCC diagnostic ignored "-Wconversion"
#        endif // AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
#        if LWIP_VERSION_MAJOR < 2
// LwIP < 2.0 lacks cast to unsigned inside FD_* macros
#            define AVS_FD_SET(fd, set) FD_SET((unsigned) (fd), (set))
#            define AVS_FD_ISSET(fd, set) FD_ISSET((unsigned) (fd), (set))
#        else
#            define AVS_FD_SET FD_SET
#            define AVS_FD_ISSET FD_ISSET
#        endif // LWIP_VERSION_MAJOR < 2

    if (flags & AVS_POLLIN) {
        AVS_FD_SET(sockfd, &infds);
    }
    if (flags & AVS_POLLOUT) {
        AVS_FD_SET(sockfd, &outfds);
    }
    AVS_FD_SET(sockfd, &errfds);
    errno = 0;
    int result =
            select(sockfd + 1, &infds, &outfds, &errfds,
                   avs_time_duration_valid(timeout) ? &timeval_timeout : NULL);
    if (result == 0) {
        return avs_errno(AVS_ETIMEDOUT);
    }
    if (result < 0) {
        return failure_from_errno();
    }
    return avs_errno(
            (((flags & AVS_POLLERR) && AVS_FD_ISSET(sockfd, &errfds))
             || ((flags & AVS_POLLIN) && AVS_FD_ISSET(sockfd, &infds))
             || ((flags & AVS_POLLOUT) && AVS_FD_ISSET(sockfd, &outfds)))
                    ? AVS_NO_ERROR
                    : AVS_ECONNABORTED);
#        undef AVS_FD_SET
#        undef AVS_FD_ISSET

#        ifdef AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
#            pragma GCC diagnostic pop
#        endif // AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC

#    endif
}

static avs_error_t wait_until_ready(const volatile sockfd_t *sockfd_ptr,
                                    avs_time_monotonic_t deadline,
                                    int flags) {
    avs_error_t error;
    do {
        sockfd_t sockfd = *sockfd_ptr;
        if (sockfd == INVALID_SOCKET) {
            // socket might have been closed in signal handler
            // or something like this
            return avs_errno(AVS_EBADF);
        }

        error = wait_until_ready_internal(
                sockfd,
                avs_time_monotonic_diff(deadline, avs_time_monotonic_now()),
                flags);
    } while (error.category == AVS_ERRNO_CATEGORY
             && (error.code == AVS_EINTR || error.code == AVS_EAGAIN));

    return error;
}

typedef avs_error_t call_when_ready_cb_t(sockfd_t sockfd, void *arg);

static avs_error_t call_when_ready(const volatile sockfd_t *sockfd_ptr,
                                   avs_time_duration_t timeout,
                                   int flags,
                                   call_when_ready_cb_t *callback,
                                   void *callback_arg) {
    avs_error_t error;
    avs_time_monotonic_t deadline =
            avs_time_monotonic_add(avs_time_monotonic_now(), timeout);
    while (avs_is_ok((error = wait_until_ready(sockfd_ptr, deadline, flags)))) {
        do {
            sockfd_t sockfd = *sockfd_ptr;
            if (sockfd == INVALID_SOCKET) {
                // socket might have been closed in signal handler
                // or something like this
                error = avs_errno(AVS_EBADF);
            } else {
                error = callback(sockfd, callback_arg);
            }
        } while (error.category == AVS_ERRNO_CATEGORY && error.code == AVS_EINTR
                 && !avs_time_monotonic_before(deadline,
                                               avs_time_monotonic_now()));
        if (error.category != AVS_ERRNO_CATEGORY || error.code != AVS_EAGAIN) {
            // AVS_EAGAIN might signify a false positive result from
            // wait_until_ready(); this might happen e.g. if poll() returned an
            // event when the kernel saw incoming data, but the data turned out
            // to have e.g. wrong checksum and were discarded later - this is
            // basically a spurious wakeup; in such case, try again;
            // otherwise, return.
            // NOTE: Both EAGAIN and EWOULDBLOCK map onto AVS_EAGAIN. These
            // constants are allowed to be equivalent, so we coerce them in
            // avs_errno_t for simplicity.
            break;
        }
    }
    return error;
}

static avs_error_t
connect_with_timeout(const volatile sockfd_t *sockfd_ptr,
                     const sockaddr_endpoint_union_t *endpoint) {
    if (connect(*sockfd_ptr, &endpoint->sockaddr_ep.addr,
                endpoint->sockaddr_ep.header.size)
                    == -1
            && errno != EINPROGRESS) { // see man connect for details
        return failure_from_errno();
    }
    avs_time_monotonic_t deadline =
            avs_time_monotonic_add(avs_time_monotonic_now(),
                                   NET_CONNECT_TIMEOUT);
    avs_error_t err =
            wait_until_ready(sockfd_ptr, deadline, AVS_POLLIN | AVS_POLLOUT);
    if (avs_is_err(err)) {
        int error_code = 0;
        socklen_t length = sizeof(error_code);
        if (!getsockopt(*sockfd_ptr, SOL_SOCKET, SO_ERROR, &error_code, &length)
                && error_code) {
            err = avs_errno(avs_map_errno(error_code));
        }
    }
    return err;
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

#    ifndef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETNAMEINFO
static avs_error_t get_host_port_ptr(const struct sockaddr *sa,
                                     socklen_t salen,
                                     const void **out_addr_ptr,
                                     const uint16_t **out_port_ptr) {
    switch (sa->sa_family) {
#        ifdef AVS_COMMONS_NET_WITH_IPV4
    case AF_INET:
        if (salen >= sizeof(struct sockaddr_in)) {
            *out_addr_ptr = &((const struct sockaddr_in *) sa)->sin_addr;
            *out_port_ptr = &((const struct sockaddr_in *) sa)->sin_port;
            return AVS_OK;
        } else {
            LOG(ERROR,
                _("malformed IPv4 address (too short: got ") "%uB" _(
                        ", expected >= ") "%uB" _(")"),
                (unsigned) salen, (unsigned) sizeof(struct sockaddr_in));
            return avs_errno(AVS_EINVAL);
        }
#        endif /* AVS_COMMONS_NET_WITH_IPV4 */

#        ifdef AVS_COMMONS_NET_WITH_IPV6
    case AF_INET6:
        if (salen >= sizeof(struct sockaddr_in6)) {
            *out_addr_ptr = &((const struct sockaddr_in6 *) sa)->sin6_addr;
            *out_port_ptr = &((const struct sockaddr_in6 *) sa)->sin6_port;
            return AVS_OK;
        } else {
            LOG(ERROR,
                _("malformed IPv6 address (too short: got ") "%uB" _(
                        ", expected >= ") "%uB" _(")"),
                (unsigned) salen, (unsigned) sizeof(struct sockaddr_in6));
            return avs_errno(AVS_EINVAL);
        }
#        endif /* AVS_COMMONS_NET_WITH_IPV6 */

    default:
        LOG(ERROR, _("unsupported socket family: ") "%d", (int) sa->sa_family);
        return avs_errno(AVS_ENOTSUP);
    }
}
#    endif /* AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETNAMEINFO */

static avs_error_t host_port_to_string_impl(const struct sockaddr *sa,
                                            socklen_t salen,
                                            char *host,
                                            socklen_t hostlen,
                                            char *serv,
                                            socklen_t servlen) {
#    ifdef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETNAMEINFO
    int result = getnameinfo(sa, salen, host, hostlen, serv, servlen,
                             NI_NUMERICHOST | NI_NUMERICSERV);
    if (result) {
        LOG(ERROR, _("getnameinfo() failed: ") "%s" _(" (") "%d" _(")"),
            avs_strerror(avs_map_errno(errno)), avs_map_errno(errno));
        return failure_from_errno();
    } else {
        return AVS_OK;
    }
#    else  /* AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETNAMEINFO */
    const void *addr_ptr = NULL;
    const uint16_t *port_ptr = NULL;
    avs_error_t err = get_host_port_ptr(sa, salen, &addr_ptr, &port_ptr);
    if (avs_is_err(err)) {
        return err;
    }

    if (host
            && _avs_inet_ntop(sa->sa_family, addr_ptr, host, hostlen) == NULL) {
        err = failure_from_errno();
        LOG(ERROR, _("could not stringify host (buf size ") "%u" _(")"),
            (unsigned) hostlen);
        return err;
    }
    if (serv
            && avs_simple_snprintf(serv, servlen, "%" PRIu16, ntohs(*port_ptr))
                           < 0) {
        LOG(ERROR,
            _("could not stringify port: ") "%u" _(" (buf size ") "%u" _(")"),
            ntohs(*port_ptr), (unsigned) servlen);
        return avs_errno(AVS_ERANGE);
    }

    return err;
#    endif /* AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETNAMEINFO */
}

static avs_error_t host_port_to_string(const struct sockaddr *sa,
                                       socklen_t salen,
                                       char *host,
                                       socklen_t hostlen,
                                       char *serv,
                                       socklen_t servlen) {
    avs_error_t err =
            host_port_to_string_impl(sa, salen, host, hostlen, serv, servlen);
    if (avs_is_ok(err) && host) {
        unwrap_4in6(host);
    }
    return err;
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

static int get_socket_proto(avs_net_socket_type_t socket_type) {
    switch (socket_type) {
    case AVS_NET_TCP_SOCKET:
    case AVS_NET_SSL_SOCKET:
        return IPPROTO_TCP;
    case AVS_NET_UDP_SOCKET:
    case AVS_NET_DTLS_SOCKET:
        return IPPROTO_UDP;
    default:
        return 0;
    }
}

static avs_net_af_t get_avs_af(int af) {
    switch (af) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
    case AF_INET:
        return AVS_NET_AF_INET4;
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */

#    ifdef AVS_COMMONS_NET_WITH_IPV6
    case AF_INET6:
        return AVS_NET_AF_INET6;
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

    default:
        return AVS_NET_AF_UNSPEC;
    }
}

static int get_other_family(avs_net_af_t *out, avs_net_af_t in) {
    (void) out;
    (void) in;
    switch (in) {
#    if defined(AVS_COMMONS_NET_WITH_IPV4) && defined(AVS_COMMONS_NET_WITH_IPV6)
    case AVS_NET_AF_INET4:
        *out = AVS_NET_AF_INET6;
        return 0;
    case AVS_NET_AF_INET6:
        *out = AVS_NET_AF_INET4;
        return 0;
#    endif // defined(AVS_COMMONS_NET_WITH_IPV4) &&
           // defined(AVS_COMMONS_NET_WITH_IPV6)
    default:
        return -1;
    }
}

static int get_requested_family(net_socket_impl_t *net_socket,
                                avs_net_af_t *out,
                                preferred_family_mode_t preferred_family_mode) {
    if (net_socket->configuration.address_family == AVS_NET_AF_UNSPEC) {
        // If we only have "soft" family preference,
        // use it as the preferred one, and later try the "opposite" setting
        avs_net_af_t preferred_family =
                net_socket->configuration.preferred_family;
        if (preferred_family == AVS_NET_AF_UNSPEC) {
#    ifdef AVS_COMMONS_NET_WITH_IPV6
            preferred_family = AVS_NET_AF_INET6;
#    elif defined(AVS_COMMONS_NET_WITH_IPV4)
            preferred_family = AVS_NET_AF_INET4;
#    else
            return -1;
#    endif
        }
        switch (preferred_family_mode) {
        case PREFERRED_FAMILY_ONLY:
            *out = preferred_family;
            return 0;
        case PREFERRED_FAMILY_BLOCKED:
            return get_other_family(out, preferred_family);
        }
    } else {
        // If we have "hard" address_family setting,
        // it is the preferred one, and there is nothing else
        switch (preferred_family_mode) {
        case PREFERRED_FAMILY_ONLY:
            *out = net_socket->configuration.address_family;
            return 0;
        case PREFERRED_FAMILY_BLOCKED:
            return -1;
        }
    }
    AVS_UNREACHABLE("Invalid value of preferred_family_mode");
    return -1;
}

static avs_net_addrinfo_t *
resolve_addrinfo_for_socket(net_socket_impl_t *net_socket,
                            const char *host,
                            const char *port,
                            bool use_preferred_endpoint,
                            preferred_family_mode_t preferred_family_mode) {
    int resolve_flags = AVS_NET_ADDRINFO_RESOLVE_F_NOADDRCONFIG;
    avs_net_af_t family = AVS_NET_AF_UNSPEC;
    if (get_requested_family(net_socket, &family, preferred_family_mode)) {
        return NULL;
    }

    assert(family != AVS_NET_AF_UNSPEC);
    if (net_socket->socket != INVALID_SOCKET) {
        avs_net_af_t socket_family =
                get_avs_af(get_socket_family(net_socket->socket));
        if (socket_family == AVS_NET_AF_INET6) {
            if (family != AVS_NET_AF_INET6) {
                // If we have an already created socket that is bound to IPv6,
                // but the requested family is something else, use v4-mapping
                resolve_flags |= AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED;
            }
        } else if (socket_family != AVS_NET_AF_UNSPEC
                   && socket_family != family) {
            // If we have an already created socket, we cannot use
            // IPv6-to-IPv4 mapping, and the requested family is different
            // than the socket's bound one - we're screwed, just give up
            return NULL;
        }
    }

    return avs_net_addrinfo_resolve_ex(
            net_socket->type, family, host, port, resolve_flags,
            use_preferred_endpoint
                    ? net_socket->configuration.preferred_endpoint
                    : NULL);
}

static avs_error_t
try_connect_open_socket(net_socket_impl_t *net_socket,
                        const sockaddr_endpoint_union_t *address) {
    bool socket_is_stream = (net_socket->type == AVS_NET_TCP_SOCKET);
    avs_error_t err;
    if (avs_is_err((err = connect_with_timeout(&net_socket->socket, address)))
            || (socket_is_stream
                && avs_is_err((err = send_net((avs_net_socket_t *) net_socket,
                                              NULL, 0))))) {
        return err;
    } else {
        /* SUCCESS */
        net_socket->state = AVS_NET_SOCKET_STATE_CONNECTED;
        /* store address affinity */
        if (net_socket->configuration.preferred_endpoint) {
            *net_socket->configuration.preferred_endpoint = address->api_ep;
        }
        return AVS_OK;
    }
}

static avs_error_t try_connect(net_socket_impl_t *net_socket,
                               const sockaddr_endpoint_union_t *address) {
    char socket_was_already_open = (net_socket->socket != INVALID_SOCKET);
    avs_error_t err = AVS_OK;
    if (!socket_was_already_open) {
        if ((net_socket->socket =
                     socket(address->sockaddr_ep.addr.sa_family,
                            _avs_net_get_socket_type(net_socket->type),
                            get_socket_proto(net_socket->type)))
                == INVALID_SOCKET) {
            err = failure_from_errno();
            LOG(ERROR, _("cannot create socket: ") "%s",
                avs_strerror((avs_errno_t) err.code));
        } else if (avs_is_err((err = configure_socket(net_socket)))) {
            LOG(WARNING, _("socket configuration problem"));
        }
    }
    if (avs_is_ok(err)) {
        err = try_connect_open_socket(net_socket, address);
    }
    if (avs_is_err(err) && !socket_was_already_open
            && net_socket->socket != INVALID_SOCKET) {
        close(net_socket->socket);
        net_socket->socket = INVALID_SOCKET;
    }
    return err;
}

static avs_error_t connect_impl(net_socket_impl_t *net_socket,
                                const char *host,
                                const char *port) {
    avs_net_addrinfo_t *info = NULL;

    if (net_socket->socket != INVALID_SOCKET) {
        if (net_socket->type != AVS_NET_UDP_SOCKET
                || net_socket->state != AVS_NET_SOCKET_STATE_BOUND) {
            LOG(ERROR, _("socket is already connected or bound"));
            return avs_errno(AVS_EISCONN);
        }
    }

    LOG(TRACE, _("connecting to [") "%s" _("]:") "%s", host, port);

    errno = 0;
    avs_error_t err = avs_errno(AVS_EADDRNOTAVAIL);
    if ((info = resolve_addrinfo_for_socket(net_socket, host, port, true,
                                            PREFERRED_FAMILY_ONLY))) {
        sockaddr_endpoint_union_t address;
        while (!avs_net_addrinfo_next(info, &address.api_ep)) {
            if (avs_is_ok((err = try_connect(net_socket, &address)))) {
                avs_net_addrinfo_delete(&info);
                return AVS_OK;
            }
        }
    }
    avs_net_addrinfo_delete(&info);
    if ((info = resolve_addrinfo_for_socket(net_socket, host, port, true,
                                            PREFERRED_FAMILY_BLOCKED))) {
        sockaddr_endpoint_union_t address;
        while (!avs_net_addrinfo_next(info, &address.api_ep)) {
            if (avs_is_ok((err = try_connect(net_socket, &address)))) {
                avs_net_addrinfo_delete(&info);
                return AVS_OK;
            }
        }
    }
    avs_net_addrinfo_delete(&info);
    LOG(ERROR, _("cannot establish connection to [") "%s" _("]:") "%s", host,
        port);
    assert(avs_is_err(err));
    return err;
}

static void cache_remote_hostname(net_socket_impl_t *net_socket,
                                  const char *remote_hostname) {
    if (avs_simple_snprintf(net_socket->remote_hostname,
                            sizeof(net_socket->remote_hostname), "%s",
                            remote_hostname)
            < 0) {
        LOG(WARNING, _("Remote hostname ") "%s" _(" is too long, not storing"),
            remote_hostname);
        net_socket->remote_hostname[0] = '\0';
    }
}

static void cache_remote_port(net_socket_impl_t *net_socket,
                              const char *remote_port) {
    if (avs_simple_snprintf(net_socket->remote_port,
                            sizeof(net_socket->remote_port), "%s", remote_port)
            < 0) {
        LOG(WARNING, _("Remote port ") "%s" _(" is too long, not storing"),
            remote_port);
        net_socket->remote_port[0] = '\0';
    }
}

static avs_error_t
connect_net(avs_net_socket_t *net_socket_, const char *host, const char *port) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    avs_error_t err = connect_impl(net_socket, host, port);
    if (avs_is_ok(err)) {
        cache_remote_hostname(net_socket, host);
        cache_remote_port(net_socket, port);
    }
    return err;
}

typedef struct {
    size_t bytes_sent;
    const char *data;
    size_t data_length;
} send_internal_arg_t;

static avs_error_t send_internal(sockfd_t sockfd, void *arg_) {
    send_internal_arg_t *arg = (send_internal_arg_t *) arg_;
    ssize_t result = send(sockfd, arg->data, arg->data_length, MSG_NOSIGNAL);
    if (result < 0) {
        return failure_from_errno();
    }
    arg->bytes_sent = (size_t) result;
    return AVS_OK;
}

static avs_error_t send_net(avs_net_socket_t *net_socket_,
                            const void *buffer,
                            size_t buffer_length) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    size_t bytes_sent = 0;
    send_internal_arg_t arg = {
        .bytes_sent = 0,
        .data = (const char *) buffer,
        .data_length = buffer_length
    };

    /* send at least one datagram, even if zero-length - hence do..while */
    do {
        avs_error_t err =
                call_when_ready(&net_socket->socket, NET_SEND_TIMEOUT,
                                AVS_POLLOUT | AVS_POLLERR, send_internal, &arg);
        if (avs_is_err(err)) {
            LOG(ERROR, _("send failed"));
            return err;
        } else if (buffer_length != 0 && arg.bytes_sent == 0) {
            LOG(ERROR, _("send returned 0"));
            break;
        } else {
            bytes_sent += arg.bytes_sent;
            net_socket->bytes_sent += bytes_sent;
            arg.data += arg.bytes_sent;
            arg.data_length -= arg.bytes_sent;
        }
        /* call send() multiple times only if the socket is stream-oriented */
    } while (net_socket->type == AVS_NET_TCP_SOCKET
             && bytes_sent < buffer_length);

    if (bytes_sent < buffer_length) {
        LOG(ERROR, _("sending fail (") "%lu" _("/") "%lu" _(")"),
            (unsigned long) bytes_sent, (unsigned long) buffer_length);
        return avs_errno(AVS_EIO);
    } else {
        return AVS_OK;
    }
}

typedef struct {
    const void *data;
    size_t data_length;
    const sockaddr_endpoint_union_t *dest_addr;
    size_t bytes_sent;
} send_to_internal_arg_t;

static avs_error_t send_to_internal(sockfd_t sockfd, void *arg_) {
    send_to_internal_arg_t *arg = (send_to_internal_arg_t *) arg_;
    ssize_t result = sendto(sockfd, arg->data, arg->data_length, MSG_NOSIGNAL,
                            &arg->dest_addr->sockaddr_ep.addr,
                            arg->dest_addr->sockaddr_ep.header.size);
    if (result < 0) {
        return failure_from_errno();
    }

    arg->bytes_sent = (size_t) result;

    if ((size_t) result != arg->data_length) {
        LOG(ERROR, _("send_to fail (") "%lu" _("/") "%lu" _(")"),
            (unsigned long) result, (unsigned long) arg->data_length);
        return avs_errno(AVS_EIO);
    } else {
        return AVS_OK;
    }
}

static avs_error_t send_to_resolved(net_socket_impl_t *net_socket,
                                    const void *buffer,
                                    size_t buffer_length,
                                    const sockaddr_endpoint_union_t *address) {
    send_to_internal_arg_t arg = {
        .data = buffer,
        .data_length = buffer_length,
        .dest_addr = address
    };

    avs_error_t err =
            call_when_ready(&net_socket->socket, NET_SEND_TIMEOUT,
                            AVS_POLLOUT | AVS_POLLERR, send_to_internal, &arg);
    net_socket->bytes_sent += arg.bytes_sent;
    return err;
}

static avs_error_t send_to_net(avs_net_socket_t *net_socket_,
                               const void *buffer,
                               size_t buffer_length,
                               const char *host,
                               const char *port) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    avs_net_addrinfo_t *info = NULL;

    avs_error_t err = avs_errno(AVS_EADDRNOTAVAIL);
    if ((info = resolve_addrinfo_for_socket(net_socket, host, port, false,
                                            PREFERRED_FAMILY_ONLY))) {
        sockaddr_endpoint_union_t address;
        while (!avs_net_addrinfo_next(info, &address.api_ep)) {
            err = send_to_resolved(net_socket, buffer, buffer_length, &address);
            if (err.category != AVS_ERRNO_CATEGORY
                    || err.code != AVS_ENETUNREACH) {
                avs_net_addrinfo_delete(&info);
                return err;
            }
        }
    }
    avs_net_addrinfo_delete(&info);
    if ((info = resolve_addrinfo_for_socket(net_socket, host, port, false,
                                            PREFERRED_FAMILY_BLOCKED))) {
        sockaddr_endpoint_union_t address;
        if (!avs_net_addrinfo_next(info, &address.api_ep)) {
            err = send_to_resolved(net_socket, buffer, buffer_length, &address);
            if (err.category != AVS_ERRNO_CATEGORY
                    || err.code != AVS_ENETUNREACH) {
                avs_net_addrinfo_delete(&info);
                return err;
            }
        }
    }
    avs_net_addrinfo_delete(&info);
    LOG(ERROR, _("cannot resolve address for sending: [") "%s" _("]:") "%s",
        host, port);
    assert(avs_is_err(err));
    return avs_errno(AVS_EADDRNOTAVAIL);
}

typedef struct {
    avs_net_socket_type_t socket_type;
    size_t bytes_received;
    void *buffer;
    size_t buffer_length;
    sockaddr_union_t *src_addr;
    socklen_t *src_addr_length;
} recvfrom_internal_arg_t;

#    ifndef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_RECVMSG

/* (2017-01-03) LwIP does not implement recvmsg call, try to simulate it using
 * plain recv(), with a little hack to try to detect truncated packets. */
static avs_error_t recvfrom_internal(sockfd_t sockfd, void *arg_) {
    recvfrom_internal_arg_t *arg = (recvfrom_internal_arg_t *) arg_;
    if (arg->src_addr_length && arg->src_addr) {
        *arg->src_addr_length = (socklen_t) sizeof(*arg->src_addr);
    }

    errno = 0;
    ssize_t recv_out =
            recvfrom(sockfd, arg->buffer, arg->buffer_length, MSG_NOSIGNAL,
                     arg->src_addr ? &arg->src_addr->addr : NULL,
                     arg->src_addr_length);

    if (arg->socket_type == AVS_NET_UDP_SOCKET && recv_out > 0
            && (size_t) recv_out == arg->buffer_length) {
        /* Buffer entirely filled - data possibly truncated. This will
         * incorrectly reject packets that have exactly buffer_length
         * bytes, but we have no means of distinguishing the edge case
         * without recvmsg.
         * This does only apply to datagram sockets (in our case: UDP). */
        arg->bytes_received = arg->buffer_length;
        return avs_errno(AVS_EMSGSIZE);
    } else if (recv_out < 0) {
        arg->bytes_received = 0;
        return failure_from_errno();
    } else {
        arg->bytes_received = (size_t) recv_out;
        return AVS_OK;
    }
}

#    else /* AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_RECVMSG */

static avs_error_t recvfrom_internal(sockfd_t sockfd, void *arg_) {
    recvfrom_internal_arg_t *arg = (recvfrom_internal_arg_t *) arg_;
    ssize_t recv_out;
    struct iovec iov = {
        .iov_base = arg->buffer,
        .iov_len = arg->buffer_length
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    if (arg->src_addr) {
        msg.msg_name = &arg->src_addr->addr;
        msg.msg_namelen = (socklen_t) sizeof(*arg->src_addr);
    }

    errno = 0;
    recv_out = recvmsg(sockfd, &msg, 0);

    if (arg->src_addr_length) {
        *arg->src_addr_length = msg.msg_namelen;
    }
    if (msg.msg_flags & MSG_TRUNC) {
        /* message too long to fit in the buffer */
        arg->bytes_received = AVS_MIN((size_t) recv_out, arg->buffer_length);
        return avs_errno(AVS_EMSGSIZE);
    } else if (recv_out < 0) {
        arg->bytes_received = 0;
        return failure_from_errno();
    } else {
        arg->bytes_received = (size_t) recv_out;
        return AVS_OK;
    }
}

#    endif /* AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_RECVMSG */

static avs_error_t receive_net(avs_net_socket_t *net_socket_,
                               size_t *out,
                               void *buffer,
                               size_t buffer_length) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    recvfrom_internal_arg_t arg = {
        .socket_type = net_socket->type,
        .buffer = buffer,
        .buffer_length = buffer_length
    };
    avs_error_t err =
            call_when_ready(&net_socket->socket, net_socket->recv_timeout,
                            AVS_POLLIN | AVS_POLLERR, recvfrom_internal, &arg);
    *out = arg.bytes_received;
    net_socket->bytes_received += arg.bytes_received;
    return err;
}

static avs_error_t receive_from_net(avs_net_socket_t *net_socket_,
                                    size_t *out,
                                    void *message_buffer,
                                    size_t buffer_size,
                                    char *host,
                                    size_t host_size,
                                    char *port,
                                    size_t port_size) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;

    assert(host);
    assert(port);
    host[0] = '\0';
    port[0] = '\0';

    sockaddr_union_t src_addr;
    socklen_t src_addr_length = 0;
    recvfrom_internal_arg_t arg = {
        .socket_type = net_socket->type,
        .buffer = message_buffer,
        .buffer_length = buffer_size,
        .src_addr = &src_addr,
        .src_addr_length = &src_addr_length
    };
    avs_error_t err =
            call_when_ready(&net_socket->socket, net_socket->recv_timeout,
                            AVS_POLLIN | AVS_POLLERR, recvfrom_internal, &arg);
    net_socket->bytes_received += arg.bytes_received;
    *out = arg.bytes_received;
    if (avs_is_ok(err)
            || (err.category == AVS_ERRNO_CATEGORY
                && err.code == AVS_EMSGSIZE)) {
        avs_error_t sub_err =
                host_port_to_string(&src_addr.addr, src_addr_length, host,
                                    (socklen_t) host_size, port,
                                    (socklen_t) port_size);
        if (avs_is_ok(err)) {
            err = sub_err;
        }
    }
    return err;
}

static avs_error_t create_listening_socket(net_socket_impl_t *net_socket,
                                           const struct sockaddr *addr,
                                           socklen_t addrlen) {
    avs_error_t err;
    int reuse_addr = net_socket->configuration.reuse_addr;
    if (reuse_addr != 0 && reuse_addr != 1) {
        return avs_errno(AVS_EINVAL);
    }
    errno = 0;
    net_socket->socket = socket(addr->sa_family,
                                _avs_net_get_socket_type(net_socket->type),
                                get_socket_proto(net_socket->type));
    if (net_socket->socket == INVALID_SOCKET) {
        err = failure_from_errno();
        LOG(ERROR, _("cannot create system socket: ") "%s",
            avs_strerror((avs_errno_t) err.code));
        goto create_listening_socket_error;
    }
    if (setsockopt(net_socket->socket, SOL_SOCKET, SO_REUSEADDR, &reuse_addr,
                   sizeof(reuse_addr))) {
        err = failure_from_errno();
        LOG(ERROR, _("can't set socket opt"));
        goto create_listening_socket_error;
    }
    if (avs_is_err((err = configure_socket(net_socket)))) {
        goto create_listening_socket_error;
    }
    // http://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html
    // says that asynchronous bind()s may happen...
    errno = 0;
    if (bind(net_socket->socket, addr, addrlen) < 0 && errno != EINPROGRESS) {
        err = failure_from_errno();
        LOG(ERROR, _("bind error: ") "%s",
            avs_strerror((avs_errno_t) err.code));
        goto create_listening_socket_error;
    }
    if (net_socket->type == AVS_NET_TCP_SOCKET
            && listen(net_socket->socket, NET_LISTEN_BACKLOG) < 0) {
        err = failure_from_errno();
        LOG(ERROR, _("listen error: ") "%s",
            avs_strerror((avs_errno_t) err.code));
        goto create_listening_socket_error;
    }
    return AVS_OK;
create_listening_socket_error:
    close_net_raw(net_socket);
    return err;
}

static avs_error_t try_bind(net_socket_impl_t *net_socket,
                            avs_net_af_t family,
                            const char *localaddr,
                            const char *port) {
    avs_net_addrinfo_t *info = NULL;
    sockaddr_endpoint_union_t address;
    avs_error_t err;
    if (net_socket->configuration.address_family != AVS_NET_AF_UNSPEC
            && net_socket->configuration.address_family != family) {
        return avs_errno(AVS_EINVAL);
    }
    if (!(info = avs_net_addrinfo_resolve_ex(
                  net_socket->type, family, localaddr, port,
                  AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE, NULL))
            || avs_net_addrinfo_next(info, &address.api_ep)) {
        LOG(WARNING, _("Cannot get ") "%s" _(" address info for ") "%s",
            get_af_name(family), localaddr ? localaddr : "(null)");
        err = avs_errno(AVS_EINVAL);
        goto bind_net_end;
    }
    net_socket->state = AVS_NET_SOCKET_STATE_BOUND;
    err = create_listening_socket(net_socket, &address.sockaddr_ep.addr,
                                  address.sockaddr_ep.header.size);
bind_net_end:
    avs_net_addrinfo_delete(&info);
    return err;
}

static avs_error_t bind_net(avs_net_socket_t *net_socket_,
                            const char *localaddr,
                            const char *port) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    if (net_socket->socket != INVALID_SOCKET) {
        LOG(ERROR, _("socket is already connected or bound"));
        return avs_errno(AVS_EISCONN);
    }

    avs_net_af_t family;
    avs_error_t err = avs_errno(AVS_EINVAL);
    if (!get_requested_family(net_socket, &family, PREFERRED_FAMILY_ONLY)
            && avs_is_ok(
                       (err = try_bind(net_socket, family, localaddr, port)))) {
        return AVS_OK;
    }
    if (!get_requested_family(net_socket, &family, PREFERRED_FAMILY_BLOCKED)
            && avs_is_ok(
                       (err = try_bind(net_socket, family, localaddr, port)))) {
        return AVS_OK;
    }
    return err;
}

typedef struct {
    sockfd_t client_sockfd;
    sockaddr_union_t remote_addr;
    socklen_t remote_addr_length;
} accept_internal_arg_t;

static avs_error_t accept_internal(sockfd_t sockfd, void *arg_) {
    accept_internal_arg_t *arg = (accept_internal_arg_t *) arg_;
    arg->remote_addr_length = (socklen_t) sizeof(arg->remote_addr);
    arg->client_sockfd =
            accept(sockfd, &arg->remote_addr.addr, &arg->remote_addr_length);
    return arg->client_sockfd == INVALID_SOCKET ? failure_from_errno() : AVS_OK;
}

static avs_error_t peek_internal(sockfd_t sockfd, void *addr_) {
    struct sockaddr *addr = (struct sockaddr *) addr_;
    socklen_t addr_len = sizeof(*addr);
    return recvfrom(sockfd, NULL, 0, MSG_PEEK, addr, &addr_len) == 0
                           && addr_len == sizeof(*addr)
                   ? AVS_OK
                   : failure_from_errno();
}

static avs_error_t peek_received_msg_host_port(net_socket_impl_t *net_socket,
                                               char *host,
                                               size_t host_size,
                                               char *port,
                                               size_t port_size) {
    avs_error_t err;
    struct sockaddr addr;
    (void) (avs_is_err((err = call_when_ready(&net_socket->socket,
                                              net_socket->recv_timeout,
                                              AVS_POLLIN | AVS_POLLERR,
                                              peek_internal, &addr)))
            || avs_is_err(
                       (err = host_port_to_string(&addr, sizeof(addr), host,
                                                  (socklen_t) host_size, port,
                                                  (socklen_t) port_size)))

    );
    return err;
}

static void swap_socket_fd_and_state(net_socket_impl_t *socket1,
                                     net_socket_impl_t *socket2) {
    AVS_SWAP(socket1->socket, socket2->socket);
    AVS_SWAP(socket1->state, socket2->state);
}

static avs_error_t accept_udp(net_socket_impl_t *server_net_socket,
                              net_socket_impl_t *new_net_socket) {
    if (!server_net_socket->configuration.reuse_addr
            || !new_net_socket->configuration.reuse_addr) {
        LOG(ERROR, _("Both server and client socket must have ")
                           _("configuration.reuse_addr set to 1"));
        return avs_errno(AVS_EINVAL);
    }

    avs_error_t err;
    char local_hostname[NET_MAX_HOSTNAME_SIZE];
    char local_port[NET_PORT_SIZE];
    if (avs_is_err(
                (err = local_host_net((avs_net_socket_t *) server_net_socket,
                                      local_hostname, sizeof(local_hostname))))
            || (avs_is_err((err = local_port_net(
                                    (avs_net_socket_t *) server_net_socket,
                                    local_port, sizeof(local_port)))))
            || (avs_is_err((err = peek_received_msg_host_port(
                                    server_net_socket,
                                    new_net_socket->remote_hostname,
                                    sizeof(new_net_socket->remote_hostname),
                                    new_net_socket->remote_port,
                                    sizeof(new_net_socket->remote_port)))))) {
        const char *error_string =
                (err.category == AVS_ERRNO_CATEGORY
                         ? avs_strerror((avs_errno_t) err.code)
                         : "unknown error");
        LOG(DEBUG,
            _("Error while gathering info about server_net_socket (") "%s" _(
                    "). ") _("None of server_net_socket or new_net_socket has "
                             "been affected."),
            error_string);
        return err;
    }

    swap_socket_fd_and_state(server_net_socket, new_net_socket);
    if (avs_is_err((err = connect_impl(new_net_socket,
                                       new_net_socket->remote_hostname,
                                       new_net_socket->remote_port)))) {
        LOG(DEBUG,
            _("Error while connecting new_net_socket to ") "%s" _(":") "%s" _(
                    "). Rolling back ") _("changes."),
            new_net_socket->remote_hostname, new_net_socket->remote_port);
        swap_socket_fd_and_state(server_net_socket, new_net_socket);
        close_net_raw(server_net_socket);
    }
    avs_error_t bind_again_err =
            bind_net((avs_net_socket_t *) server_net_socket, local_hostname,
                     local_port);
    if (avs_is_err(bind_again_err)) {
        LOG(ERROR,
            _("Could not bind server_net_socket again. It's closed now."));
        close_net_raw(server_net_socket);
        return bind_again_err;
    }

    return err;
}

static avs_error_t accept_tcp(net_socket_impl_t *server_net_socket,
                              net_socket_impl_t *new_net_socket) {
    accept_internal_arg_t arg = {
        .client_sockfd = INVALID_SOCKET
    };
    avs_error_t err;
    if (avs_is_err((err = call_when_ready(&server_net_socket->socket,
                                          NET_ACCEPT_TIMEOUT,
                                          AVS_POLLIN | AVS_POLLERR,
                                          accept_internal, &arg)))) {
        return err;
    }

    new_net_socket->socket = arg.client_sockfd;
    if (avs_is_err((err = host_port_to_string(
                            &arg.remote_addr.addr, arg.remote_addr_length,
                            new_net_socket->remote_hostname,
                            sizeof(new_net_socket->remote_hostname),
                            new_net_socket->remote_port,
                            sizeof(new_net_socket->remote_port))))) {
        close_net_raw(new_net_socket);
        return err;
    }
    return configure_socket(new_net_socket);
}

static avs_error_t accept_net(avs_net_socket_t *server_net_socket_,
                              avs_net_socket_t *new_net_socket_) {
    net_socket_impl_t *server_net_socket =
            (net_socket_impl_t *) server_net_socket_;
    net_socket_impl_t *new_net_socket = (net_socket_impl_t *) new_net_socket_;

    assert(server_net_socket->operations == &net_vtable);
    if (new_net_socket->operations != &net_vtable
            || new_net_socket->type != server_net_socket->type) {
        LOG(ERROR, _("accept_net() called with socket of invalid type"));
        return avs_errno(AVS_EINVAL);
    }

    if (new_net_socket->socket != INVALID_SOCKET) {
        LOG(ERROR, _("socket is already connected or bound"));
        return avs_errno(AVS_EISCONN);
    }

    if (server_net_socket->state != AVS_NET_SOCKET_STATE_BOUND) {
        LOG(ERROR,
            _("Server socket must be bound before calling 'accept' on it"));
        return avs_errno(AVS_ENETDOWN);
    }

    avs_error_t err;
    switch (server_net_socket->type) {
    case AVS_NET_UDP_SOCKET:
        err = accept_udp(server_net_socket, new_net_socket);
        break;
    case AVS_NET_TCP_SOCKET:
        err = accept_tcp(server_net_socket, new_net_socket);
        break;
    case AVS_NET_SSL_SOCKET:
    case AVS_NET_DTLS_SOCKET:
        AVS_UNREACHABLE("net_vtable applies only to UDP and TCP sockets");
        err = avs_errno(AVS_EINVAL);
        break;
    }

    if (avs_is_err(err)) {
        close_net_raw(new_net_socket);
        return err;
    }

    new_net_socket->state = AVS_NET_SOCKET_STATE_ACCEPTED;
    return AVS_OK;
}

static int
check_configuration(const avs_net_socket_configuration_t *configuration) {
    if (strlen(configuration->interface_name) >= IF_NAMESIZE) {
        LOG(ERROR, _("interface name too long <") "%s" _(">"),
            configuration->interface_name);
        return -1;
    }
    if (configuration->dscp >= 64) {
        LOG(ERROR, _("bad DSCP value <") "%x" _(">"),
            (unsigned) configuration->dscp);
        return -1;
    }
    if (configuration->priority > 7) {
        LOG(ERROR, _("bad priority value <") "%d" _(">"),
            (unsigned) configuration->priority);
        return -1;
    }
    return 0;
}

static void
store_configuration(net_socket_impl_t *socket,
                    const avs_net_socket_configuration_t *configuration) {
    memcpy(&socket->configuration, configuration, sizeof(*configuration));
    LOG(TRACE, _("stored socket configuration"));
}

static avs_error_t create_net_socket(avs_net_socket_t **socket,
                                     avs_net_socket_type_t socket_type,
                                     const void *socket_configuration) {
    const avs_net_socket_v_table_t *const VTABLE_PTR = &net_vtable;
    const avs_net_socket_configuration_t *configuration =
            (const avs_net_socket_configuration_t *) socket_configuration;
    net_socket_impl_t *net_socket =
            (net_socket_impl_t *) avs_calloc(1, sizeof(net_socket_impl_t));
    if (!net_socket) {
        return avs_errno(AVS_ENOMEM);
    }

    memcpy((void *) (intptr_t) &net_socket->operations, &VTABLE_PTR,
           sizeof(VTABLE_PTR));
    net_socket->socket = INVALID_SOCKET;
    net_socket->type = socket_type;
    net_socket->recv_timeout = AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT;

    *socket = (avs_net_socket_t *) net_socket;

    if (configuration) {
        if (check_configuration(configuration)) {
            avs_free(*socket);
            *socket = NULL;
            return avs_errno(AVS_EINVAL);
        } else {
            store_configuration((net_socket_impl_t *) *socket, configuration);
        }
    } else {
        LOG(TRACE, _("no additional socket configuration"));
    }
    return AVS_OK;
}

avs_error_t _avs_net_create_tcp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration) {
    return create_net_socket(socket, AVS_NET_TCP_SOCKET, socket_configuration);
}

avs_error_t _avs_net_create_udp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration) {
    return create_net_socket(socket, AVS_NET_UDP_SOCKET, socket_configuration);
}

avs_error_t avs_net_local_address_for_target_host(const char *target_host,
                                                  avs_net_af_t addr_family,
                                                  char *address_buffer,
                                                  size_t buffer_size) {
    avs_error_t err = avs_errno(AVS_EADDRNOTAVAIL);
    sockaddr_endpoint_union_t address;
    avs_net_addrinfo_t *info =
            avs_net_addrinfo_resolve_ex(AVS_NET_UDP_SOCKET, addr_family,
                                        target_host, AVS_NET_RESOLVE_DUMMY_PORT,
                                        AVS_NET_ADDRINFO_RESOLVE_F_NOADDRCONFIG,
                                        NULL);
    if (!info) {
        return err;
    }
    while (!avs_net_addrinfo_next(info, &address.api_ep)) {
        sockfd_t test_socket = socket(address.sockaddr_ep.addr.sa_family,
                                      SOCK_DGRAM, IPPROTO_UDP);

        if (test_socket == INVALID_SOCKET) {
            err = failure_from_errno();
        } else {
            if (fcntl(test_socket, F_SETFL, O_NONBLOCK) == -1) {
                err = failure_from_errno();
            } else if (avs_is_ok((err = connect_with_timeout(&test_socket,
                                                             &address)))) {
                sockaddr_union_t addr;
                socklen_t addrlen = sizeof(addr);

                if (getsockname(test_socket, &addr.addr, &addrlen)) {
                    err = failure_from_errno();
                } else {
                    err = get_string_ip(&addr, address_buffer, buffer_size);
                }
            }

            close(test_socket);
        }

        if (avs_is_ok(err)) {
            break;
        }
    }
    avs_net_addrinfo_delete(&info);
    return err;
}

static avs_error_t local_host_net(avs_net_socket_t *socket,
                                  char *out_buffer,
                                  size_t out_buffer_size) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) socket;
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    errno = 0;
    if (!getsockname(net_socket->socket, &addr.addr, &addrlen)) {
        (void) unmap_v4mapped(&addr);
        return get_string_ip(&addr, out_buffer, out_buffer_size);
    } else {
        return failure_from_errno();
    }
}

static avs_error_t local_port_net(avs_net_socket_t *socket,
                                  char *out_buffer,
                                  size_t out_buffer_size) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) socket;
    sockaddr_union_t addr;
    socklen_t addrlen = sizeof(addr);

    errno = 0;
    if (!getsockname(net_socket->socket, &addr.addr, &addrlen)) {
        int result = get_string_port(&addr, out_buffer, out_buffer_size);
        return avs_errno(result ? AVS_ERANGE : AVS_NO_ERROR);
    } else {
        return failure_from_errno();
    }
}

static avs_error_t get_mtu(net_socket_impl_t *net_socket, int *out_mtu) {
    if (net_socket->configuration.forced_mtu > 0) {
        *out_mtu = net_socket->configuration.forced_mtu;
        return AVS_OK;
    }

    int mtu = -1;
    avs_error_t err = AVS_OK;
    socklen_t dummy = sizeof(mtu);
    switch (get_socket_family(net_socket->socket)) {
#    if defined(AVS_COMMONS_NET_WITH_IPV4) && defined(IP_MTU)
    case AF_INET:
        errno = 0;
        if (getsockopt(net_socket->socket, IPPROTO_IP, IP_MTU, &mtu, &dummy)
                < 0) {
            err = failure_from_errno();
        }
        break;
#    endif /* defined(AVS_COMMONS_NET_WITH_IPV4) && defined(IP_MTU) */

#    if defined(AVS_COMMONS_NET_WITH_IPV6) && defined(IPV6_MTU)
    case AF_INET6:
        errno = 0;
        if (getsockopt(net_socket->socket, IPPROTO_IPV6, IPV6_MTU, &mtu, &dummy)
                < 0) {
            err = failure_from_errno();
        }
        break;
#    endif /* defined(AVS_COMMONS_NET_WITH_IPV6) && defined(IPV6_MTU) */

    default:
        (void) dummy;
        err = avs_errno(AVS_EINVAL);
    }
    if (avs_is_ok(err)) {
        if (mtu >= 0) {
            *out_mtu = mtu;
        } else {
            err = avs_errno(AVS_UNKNOWN_ERROR);
        }
    }
    return err;
}

static int get_fallback_inner_mtu(net_socket_impl_t *socket) {
    assert(socket->socket != INVALID_SOCKET);
#    ifdef AVS_COMMONS_NET_WITH_IPV6
    if (get_connection_family(socket->socket) == AF_INET6) { /* IPv6 */
        return 1232;                                         /* 1280 - 48 */
    } else
#    endif
    { /* probably IPv4 */
        (void) socket;
        return 548; /* 576 - 28 */
    }
}

static avs_error_t get_udp_overhead(net_socket_impl_t *net_socket, int *out) {
    switch (get_socket_family(net_socket->socket)) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
    case AF_INET:
        *out = 28; /* 20 for IP + 8 for UDP */
        return AVS_OK;
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */

#    ifdef AVS_COMMONS_NET_WITH_IPV6
    case AF_INET6:
        *out = 48; /* 40 for IPv6 + 8 for UDP */
        return AVS_OK;
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

    default:
        return avs_errno(AVS_EINVAL);
    }
}

static avs_error_t get_inner_mtu(net_socket_impl_t *net_socket, int *out_mtu) {
    if (net_socket->type != AVS_NET_UDP_SOCKET) {
        LOG(ERROR,
            _("get_opt_net: inner MTU calculation unimplemented for TCP"));
        return avs_errno(AVS_ENOTSUP);
    }
    avs_error_t err = get_mtu(net_socket, out_mtu);
    if (avs_is_ok(err)) {
        int udp_overhead;
        if (avs_is_err((err = get_udp_overhead(net_socket, &udp_overhead)))) {
            return err;
        }
        *out_mtu -= udp_overhead;
        if (*out_mtu < 0) {
            *out_mtu = 0;
        }
    } else {
        if (net_socket->socket == INVALID_SOCKET) {
            LOG(ERROR, _("cannot get inner MTU for closed socket"));
            return avs_errno(AVS_EBADF);
        }
        *out_mtu = get_fallback_inner_mtu(net_socket);
    }
    return AVS_OK;
}

static avs_error_t get_opt_net(avs_net_socket_t *net_socket_,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t *out_option_value) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
        out_option_value->recv_timeout = net_socket->recv_timeout;
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_STATE:
        out_option_value->state = net_socket->state;
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_ADDR_FAMILY:
        out_option_value->addr_family =
                get_avs_af(get_socket_family(net_socket->socket));
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_MTU:
        return get_mtu(net_socket, &out_option_value->mtu);
    case AVS_NET_SOCKET_OPT_INNER_MTU:
        return get_inner_mtu(net_socket, &out_option_value->mtu);
    case AVS_NET_SOCKET_OPT_BYTES_RECEIVED:
        out_option_value->bytes_received = net_socket->bytes_received;
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_BYTES_SENT:
        out_option_value->bytes_sent = net_socket->bytes_sent;
        return AVS_OK;
    default:
        LOG(DEBUG,
            _("get_opt_net: unknown or unsupported option key: ")
                    _("(avs_net_socket_opt_key_t) ") "%d",
            (int) option_key);
        return avs_errno(AVS_EINVAL);
    }
}

static avs_error_t set_opt_net(avs_net_socket_t *net_socket_,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t option_value) {
    net_socket_impl_t *net_socket = (net_socket_impl_t *) net_socket_;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
        net_socket->recv_timeout = option_value.recv_timeout;
        return AVS_OK;
    default:
        LOG(DEBUG,
            _("set_opt_net: unknown or unsupported option key: ")
                    _("(avs_net_socket_opt_key_t) ") "%d",
            (int) option_key);
        return avs_errno(AVS_EINVAL);
    }
}

static inline int ifaddr_ip_equal(const struct sockaddr *left,
                                  const struct sockaddr *right) {
    size_t offset;
    size_t length;
    int family_diff = left->sa_family - right->sa_family;

    if (family_diff) {
        return family_diff;
    }

    switch (left->sa_family) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
    case AF_INET:
        offset = offsetof(struct sockaddr_in, sin_addr);
        length = 4;
        break;
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */

#    ifdef AVS_COMMONS_NET_WITH_IPV6
    case AF_INET6:
        offset = offsetof(struct sockaddr_in6, sin6_addr);
        length = 16;
        break;
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

    default:
        return -1;
    }

    return memcmp(((const char *) left) + offset,
                  ((const char *) right) + offset, length);
}

static int find_interface(const struct sockaddr *addr,
                          avs_net_socket_interface_name_t *if_name) {
#    define TRY_ADDRESS(TriedAddr, TriedName)                                  \
        do {                                                                   \
            if ((TriedAddr) && (TriedName)                                     \
                    && ifaddr_ip_equal(addr, (TriedAddr)) == 0) {              \
                retval = avs_simple_snprintf(*if_name, sizeof(*if_name), "%s", \
                                             (TriedName))                      \
                                         < 0                                   \
                                 ? -1                                          \
                                 : 0;                                          \
                goto interface_name_end;                                       \
            }                                                                  \
        } while (0)
#    ifdef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETIFADDRS
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
#    elif defined(SIOCGIFCONF)
#        ifndef _SIZEOF_ADDR_IFREQ
#            define _SIZEOF_ADDR_IFREQ sizeof
#        endif
    int retval = -1;
    sockfd_t null_socket;
    struct ifconf conf;
    size_t blen = 32 * sizeof(struct ifconf[1]);
    struct ifreq *reqs = NULL;
    struct ifreq *req;
    if ((null_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))
            == INVALID_SOCKET) {
        goto interface_name_end;
    }
interface_name_retry:
    if (!(req = (struct ifreq *) avs_realloc(reqs, blen))) {
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
         req = (struct ifreq *) (((char *) req) + _SIZEOF_ADDR_IFREQ(*req))) {
        TRY_ADDRESS(&req->ifr_addr, req->ifr_name);
    }
interface_name_end:
    avs_free(reqs);
    close(null_socket);
    return retval;
#    else
    (void) ifaddr_ip_equal;
    (void) addr;
    (void) if_name;
    return -1;
#    endif
#    undef TRY_ADDRESS
}

static avs_error_t
interface_name_net(avs_net_socket_t *socket_,
                   avs_net_socket_interface_name_t *if_name) {
    net_socket_impl_t *socket = (net_socket_impl_t *) socket_;
    if (socket->configuration.interface_name[0]) {
        memcpy(*if_name, socket->configuration.interface_name,
               sizeof(*if_name));
    } else {
        sockaddr_union_t addr;
        socklen_t addrlen = sizeof(addr);
        errno = 0;
        if (getsockname(socket->socket, &addr.addr, &addrlen)
                || find_interface(&addr.addr, if_name)) {
            return failure_from_errno();
        }
    }
    return AVS_OK;
}

avs_error_t
avs_net_resolved_endpoint_get_host_port(const avs_net_resolved_endpoint_t *endp,
                                        char *host,
                                        size_t hostlen,
                                        char *serv,
                                        size_t servlen) {
    return host_port_to_string((const struct sockaddr *) &endp->data,
                               endp->size, host, (socklen_t) hostlen, serv,
                               (socklen_t) servlen);
}

avs_error_t _avs_net_initialize_global_compat_state(void) {
    avs_error_t err = AVS_OK;
#    ifdef HAVE_GLOBAL_COMPAT_STATE
    err = initialize_global_compat_state();
#    endif // HAVE_GLOBAL_COMPAT_STATE
    return err;
}

void _avs_net_cleanup_global_compat_state(void) {
#    ifdef HAVE_GLOBAL_COMPAT_STATE
    cleanup_global_compat_state();
#    endif // HAVE_GLOBAL_COMPAT_STATE
}

#endif // defined(AVS_COMMONS_WITH_AVS_NET) &&
       // defined(AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET)
