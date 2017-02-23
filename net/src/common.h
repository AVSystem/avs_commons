/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef NET_COMMON_H
#define NET_COMMON_H


/* Required non-common static method implementations */
static int is_ssl_started(ssl_socket_t *socket);
static int start_ssl(ssl_socket_t *socket, const char *host);
static void close_ssl_raw(ssl_socket_t *socket);
static int get_dtls_overhead(ssl_socket_t *socket,
                             int *out_header,
                             int *out_padding_size);

/* avs_net_socket_v_table_t ssl handlers */
static int decorate_ssl(avs_net_abstract_socket_t *socket,
                        avs_net_abstract_socket_t *backend_socket);
static int send_ssl(avs_net_abstract_socket_t *ssl_socket,
                    const void *buffer,
                    size_t buffer_length);
static int receive_ssl(avs_net_abstract_socket_t *ssl_socket,
                       size_t *out,
                       void *buffer,
                       size_t buffer_length);
static int bind_ssl(avs_net_abstract_socket_t *socket,
                    const char *localaddr,
                    const char *port);
static int shutdown_ssl(avs_net_abstract_socket_t *socket);
static int close_ssl(avs_net_abstract_socket_t *ssl_socket);
static int cleanup_ssl(avs_net_abstract_socket_t **ssl_socket);
static int system_socket_ssl(avs_net_abstract_socket_t *ssl_socket,
                             const void **out);
static int interface_name_ssl(avs_net_abstract_socket_t *ssl_socket,
                              avs_net_socket_interface_name_t *if_name);
static int remote_hostname_ssl(avs_net_abstract_socket_t *socket,
                               char *out_buffer, size_t ouf_buffer_size);
static int remote_host_ssl(avs_net_abstract_socket_t *socket,
                           char *out_buffer, size_t ouf_buffer_size);
static int remote_port_ssl(avs_net_abstract_socket_t *socket,
                           char *out_buffer, size_t ouf_buffer_size);
static int local_port_ssl(avs_net_abstract_socket_t *socket,
                          char *out_buffer, size_t ouf_buffer_size);
static int get_opt_ssl(avs_net_abstract_socket_t *ssl_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value);
static int set_opt_ssl(avs_net_abstract_socket_t *net_socket,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t option_value);
static int errno_ssl(avs_net_abstract_socket_t *net_socket);

#define WRAP_ERRNO_IMPL(SslSocket, BackendSocket, Retval, ...) do { \
    if (BackendSocket) { \
        Retval = (__VA_ARGS__); \
        (SslSocket)->error_code = avs_net_socket_errno((BackendSocket)); \
    } else { \
        Retval = -1; \
        (SslSocket)->error_code = EBADF; \
    } \
} while (0)

#define WRAP_ERRNO(SslSocket, Retval, ...) \
        WRAP_ERRNO_IMPL(SslSocket, (SslSocket)->backend_socket, Retval, \
                        __VA_ARGS__)

static int unimplemented() {
    return -1;
}

static int ensure_have_backend_socket(ssl_socket_t *socket) {
    if (!socket->backend_socket
            && avs_net_socket_create(&socket->backend_socket,
                                     socket->backend_type,
                                     &socket->backend_configuration)) {
        socket->error_code = EBADF;
        return -1;
    }
    return 0;
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 avs_net_socket_type_t backend_type,
                                 const avs_net_ssl_configuration_t *configuration);

static int create_ssl_socket(avs_net_abstract_socket_t **socket,
                             avs_net_socket_type_t backend_type,
                             const void *socket_configuration) {
    LOG(TRACE, "create_ssl_socket(socket=%p)", (void *) socket);

    *socket = (avs_net_abstract_socket_t *) calloc(1, sizeof (ssl_socket_t));
    if (*socket) {
        if (initialize_ssl_socket((ssl_socket_t *) * socket, backend_type,
                                  (const avs_net_ssl_configuration_t *)
                                  socket_configuration)) {
            LOG(ERROR, "socket initialization error");
            avs_net_socket_cleanup(socket);
            return -1;
        } else {
            return 0;
        }
    } else {
        LOG(ERROR, "memory allocation error");
        return -1;
    }
}

static int connect_ssl(avs_net_abstract_socket_t *socket_,
                       const char *host,
                       const char *port) {
    int result;
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    LOG(TRACE, "connect_ssl(socket=%p, host=%s, port=%s)",
        (void *) socket, host, port);

    if (is_ssl_started(socket)) {
        LOG(ERROR, "SSL socket already connected");
        socket->error_code = EISCONN;
        return -1;
    }
    if (ensure_have_backend_socket(socket)) {
        socket->error_code = EBADF;
        return -1;
    }
    if (avs_net_socket_connect(socket->backend_socket, host, port)) {
        LOG(ERROR, "cannot establish TCP connection");
        socket->error_code = avs_net_socket_errno(socket->backend_socket);
        return -1;
    }

    result = start_ssl(socket, host);
    if (result) {
        close_ssl_raw(socket);
    }
    return result;
}

static int decorate_ssl(avs_net_abstract_socket_t *socket_,
                        avs_net_abstract_socket_t *backend_socket) {
    char host[NET_MAX_HOSTNAME_SIZE];
    int result;
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    LOG(TRACE, "decorate_ssl(socket=%p, backend_socket=%p)",
        (void *) socket, (void *) backend_socket);

    if (is_ssl_started(socket)) {
        LOG(ERROR, "SSL socket already connected");
        socket->error_code = EISCONN;
        return -1;
    }
    if (socket->backend_socket) {
        avs_net_socket_cleanup(&socket->backend_socket);
    }

    WRAP_ERRNO_IMPL(socket, backend_socket, result,
                    avs_net_socket_get_remote_hostname(backend_socket,
                                                   host, sizeof(host)));
    if (result) {
        return result;
    }

    socket->backend_socket = backend_socket;
    result = start_ssl(socket, host);
    if (result) {
        socket->backend_socket = NULL;
        close_ssl_raw(socket);
    }
    return result;
}

static int set_opt_ssl(avs_net_abstract_socket_t *ssl_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t option_value) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    int retval;
    WRAP_ERRNO(ssl_socket, retval,
               avs_net_socket_set_opt(ssl_socket->backend_socket, option_key,
                                      option_value));
    return retval;
}

static int system_socket_ssl(avs_net_abstract_socket_t *socket_,
                             const void **out) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    if (socket->backend_socket) {
        *out = avs_net_socket_get_system(socket->backend_socket);
        socket->error_code = avs_net_socket_errno(socket->backend_socket);
    } else {
        *out = NULL;
        socket->error_code = EBADF;
    }
    return *out ? 0 : -1;
}

static int close_ssl(avs_net_abstract_socket_t *socket_) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    LOG(TRACE, "close_ssl(socket=%p)", (void *) socket);
    close_ssl_raw(socket);
    socket->error_code = 0;
    return 0;
}

static int interface_name_ssl(avs_net_abstract_socket_t *ssl_socket_,
                              avs_net_socket_interface_name_t *if_name) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    int retval;
    WRAP_ERRNO(ssl_socket, retval,
               avs_net_socket_interface_name(ssl_socket->backend_socket,
                                             if_name));
    return retval;
}

static int remote_host_ssl(avs_net_abstract_socket_t *socket_,
                           char *out_buffer, size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int retval;
    WRAP_ERRNO(socket, retval,
               avs_net_socket_get_remote_host(socket->backend_socket,
                                              out_buffer, out_buffer_size));
    return retval;
}

static int remote_hostname_ssl(avs_net_abstract_socket_t *socket_,
                               char *out_buffer, size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int retval;
    WRAP_ERRNO(socket, retval,
               avs_net_socket_get_remote_hostname(socket->backend_socket,
                                                  out_buffer, out_buffer_size));
    return retval;
}

static int remote_port_ssl(avs_net_abstract_socket_t *socket_,
                           char *out_buffer, size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int retval;
    WRAP_ERRNO(socket, retval,
               avs_net_socket_get_remote_port(socket->backend_socket,
                                              out_buffer, out_buffer_size));
    return retval;
}

static int local_port_ssl(avs_net_abstract_socket_t *socket_,
                          char *out_buffer, size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int retval;
    WRAP_ERRNO(socket, retval,
               avs_net_socket_get_local_port(socket->backend_socket,
                                             out_buffer, out_buffer_size));
    return retval;
}

static int get_socket_inner_mtu_or_zero(avs_net_abstract_socket_t *sock) {
    avs_net_socket_opt_value_t opt_value;
    if (avs_net_socket_get_opt(sock, AVS_NET_SOCKET_OPT_INNER_MTU,
                               &opt_value)) {
        return 0;
    } else {
        return opt_value.mtu;
    }
}

static int get_opt_ssl(avs_net_abstract_socket_t *ssl_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    int retval;
    ssl_socket->error_code = 0;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_INNER_MTU:
    {
        /* getting inner MTU will fail for non-datagram sockets */
        int mtu = get_socket_inner_mtu_or_zero(ssl_socket->backend_socket);
        if (mtu > 0) {
            int header, padding;
            if (get_dtls_overhead(ssl_socket, &header, &padding)) {
                return -1;
            }
            mtu -= header;
            if (padding > 0) {
                /* SSL padding is always present - when data is an exact
                 * multiply of block size, a full block of padding is added;
                 * the maximum user data we can pass is thus the maximum number
                 * of full blocks minus one byte */
                mtu = (mtu / padding) * padding - 1;
            }
        }
        if (mtu < 0) {
            return -1;
        }
        out_option_value->mtu = mtu;
        return 0;
    }
    default:
        retval = avs_net_socket_get_opt(ssl_socket->backend_socket, option_key,
                                        out_option_value);
    }
    if (retval && !(ssl_socket->error_code =
                avs_net_socket_errno(ssl_socket->backend_socket))) {
        ssl_socket->error_code = EPROTO;
    }
    return retval;
}

static int is_client_cert_empty(const avs_net_client_cert_t *cert) {
    switch (cert->impl.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        return !cert->impl.data.file.path;
    case AVS_NET_DATA_SOURCE_BUFFER:
        return !cert->impl.data.cert.data;
    default:
        assert(0 && "invalid enum value");
        return 1;
    }
}

int _avs_net_create_ssl_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return create_ssl_socket(socket, AVS_NET_TCP_SOCKET, socket_configuration);
}

int _avs_net_create_dtls_socket(avs_net_abstract_socket_t **socket,
                                const void *socket_configuration) {
    return create_ssl_socket(socket, AVS_NET_UDP_SOCKET, socket_configuration);
}

#endif /* NET_COMMON_H */
