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

#endif /* NET_COMMON_H */
