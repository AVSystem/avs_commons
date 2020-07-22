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

#ifndef NET_SSL_COMMON_H
#define NET_SSL_COMMON_H

#ifndef NET_SSL_COMMON_INTERNALS
#    error "This header is not meant to be included from outside"
#endif

#include <avsystem/commons/avs_memory.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

/* Required non-common static method implementations */
static bool is_ssl_started(ssl_socket_t *socket);
static bool is_session_resumed(ssl_socket_t *socket);
static avs_error_t start_ssl(ssl_socket_t *socket, const char *host);
static void close_ssl_raw(ssl_socket_t *socket);
static avs_error_t
get_dtls_overhead(ssl_socket_t *socket, int *out_header, int *out_padding_size);
static avs_error_t
initialize_ssl_socket(ssl_socket_t *socket,
                      avs_net_socket_type_t backend_type,
                      const avs_net_ssl_configuration_t *configuration);

/* avs_net_socket_v_table_t ssl handlers implemented differently per backend */
static avs_error_t send_ssl(avs_net_socket_t *ssl_socket,
                            const void *buffer,
                            size_t buffer_length);
static avs_error_t receive_ssl(avs_net_socket_t *ssl_socket,
                               size_t *out,
                               void *buffer,
                               size_t buffer_length);
static avs_error_t cleanup_ssl(avs_net_socket_t **ssl_socket);

/* avs_net_socket_v_table_t ssl handlers implemented in this file */
static avs_error_t decorate_ssl(avs_net_socket_t *socket,
                                avs_net_socket_t *backend_socket);
static avs_error_t close_ssl(avs_net_socket_t *ssl_socket);
static const void *system_socket_ssl(avs_net_socket_t *ssl_socket);
static avs_error_t interface_name_ssl(avs_net_socket_t *ssl_socket,
                                      avs_net_socket_interface_name_t *if_name);
static avs_error_t remote_hostname_ssl(avs_net_socket_t *socket,
                                       char *out_buffer,
                                       size_t ouf_buffer_size);
static avs_error_t remote_host_ssl(avs_net_socket_t *socket,
                                   char *out_buffer,
                                   size_t ouf_buffer_size);
static avs_error_t remote_port_ssl(avs_net_socket_t *socket,
                                   char *out_buffer,
                                   size_t ouf_buffer_size);
static avs_error_t local_port_ssl(avs_net_socket_t *socket,
                                  char *out_buffer,
                                  size_t ouf_buffer_size);
static avs_error_t get_opt_ssl(avs_net_socket_t *ssl_socket_,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t *out_option_value);
static avs_error_t set_opt_ssl(avs_net_socket_t *net_socket,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t option_value);

static avs_error_t ensure_have_backend_socket(ssl_socket_t *socket) {
    if (!socket->backend_socket) {
        if (socket->backend_type == AVS_NET_UDP_SOCKET) {
            return avs_net_udp_socket_create(&socket->backend_socket,
                                             &socket->backend_configuration);
        } else if (socket->backend_type == AVS_NET_TCP_SOCKET) {
            return avs_net_tcp_socket_create(&socket->backend_socket,
                                             &socket->backend_configuration);
        } else {
            return avs_errno(AVS_EINVAL);
        }
    }
    return AVS_OK;
}

static avs_error_t create_ssl_socket(avs_net_socket_t **socket,
                                     avs_net_socket_type_t backend_type,
                                     const void *socket_configuration) {
    LOG(TRACE, _("create_ssl_socket(socket=") "%p" _(")"), (void *) socket);

    if (!socket_configuration) {
        LOG(ERROR, _("SSL configuration not specified"));
        return avs_errno(AVS_EINVAL);
    }

    ssl_socket_t *ssl_sock =
            (ssl_socket_t *) avs_calloc(1, sizeof(ssl_socket_t));
    *socket = (avs_net_socket_t *) ssl_sock;
    if (*socket) {
        LOG(TRACE,
            _("configure_ssl(socket=") "%p" _(", configuration=") "%p" _(")"),
            (void *) socket, (const void *) socket_configuration);

        avs_error_t err = initialize_ssl_socket(
                ssl_sock, backend_type,
                (const avs_net_ssl_configuration_t *) socket_configuration);
        if (avs_is_err(err)) {
            LOG(ERROR, _("socket initialization error"));
            avs_net_socket_cleanup(socket);
            return err;
        } else {
            return AVS_OK;
        }
    } else {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }
}

static avs_error_t
bind_ssl(avs_net_socket_t *socket_, const char *localaddr, const char *port) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    avs_error_t err = ensure_have_backend_socket(socket);
    if (avs_is_err(err)) {
        return err;
    }
    return avs_net_socket_bind(socket->backend_socket, localaddr, port);
}

static avs_error_t
connect_ssl(avs_net_socket_t *socket_, const char *host, const char *port) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    LOG(TRACE,
        _("connect_ssl(socket=") "%p" _(", host=") "%s" _(", port=") "%s" _(
                ")"),
        (void *) socket, host, port);

    if (is_ssl_started(socket)) {
        LOG(ERROR, _("SSL socket already connected"));
        return avs_errno(AVS_EISCONN);
    }
    avs_error_t err = ensure_have_backend_socket(socket);
    if (avs_is_err(err)) {
        return avs_errno(AVS_EBADF);
    }
    if (avs_is_err((err = avs_net_socket_connect(socket->backend_socket, host,
                                                 port)))) {
        LOG(ERROR, _("avs_net_socket_connect() on backend socket failed"));
        return err;
    }

    if (avs_is_err((err = start_ssl(socket, host)))) {
        close_ssl_raw(socket);
    }
    return err;
}

static avs_error_t decorate_ssl(avs_net_socket_t *socket_,
                                avs_net_socket_t *backend_socket) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    LOG(TRACE,
        _("decorate_ssl(socket=") "%p" _(", backend_socket=") "%p" _(")"),
        (void *) socket, (void *) backend_socket);

    if (is_ssl_started(socket)) {
        LOG(ERROR, _("SSL socket already connected"));
        return avs_errno(AVS_EISCONN);
    }
    avs_net_socket_opt_value_t backend_state;
    avs_error_t err =
            avs_net_socket_get_opt(backend_socket, AVS_NET_SOCKET_OPT_STATE,
                                   &backend_state);
    if (avs_is_err(err)) {
        LOG(ERROR, _("Could not get backend socket state"));
        return err;
    }

    if (socket->backend_socket) {
        avs_net_socket_cleanup(&socket->backend_socket);
    }
    socket->backend_socket = backend_socket;

    // If the backend socket is already connected, perform handshake immediately
    // (this is most likely the STARTTLS case). Otherwise, don't do anything,
    // the handshake will be performed when the user calls connect() on the
    // decorated socket (likely a non-TCP/UDP TLS socket).
    if (backend_state.state == AVS_NET_SOCKET_STATE_ACCEPTED
            || backend_state.state == AVS_NET_SOCKET_STATE_CONNECTED) {
        char host[NET_MAX_HOSTNAME_SIZE];
        if (avs_is_ok((err = avs_net_socket_get_remote_hostname(
                               backend_socket, host, sizeof(host))))) {
            err = start_ssl(socket, host);
        }
    }
    if (avs_is_err(err)) {
        socket->backend_socket = NULL;
        close_ssl_raw(socket);
    }
    return err;
}

static const void *system_socket_ssl(avs_net_socket_t *socket_) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    if (socket->backend_socket) {
        return avs_net_socket_get_system(socket->backend_socket);
    } else {
        return NULL;
    }
}

static avs_error_t shutdown_ssl(avs_net_socket_t *socket_) {
    LOG(TRACE, _("shutdown_ssl(socket=") "%p" _(")"), (void *) socket_);
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    return avs_net_socket_shutdown(socket->backend_socket);
}

static avs_error_t close_ssl(avs_net_socket_t *socket_) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    LOG(TRACE, _("close_ssl(socket=") "%p" _(")"), (void *) socket);
    close_ssl_raw(socket);
    return AVS_OK;
}

static avs_error_t
interface_name_ssl(avs_net_socket_t *ssl_socket_,
                   avs_net_socket_interface_name_t *if_name) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    return avs_net_socket_interface_name(ssl_socket->backend_socket, if_name);
}

static avs_error_t remote_host_ssl(avs_net_socket_t *socket_,
                                   char *out_buffer,
                                   size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    return avs_net_socket_get_remote_host(socket->backend_socket, out_buffer,
                                          out_buffer_size);
}

static avs_error_t remote_hostname_ssl(avs_net_socket_t *socket_,
                                       char *out_buffer,
                                       size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    return avs_net_socket_get_remote_hostname(socket->backend_socket,
                                              out_buffer, out_buffer_size);
}

static avs_error_t remote_port_ssl(avs_net_socket_t *socket_,
                                   char *out_buffer,
                                   size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    return avs_net_socket_get_remote_port(socket->backend_socket, out_buffer,
                                          out_buffer_size);
}

static avs_error_t local_host_ssl(avs_net_socket_t *socket_,
                                  char *out_buffer,
                                  size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    return avs_net_socket_get_local_host(socket->backend_socket, out_buffer,
                                         out_buffer_size);
}

static avs_error_t local_port_ssl(avs_net_socket_t *socket_,
                                  char *out_buffer,
                                  size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    return avs_net_socket_get_local_port(socket->backend_socket, out_buffer,
                                         out_buffer_size);
}

static int get_socket_inner_mtu_or_zero(avs_net_socket_t *sock) {
    avs_net_socket_opt_value_t opt_value;
    if (!sock
            || avs_is_err(avs_net_socket_get_opt(
                       sock, AVS_NET_SOCKET_OPT_INNER_MTU, &opt_value))) {
        return 0;
    } else {
        return opt_value.mtu;
    }
}

#ifdef WITH_DANE_SUPPORT
static avs_error_t calculate_copied_tlsa_array_size(size_t *out_size_bytes,
                                                    size_t record_count) {
    if (record_count > SIZE_MAX / sizeof(avs_net_socket_dane_tlsa_record_t)) {
        return avs_errno(AVS_ENOMEM);
    }
    *out_size_bytes = record_count * sizeof(avs_net_socket_dane_tlsa_record_t);
    return AVS_OK;
}

static avs_error_t
set_dane_tlsa_array(ssl_socket_t *socket,
                    const avs_net_socket_dane_tlsa_array_t *array) {
    size_t array_buffer_size = 0;
    avs_error_t err =
            calculate_copied_tlsa_array_size(&array_buffer_size,
                                             array->array_element_count);
    size_t buffer_size = array_buffer_size;
    for (size_t i = 0; avs_is_ok(err) && i < array->array_element_count; ++i) {
        if (buffer_size
                > SIZE_MAX - array->array_ptr[i].association_data_size) {
            err = avs_errno(AVS_ENOMEM);
        } else {
            buffer_size += array->array_ptr[i].association_data_size;
        }
    }
    avs_net_socket_dane_tlsa_record_t *copied_array = NULL;
    if (avs_is_ok(err)
            && !(copied_array = (avs_net_socket_dane_tlsa_record_t *)
                         avs_malloc(buffer_size))) {
        err = avs_errno(AVS_ENOMEM);
    }
    if (avs_is_err(err)) {
        LOG(ERROR, _("Out of memory"));
        return err;
    }
    avs_free((void *) (intptr_t) (const void *)
                     socket->dane_tlsa_array_field.array_ptr);
    socket->dane_tlsa_array_field.array_ptr = copied_array;
    socket->dane_tlsa_array_field.array_element_count =
            array->array_element_count;
    memcpy(copied_array, array->array_ptr,
           array->array_element_count
                   * sizeof(avs_net_socket_dane_tlsa_record_t));
    char *data_buffer_ptr = (char *) &copied_array[array->array_element_count];
    for (size_t i = 0; avs_is_ok(err) && i < array->array_element_count; ++i) {
        copied_array[i].association_data = data_buffer_ptr;
        memcpy(data_buffer_ptr, array->array_ptr[i].association_data,
               array->array_ptr[i].association_data_size);
        data_buffer_ptr += array->array_ptr[i].association_data_size;
    }
    return AVS_OK;
}
#endif // WITH_DANE_SUPPORT

static avs_error_t set_opt_ssl(avs_net_socket_t *ssl_socket_,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t option_value) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    switch (option_key) {
#ifdef WITH_DANE_SUPPORT
    case AVS_NET_SOCKET_OPT_DANE_TLSA_ARRAY:
        return set_dane_tlsa_array(ssl_socket, &option_value.dane_tlsa_array);
#endif // WITH_DANE_SUPPORT
    default:
        if (!ssl_socket->backend_socket) {
            return avs_errno(AVS_EBADF);
        } else {
            return avs_net_socket_set_opt(ssl_socket->backend_socket,
                                          option_key, option_value);
        }
    }
}

static avs_error_t get_opt_ssl(avs_net_socket_t *ssl_socket_,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t *out_option_value) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_INNER_MTU: {
        /* getting inner MTU will fail for non-datagram sockets */
        int mtu = get_socket_inner_mtu_or_zero(ssl_socket->backend_socket);
        if (mtu > 0) {
            int header, padding;
            avs_error_t err = get_dtls_overhead(ssl_socket, &header, &padding);
            if (avs_is_err(err)) {
                return err;
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
            return avs_errno(AVS_UNKNOWN_ERROR);
        }
        out_option_value->mtu = mtu;
        return AVS_OK;
    }
    case AVS_NET_SOCKET_OPT_SESSION_RESUMED:
        out_option_value->flag = is_session_resumed(ssl_socket);
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_STATE:
        if (!ssl_socket->backend_socket) {
            out_option_value->state = AVS_NET_SOCKET_STATE_CLOSED;
            return AVS_OK;
        }
        // fall-through
    default:
        if (!ssl_socket->backend_socket) {
            return avs_errno(AVS_EBADF);
        } else {
            return avs_net_socket_get_opt(ssl_socket->backend_socket,
                                          option_key, out_option_value);
        }
    }
}

avs_error_t _avs_net_create_ssl_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration) {
    return create_ssl_socket(socket, AVS_NET_TCP_SOCKET, socket_configuration);
}

avs_error_t _avs_net_create_dtls_socket(avs_net_socket_t **socket,
                                        const void *socket_configuration) {
    return create_ssl_socket(socket, AVS_NET_UDP_SOCKET, socket_configuration);
}

static inline void _avs_net_psk_cleanup(avs_net_owned_psk_t *psk) {
    avs_free(psk->psk);
    psk->psk = NULL;
    avs_free(psk->identity);
    psk->identity = NULL;
}

static inline avs_error_t _avs_net_psk_copy(avs_net_owned_psk_t *dst,
                                            const avs_net_psk_info_t *src) {
    if (!src->psk_size) {
        LOG(ERROR, _("PSK cannot be empty"));
        return avs_errno(AVS_EINVAL);
    }
    avs_net_owned_psk_t out_psk;
    memset(&out_psk, 0, sizeof(out_psk));
    out_psk.psk_size = src->psk_size;
    out_psk.psk = avs_malloc(src->psk_size);
    if (!out_psk.psk) {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }

    out_psk.identity_size = src->identity_size;
    if (out_psk.identity_size) {
        out_psk.identity = avs_malloc(src->identity_size);
        if (!out_psk.identity) {
            avs_free(out_psk.psk);
            LOG(ERROR, _("Out of memory"));
            return avs_errno(AVS_ENOMEM);
        }
        memcpy(out_psk.identity, src->identity, src->identity_size);
    }
    _avs_net_psk_cleanup(dst);
    memcpy(out_psk.psk, src->psk, src->psk_size);
    *dst = out_psk;
    return AVS_OK;
}

static const avs_net_socket_v_table_t ssl_vtable = {
    .connect = connect_ssl,
    .decorate = decorate_ssl,
    .send = send_ssl,
    .receive = receive_ssl,
    .bind = bind_ssl,
    .close = close_ssl,
    .shutdown = shutdown_ssl,
    .cleanup = cleanup_ssl,
    .get_system_socket = system_socket_ssl,
    .get_interface_name = interface_name_ssl,
    .get_remote_host = remote_host_ssl,
    .get_remote_hostname = remote_hostname_ssl,
    .get_remote_port = remote_port_ssl,
    .get_local_host = local_host_ssl,
    .get_local_port = local_port_ssl,
    .get_opt = get_opt_ssl,
    .set_opt = set_opt_ssl
};

static const avs_net_dtls_handshake_timeouts_t
        DEFAULT_DTLS_HANDSHAKE_TIMEOUTS = {
            .min = { 1, 0 },
            .max = { 60, 0 }
        };

// https://tools.ietf.org/html/rfc5246#section-6.2.1
#define AVS_TLS_MESSAGE_TYPE_ALERT 21

static inline void add_err(avs_error_t *output, avs_error_t err) {
    if (avs_is_ok(*output)) {
        *output = err;
    }
}

VISIBILITY_PRIVATE_HEADER_END

#endif /* NET_SSL_COMMON_H */
