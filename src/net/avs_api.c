/*
 * Copyright 2026 AVSystem <avsystem@avsystem.com>
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

#define AVS_NET_API_C
#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_NET

#    include <inttypes.h>
#    include <stdint.h>
#    include <stdio.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_net.h>
#    include <avsystem/commons/avs_socket.h>
#    include <avsystem/commons/avs_socket_v_table.h>

#    include "avs_net_global.h"

#    include "avs_net_impl.h"

VISIBILITY_SOURCE_BEGIN

#    if defined(AVS_COMMONS_NET_WITH_SOCKET_LOG) \
            && defined(AVS_COMMONS_WITH_TRAFFIC_INTERCEPTOR)
#        error "Traffic interceptor cannot be used together with socket logging"
#    endif // defined(AVS_COMMONS_NET_WITH_SOCKET_LOG) && defined
           // (AVS_COMMONS_WITH_TRAFFIC_INTERCEPTOR)

const avs_time_duration_t AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT = { 30, 0 };

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO
avs_net_security_info_t avs_net_security_info_from_psk(avs_net_psk_info_t psk) {
    avs_net_security_info_t result;
    memset(&result, 0, sizeof(result));
    result.mode = AVS_NET_SECURITY_PSK;
    result.data.psk = psk;
    return result;
}

avs_net_security_info_t
avs_net_security_info_from_certificates(avs_net_certificate_info_t info) {
    avs_net_security_info_t result;
    memset(&result, 0, sizeof(result));
    result.mode = AVS_NET_SECURITY_CERTIFICATE;
    result.data.cert = info;
    return result;
}
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO

avs_net_socket_dane_tlsa_record_t *
avs_net_socket_dane_tlsa_array_copy(avs_net_socket_dane_tlsa_array_t in_array) {
    if (!in_array.array_element_count) {
        return NULL;
    }
    size_t association_data_size = 0;
    for (size_t i = 0; i < in_array.array_element_count; ++i) {
        association_data_size += in_array.array_ptr[i].association_data_size;
    }
    avs_net_socket_dane_tlsa_record_t *result =
            (avs_net_socket_dane_tlsa_record_t *) avs_malloc(
                    in_array.array_element_count * sizeof(*result)
                    + association_data_size);
    if (!result) {
        LOG_OOM();
        return NULL;
    }
    char *association_data_buf = (char *) &result[in_array.array_element_count];
    const char *const association_data_buf_end =
            association_data_buf + association_data_size;
    for (size_t i = 0; i < in_array.array_element_count; ++i) {
        result[i] = in_array.array_ptr[i];
        if (in_array.array_ptr[i].association_data_size) {
            memcpy(association_data_buf, in_array.array_ptr[i].association_data,
                   in_array.array_ptr[i].association_data_size);
            result[i].association_data = association_data_buf;
            association_data_buf += in_array.array_ptr[i].association_data_size;
            assert(association_data_buf <= association_data_buf_end);
        }
    }
    assert(association_data_buf == association_data_buf_end);
    (void) association_data_buf_end;
    return result;
}

#    ifdef AVS_COMMONS_NET_WITH_SOCKET_LOG
static int _avs_net_socket_debug = 0;

int avs_net_socket_debug(int value) {
    int prev_value = !!_avs_net_socket_debug;
    if (value >= 0) {
        _avs_net_socket_debug = !!value;
    }
    return prev_value;
}
#    else
int avs_net_socket_debug(int value) {
    if (value > 0) {
        return -1;
    }
    return 0;
}
#    endif

struct avs_net_socket_struct {
    const avs_net_socket_v_table_t *const operations;
};

avs_error_t avs_net_socket_connect(avs_net_socket_t *socket,
                                   const char *host,
                                   const char *port) {
    if (!socket->operations->connect) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->connect(socket, host, port);
}

avs_error_t avs_net_socket_decorate(avs_net_socket_t *socket,
                                    avs_net_socket_t *backend_socket) {
    if (!socket->operations->decorate) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->decorate(socket, backend_socket);
}

avs_error_t avs_net_socket_send(avs_net_socket_t *socket,
                                const void *buffer,
                                size_t buffer_length) {
    if (!socket->operations->send) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->send(socket, buffer, buffer_length);
}

avs_error_t avs_net_socket_send_to(avs_net_socket_t *socket,
                                   const void *buffer,
                                   size_t buffer_length,
                                   const char *host,
                                   const char *port) {
    if (!socket->operations->send_to) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->send_to(socket, buffer, buffer_length, host,
                                       port);
}

avs_error_t avs_net_socket_receive(avs_net_socket_t *socket,
                                   size_t *out_bytes_received,
                                   void *buffer,
                                   size_t buffer_length) {
    if (!socket->operations->receive) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->receive(socket, out_bytes_received, buffer,
                                       buffer_length);
}

avs_error_t avs_net_socket_receive_from(avs_net_socket_t *socket,
                                        size_t *out_bytes_received,
                                        void *buffer,
                                        size_t buffer_length,
                                        char *host,
                                        size_t host_size,
                                        char *port,
                                        size_t port_size) {
    if (!socket->operations->receive_from) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->receive_from(socket, out_bytes_received, buffer,
                                            buffer_length, host, host_size,
                                            port, port_size);
}

avs_error_t avs_net_socket_bind(avs_net_socket_t *socket,
                                const char *address,
                                const char *port) {
    if (!socket->operations->bind) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->bind(socket, address, port);
}

avs_error_t avs_net_socket_accept(avs_net_socket_t *server_socket,
                                  avs_net_socket_t *client_socket) {
    if (!server_socket->operations->accept) {
        return avs_errno(AVS_ENOTSUP);
    }
    return server_socket->operations->accept(server_socket, client_socket);
}

avs_error_t avs_net_socket_close(avs_net_socket_t *socket) {
    if (!socket->operations->close) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->close(socket);
}

avs_error_t avs_net_socket_shutdown(avs_net_socket_t *socket) {
    if (!socket->operations->shutdown) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->shutdown(socket);
}

avs_error_t avs_net_socket_cleanup(avs_net_socket_t **socket) {
    if (*socket) {
        assert((*socket)->operations->cleanup);
        return (*socket)->operations->cleanup(socket);
    } else {
        return AVS_OK;
    }
}

const void *avs_net_socket_get_system(avs_net_socket_t *socket) {
    if (!socket->operations->get_system_socket) {
        return NULL;
    }
    return socket->operations->get_system_socket(socket);
}

avs_error_t
avs_net_socket_interface_name(avs_net_socket_t *socket,
                              avs_net_socket_interface_name_t *if_name) {
    if (!socket->operations->get_interface_name) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->get_interface_name(socket, if_name);
}

avs_error_t avs_net_socket_get_remote_host(avs_net_socket_t *socket,
                                           char *out_buffer,
                                           size_t out_buffer_size) {
    if (!socket->operations->get_remote_host) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->get_remote_host(socket, out_buffer,
                                               out_buffer_size);
}

avs_error_t avs_net_socket_get_remote_hostname(avs_net_socket_t *socket,
                                               char *out_buffer,
                                               size_t out_buffer_size) {
    if (!socket->operations->get_remote_hostname) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->get_remote_hostname(socket, out_buffer,
                                                   out_buffer_size);
}

avs_error_t avs_net_socket_get_remote_port(avs_net_socket_t *socket,
                                           char *out_buffer,
                                           size_t out_buffer_size) {
    if (!socket->operations->get_remote_port) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->get_remote_port(socket, out_buffer,
                                               out_buffer_size);
}

avs_error_t avs_net_socket_get_local_host(avs_net_socket_t *socket,
                                          char *out_buffer,
                                          size_t out_buffer_size) {
    if (!socket->operations->get_local_host) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->get_local_host(socket, out_buffer,
                                              out_buffer_size);
}

avs_error_t avs_net_socket_get_local_port(avs_net_socket_t *socket,
                                          char *out_buffer,
                                          size_t out_buffer_size) {
    if (!socket->operations->get_local_port) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->get_local_port(socket, out_buffer,
                                              out_buffer_size);
}

avs_error_t
avs_net_socket_get_opt(avs_net_socket_t *socket,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value) {
    if (!socket->operations->get_opt) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->get_opt(socket, option_key, out_option_value);
}

avs_error_t avs_net_socket_set_opt(avs_net_socket_t *socket,
                                   avs_net_socket_opt_key_t option_key,
                                   avs_net_socket_opt_value_t option_value) {
    if (!socket->operations->set_opt) {
        return avs_errno(AVS_ENOTSUP);
    }
    return socket->operations->set_opt(socket, option_key, option_value);
}

typedef avs_error_t (*socket_constructor_t)(avs_net_socket_t **socket,
                                            const void *socket_configuration);

static avs_error_t create_bare_socket(avs_net_socket_t **socket,
                                      socket_constructor_t socket_constructor,
                                      const void *configuration) {
    avs_error_t err = _avs_net_ensure_global_state();
    if (avs_is_err(err)) {
        LOG(ERROR, _("avs_net global state initialization error"));
        return err;
    }

    avs_net_socket_cleanup(socket);
    return socket_constructor(socket, configuration);
}

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO
static avs_error_t decorate_socket_in_place(
        avs_net_socket_t **socket,
        avs_error_t (*new_socket_constructor)(
                avs_net_socket_t **, const avs_net_ssl_configuration_t *),
        const avs_net_ssl_configuration_t *config) {
    avs_net_socket_t *new_socket = NULL;
    avs_error_t err = new_socket_constructor(&new_socket, config);
    if (avs_is_err(err)) {
        return err;
    }
    if (avs_is_err((err = avs_net_socket_decorate(new_socket, *socket)))) {
        avs_net_socket_cleanup(&new_socket);
        return err;
    }

    *socket = new_socket;
    return AVS_OK;
}

avs_error_t avs_net_dtls_socket_decorate_in_place(
        avs_net_socket_t **socket, const avs_net_ssl_configuration_t *config) {
    return decorate_socket_in_place(socket, avs_net_dtls_socket_create, config);
}

avs_error_t avs_net_ssl_socket_decorate_in_place(
        avs_net_socket_t **socket, const avs_net_ssl_configuration_t *config) {
    return decorate_socket_in_place(socket, avs_net_ssl_socket_create, config);
}
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO

#    ifdef AVS_COMMONS_NET_WITH_SOCKET_LOG

typedef struct {
    const avs_net_socket_v_table_t *const operations;
    avs_net_socket_t *socket;
} avs_net_socket_debug_t;

static FILE *volatile communication_log = NULL;

static void debug_init(void) {
    if (communication_log == NULL) {
        communication_log = fopen("DEBUG.log", "w");
    }
}

static avs_error_t connect_debug(avs_net_socket_t *debug_socket,
                                 const char *host,
                                 const char *port) {
    avs_error_t err = avs_net_socket_connect(
            ((avs_net_socket_debug_t *) debug_socket)->socket, host, port);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "Connected to %s:%s\n", host, port);
    } else {
        fprintf(communication_log, "Cannot connect to %s:%s\n", host, port);
    }
    return err;
}

static avs_error_t decorate_debug(avs_net_socket_t *debug_socket,
                                  avs_net_socket_t *backend_socket) {
    avs_error_t err = avs_net_socket_decorate(
            ((avs_net_socket_debug_t *) debug_socket)->socket, backend_socket);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "Socket successfully decorated\n");
    } else {
        fprintf(communication_log, "Could not decorate socket\n");
    }
    return err;
}

static avs_error_t send_debug(avs_net_socket_t *debug_socket,
                              const void *buffer,
                              size_t buffer_length) {
    avs_error_t err = avs_net_socket_send(
            ((avs_net_socket_debug_t *) debug_socket)->socket, buffer,
            buffer_length);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "\n----------SEND----------\n");
        fwrite(buffer, 1, buffer_length, communication_log);
        fprintf(communication_log, "\n--------SEND-END--------\n");
        fflush(communication_log);
    } else {
        fprintf(communication_log, "\n------SEND-FAILURE------\n");
    }
    return err;
}

static avs_error_t send_to_debug(avs_net_socket_t *debug_socket,
                                 const void *buffer,
                                 size_t buffer_length,
                                 const char *host,
                                 const char *port) {
    avs_error_t err = avs_net_socket_send_to(
            ((avs_net_socket_debug_t *) debug_socket)->socket, buffer,
            buffer_length, host, port);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "\n--------SEND-TO---------\n");
        fprintf(communication_log, "%s:%s\n", host, port);
        fprintf(communication_log, "------------------------\n");
        fwrite(buffer, 1, buffer_length, communication_log);
        fprintf(communication_log, "\n--------SEND-END--------\n");
        fflush(communication_log);
    } else {
        fprintf(communication_log, "\n----SEND-TO-FAILURE-----\n");
    }
    return err;
}

static avs_error_t receive_debug(avs_net_socket_t *debug_socket,
                                 size_t *out_bytes_received,
                                 void *buffer,
                                 size_t buffer_length) {
    avs_error_t err = avs_net_socket_receive(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_bytes_received, buffer, buffer_length);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "\n----------RECV----------\n");
        fwrite(buffer, 1, (size_t) *out_bytes_received, communication_log);
        fprintf(communication_log, "\n--------RECV-END--------\n");
        fflush(communication_log);
    } else {
        fprintf(communication_log, "\n------RECV-FAILURE------\n");
    }
    return err;
}

static avs_error_t receive_from_debug(avs_net_socket_t *debug_socket,
                                      size_t *out_bytes_received,
                                      void *buffer,
                                      size_t buffer_length,
                                      char *host,
                                      size_t host_size,
                                      char *port,
                                      size_t port_size) {
    avs_error_t err = avs_net_socket_receive_from(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_bytes_received, buffer, buffer_length, host, host_size, port,
            port_size);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "\n--------RECV-FROM--------\n");
        fprintf(communication_log, "%s:%s\n", host, port);
        fprintf(communication_log, "---------------------------\n");
        fwrite(buffer, 1, (size_t) *out_bytes_received, communication_log);
        fprintf(communication_log, "\n--------RECV-END---------\n");
        fflush(communication_log);
    } else {
        fprintf(communication_log, "\n----RECV-FROM-FAILURE----\n");
    }
    return err;
}

static avs_error_t bind_debug(avs_net_socket_t *debug_socket,
                              const char *localaddr,
                              const char *port) {
    avs_error_t err = avs_net_socket_bind(
            ((avs_net_socket_debug_t *) debug_socket)->socket, localaddr, port);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "Socket bound to %s:%s\n", localaddr, port);
    } else {
        fprintf(communication_log, "Cannot bind to %s:%s\n", localaddr, port);
    }
    return err;
}

static avs_error_t accept_debug(avs_net_socket_t *server_debug_socket,
                                avs_net_socket_t *new_debug_socket) {
    avs_error_t err = avs_net_socket_accept(
            ((avs_net_socket_debug_t *) server_debug_socket)->socket,
            ((avs_net_socket_debug_t *) new_debug_socket)->socket);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "Accept successful\n");
    } else {
        fprintf(communication_log, "Accept failed\n");
    }
    return err;
}

static avs_error_t close_debug(avs_net_socket_t *debug_socket) {
    avs_error_t err = avs_net_socket_close(
            ((avs_net_socket_debug_t *) debug_socket)->socket);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "Socket closing successful\n");
    } else {
        fprintf(communication_log, "Socket closing failed\n");
    }
    return err;
}

static avs_error_t shutdown_debug(avs_net_socket_t *debug_socket) {
    avs_error_t err = avs_net_socket_shutdown(
            ((avs_net_socket_debug_t *) debug_socket)->socket);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "Socket shutdown successful\n");
    } else {
        fprintf(communication_log, "Socket shutdown failed\n");
    }
    return err;
}

static avs_error_t
interface_name_debug(avs_net_socket_t *debug_socket,
                     avs_net_socket_interface_name_t *if_name) {
    avs_error_t err = avs_net_socket_interface_name(
            ((avs_net_socket_debug_t *) debug_socket)->socket, if_name);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "interface name: %s\n", *if_name);
    } else {
        fprintf(communication_log, "cannot get interface name\n");
    }
    return err;
}

static avs_error_t remote_host_debug(avs_net_socket_t *debug_socket,
                                     char *out_buffer,
                                     size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_remote_host(
            ((avs_net_socket_debug_t *) debug_socket)->socket, out_buffer,
            out_buffer_size);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "remote host: %s\n", out_buffer);
    } else {
        fprintf(communication_log, "cannot get remote host\n");
    }
    return err;
}

static avs_error_t remote_hostname_debug(avs_net_socket_t *debug_socket,
                                         char *out_buffer,
                                         size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_remote_hostname(
            ((avs_net_socket_debug_t *) debug_socket)->socket, out_buffer,
            out_buffer_size);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "remote host: %s\n", out_buffer);
    } else {
        fprintf(communication_log, "cannot get remote hostname\n");
    }
    return err;
}

static avs_error_t remote_port_debug(avs_net_socket_t *debug_socket,
                                     char *out_buffer,
                                     size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_remote_port(
            ((avs_net_socket_debug_t *) debug_socket)->socket, out_buffer,
            out_buffer_size);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "remote port: %s\n", out_buffer);
    } else {
        fprintf(communication_log, "cannot get remote port\n");
    }
    return err;
}

static avs_error_t local_host_debug(avs_net_socket_t *debug_socket,
                                    char *out_buffer,
                                    size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_local_host(
            ((avs_net_socket_debug_t *) debug_socket)->socket, out_buffer,
            out_buffer_size);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "local host: %s\n", out_buffer);
    } else {
        fprintf(communication_log, "cannot get local host\n");
    }
    return err;
}

static avs_error_t local_port_debug(avs_net_socket_t *debug_socket,
                                    char *out_buffer,
                                    size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_local_port(
            ((avs_net_socket_debug_t *) debug_socket)->socket, out_buffer,
            out_buffer_size);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "local port: %s\n", out_buffer);
    } else {
        fprintf(communication_log, "cannot get local port\n");
    }
    return err;
}

static avs_error_t get_opt_debug(avs_net_socket_t *debug_socket,
                                 avs_net_socket_opt_key_t option_key,
                                 avs_net_socket_opt_value_t *out_option_value) {
    avs_error_t err = avs_net_socket_get_opt(
            ((avs_net_socket_debug_t *) debug_socket)->socket, option_key,
            out_option_value);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "get opt: %d, value: %s\n", option_key,
                AVS_TIME_DURATION_AS_STRING(out_option_value->recv_timeout));
    } else {
        fprintf(communication_log, "cannot get opt %d\n", option_key);
    }
    return err;
}

static avs_error_t set_opt_debug(avs_net_socket_t *debug_socket,
                                 avs_net_socket_opt_key_t option_key,
                                 avs_net_socket_opt_value_t option_value) {
    avs_error_t err = avs_net_socket_set_opt(
            ((avs_net_socket_debug_t *) debug_socket)->socket, option_key,
            option_value);
    if (avs_is_ok(err)) {
        fprintf(communication_log, "set opt: %d\n", option_key);
    } else {
        fprintf(communication_log, "cannot set opt %d\n", option_key);
    }
    return err;
}

static const void *system_socket_debug(avs_net_socket_t *debug_socket) {
    return avs_net_socket_get_system(
            ((avs_net_socket_debug_t *) debug_socket)->socket);
}

static avs_error_t cleanup_debug(avs_net_socket_t **debug_socket) {
    avs_error_t err = avs_net_socket_cleanup(
            &(*((avs_net_socket_debug_t **) debug_socket))->socket);
    avs_free(*debug_socket);
    *debug_socket = NULL;
    return err;
}

static const avs_net_socket_v_table_t debug_vtable = {
    connect_debug,        decorate_debug,    send_debug,
    send_to_debug,        receive_debug,     receive_from_debug,
    bind_debug,           accept_debug,      close_debug,
    shutdown_debug,       cleanup_debug,     system_socket_debug,
    interface_name_debug, remote_host_debug, remote_hostname_debug,
    remote_port_debug,    local_host_debug,  local_port_debug,
    get_opt_debug,        set_opt_debug
};

static avs_error_t create_socket_debug(avs_net_socket_t **debug_socket,
                                       avs_net_socket_t *backend_socket) {
    avs_net_socket_cleanup(debug_socket);

    avs_net_socket_debug_t *sock = (avs_net_socket_debug_t *) avs_malloc(
            sizeof(avs_net_socket_debug_t));
    *debug_socket = (avs_net_socket_t *) sock;
    if (*debug_socket) {
        avs_net_socket_debug_t new_socket = { &debug_vtable, NULL };
        new_socket.socket = backend_socket;
        memcpy(*debug_socket, &new_socket, sizeof(new_socket));
        return AVS_OK;
    } else {
        return avs_errno(AVS_ENOMEM);
    }
}

static avs_error_t
init_debug_socket_if_applicable(avs_net_socket_t **debug_socket,
                                avs_error_t curr_err) {
    if (avs_is_ok(curr_err) && _avs_net_socket_debug) {
        debug_init();
        avs_net_socket_t *backend_socket = *debug_socket;
        *debug_socket = NULL;
        curr_err = create_socket_debug(debug_socket, backend_socket);
        if (avs_is_err(curr_err)) {
            avs_net_socket_cleanup(&backend_socket);
        }
    }
    return curr_err;
}
#    endif /* AVS_COMMONS_NET_WITH_SOCKET_LOG */
#    ifdef AVS_COMMONS_WITH_TRAFFIC_INTERCEPTOR
typedef struct {
    const avs_net_socket_v_table_t *const operations;
    avs_net_socket_t *socket;
    avs_net_socket_type_t type;
} avs_api_socket_interceptor_t;

static avs_error_t connect_intercept(avs_net_socket_t *intercept_socket,
                                     const char *host,
                                     const char *port) {
    avs_error_t err = avs_net_socket_connect(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket, host,
            port);
    return err;
}

static avs_error_t decorate_intercept(avs_net_socket_t *intercept_socket,
                                      avs_net_socket_t *backend_socket) {
    avs_error_t err = avs_net_socket_decorate(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            backend_socket);
    return err;
}
static avs_error_t send_intercept(avs_net_socket_t *intercept_socket,
                                  const void *buffer,
                                  size_t buffer_length) {
    const avs_api_socket_interceptor_t *interceptor_socket_impl =
            (avs_api_socket_interceptor_t *) intercept_socket;
    avs_error_t err = avs_net_socket_send(interceptor_socket_impl->socket,
                                          buffer, buffer_length);
    if (avs_is_ok(err)) {
        _avs_net_traffic_interceptor(intercept_socket, buffer, buffer_length,
                                     interceptor_socket_impl->type,
                                     AVS_NET_TRAFFIC_INTERCEPTOR_OUTGOING);
    }
    return err;
}

static avs_error_t send_to_intercept(avs_net_socket_t *intercept_socket,
                                     const void *buffer,
                                     size_t buffer_length,
                                     const char *host,
                                     const char *port) {
    const avs_api_socket_interceptor_t *interceptor_socket_impl =
            (avs_api_socket_interceptor_t *) intercept_socket;
    avs_error_t err = avs_net_socket_send_to(interceptor_socket_impl->socket,
                                             buffer, buffer_length, host, port);
    if (avs_is_ok(err)) {
        _avs_net_traffic_interceptor(intercept_socket, buffer, buffer_length,
                                     interceptor_socket_impl->type,
                                     AVS_NET_TRAFFIC_INTERCEPTOR_OUTGOING);
    }
    return err;
}

static avs_error_t receive_intercept(avs_net_socket_t *intercept_socket,
                                     size_t *out_bytes_received,
                                     void *buffer,
                                     size_t buffer_length) {
    const avs_api_socket_interceptor_t *interceptor_socket_impl =
            (avs_api_socket_interceptor_t *) intercept_socket;
    avs_error_t err =
            avs_net_socket_receive(interceptor_socket_impl->socket,
                                   out_bytes_received, buffer, buffer_length);
    if (avs_is_ok(err)) {
        _avs_net_traffic_interceptor(intercept_socket, buffer,
                                     *out_bytes_received,
                                     interceptor_socket_impl->type,
                                     AVS_NET_TRAFFIC_INTERCEPTOR_INCOMING);
    }
    return err;
}

static avs_error_t receive_from_intercept(avs_net_socket_t *intercept_socket,
                                          size_t *out_bytes_received,
                                          void *buffer,
                                          size_t buffer_length,
                                          char *host,
                                          size_t host_size,
                                          char *port,
                                          size_t port_size) {
    avs_api_socket_interceptor_t *interceptor_socket_impl =
            (avs_api_socket_interceptor_t *) intercept_socket;
    avs_error_t err = avs_net_socket_receive_from(
            interceptor_socket_impl->socket, out_bytes_received, buffer,
            buffer_length, host, host_size, port, port_size);
    if (avs_is_ok(err)) {
        _avs_net_traffic_interceptor(intercept_socket, buffer,
                                     *out_bytes_received,
                                     interceptor_socket_impl->type,
                                     AVS_NET_TRAFFIC_INTERCEPTOR_INCOMING);
    }
    return err;
}

static avs_error_t bind_intercept(avs_net_socket_t *intercept_socket,
                                  const char *localaddr,
                                  const char *port) {
    avs_error_t err = avs_net_socket_bind(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            localaddr, port);
    return err;
}

static avs_error_t accept_intercept(avs_net_socket_t *server_intercept_socket,
                                    avs_net_socket_t *new_intercept_socket) {
    avs_error_t err = avs_net_socket_accept(
            ((avs_api_socket_interceptor_t *) server_intercept_socket)->socket,
            ((avs_api_socket_interceptor_t *) new_intercept_socket)->socket);
    return err;
}

static avs_error_t close_intercept(avs_net_socket_t *intercept_socket) {
    avs_error_t err = avs_net_socket_close(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket);
    return err;
}

static avs_error_t shutdown_intercept(avs_net_socket_t *intercept_socket) {
    avs_error_t err = avs_net_socket_shutdown(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket);
    return err;
}

static avs_error_t
interface_name_intercept(avs_net_socket_t *intercept_socket,
                         avs_net_socket_interface_name_t *if_name) {
    avs_error_t err = avs_net_socket_interface_name(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            if_name);
    return err;
}

static avs_error_t remote_host_intercept(avs_net_socket_t *intercept_socket,
                                         char *out_buffer,
                                         size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_remote_host(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            out_buffer, out_buffer_size);
    return err;
}

static avs_error_t remote_hostname_intercept(avs_net_socket_t *intercept_socket,
                                             char *out_buffer,
                                             size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_remote_hostname(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            out_buffer, out_buffer_size);
    return err;
}

static avs_error_t remote_port_intercept(avs_net_socket_t *intercept_socket,
                                         char *out_buffer,
                                         size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_remote_port(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            out_buffer, out_buffer_size);
    return err;
}

static avs_error_t local_host_intercept(avs_net_socket_t *intercept_socket,
                                        char *out_buffer,
                                        size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_local_host(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            out_buffer, out_buffer_size);
    return err;
}

static avs_error_t local_port_intercept(avs_net_socket_t *intercept_socket,
                                        char *out_buffer,
                                        size_t out_buffer_size) {
    avs_error_t err = avs_net_socket_get_local_port(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            out_buffer, out_buffer_size);
    return err;
}

static avs_error_t
get_opt_intercept(avs_net_socket_t *intercept_socket,
                  avs_net_socket_opt_key_t option_key,
                  avs_net_socket_opt_value_t *out_option_value) {
    avs_error_t err = avs_net_socket_get_opt(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            option_key, out_option_value);
    return err;
}

static avs_error_t set_opt_intercept(avs_net_socket_t *intercept_socket,
                                     avs_net_socket_opt_key_t option_key,
                                     avs_net_socket_opt_value_t option_value) {
    avs_error_t err = avs_net_socket_set_opt(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket,
            option_key, option_value);
    return err;
}

static const void *system_socket_intercept(avs_net_socket_t *intercept_socket) {
    return avs_net_socket_get_system(
            ((avs_api_socket_interceptor_t *) intercept_socket)->socket);
}

static avs_error_t cleanup_intercept(avs_net_socket_t **intercept_socket) {
    avs_error_t err = avs_net_socket_cleanup(
            &(*((avs_api_socket_interceptor_t **) intercept_socket))->socket);
    avs_free(*intercept_socket);
    *intercept_socket = NULL;
    return err;
}

static const avs_net_socket_v_table_t interceptor_vtable = {
    connect_intercept,        decorate_intercept,    send_intercept,
    send_to_intercept,        receive_intercept,     receive_from_intercept,
    bind_intercept,           accept_intercept,      close_intercept,
    shutdown_intercept,       cleanup_intercept,     system_socket_intercept,
    interface_name_intercept, remote_host_intercept, remote_hostname_intercept,
    remote_port_intercept,    local_host_intercept,  local_port_intercept,
    get_opt_intercept,        set_opt_intercept
};

static avs_error_t
create_socket_interceptor(avs_net_socket_t **interceptor_socket,
                          avs_net_socket_t *backend_socket,
                          avs_net_socket_type_t type) {
    avs_net_socket_cleanup(interceptor_socket);

    avs_api_socket_interceptor_t *sock =
            (avs_api_socket_interceptor_t *) avs_malloc(
                    sizeof(avs_api_socket_interceptor_t));
    *interceptor_socket = (avs_net_socket_t *) sock;
    if (*interceptor_socket) {
        avs_api_socket_interceptor_t new_socket = { &interceptor_vtable,
                                                    backend_socket, type };
        memcpy(*interceptor_socket, &new_socket, sizeof(new_socket));
        return AVS_OK;
    }
    return avs_errno(AVS_ENOMEM);
}

static avs_error_t
init_traffic_interceptor_if_applicable(avs_net_socket_t **interceptor_socket,
                                       avs_net_socket_type_t type,
                                       avs_error_t curr_err) {
    if (avs_is_ok(curr_err)) {
        avs_net_socket_t *backend_socket = *interceptor_socket;
        *interceptor_socket = NULL;
        curr_err = create_socket_interceptor(interceptor_socket, backend_socket,
                                             type);
        if (avs_is_err(curr_err)) {
            avs_net_socket_cleanup(&backend_socket);
        }
    }
    return curr_err;
}
#    endif // AVS_COMMONS_WITH_TRAFFIC_INTERCEPTOR

avs_error_t
avs_net_udp_socket_create(avs_net_socket_t **socket,
                          const avs_net_socket_configuration_t *config) {
    avs_error_t err =
            create_bare_socket(socket, _avs_net_create_udp_socket, config);
#    if defined(AVS_COMMONS_NET_WITH_SOCKET_LOG)
    return init_debug_socket_if_applicable(socket, err);
#    elif defined(AVS_COMMONS_WITH_TRAFFIC_INTERCEPTOR)
    return init_traffic_interceptor_if_applicable(socket, AVS_NET_UDP_SOCKET,
                                                  err);
#    else
    return err;
#    endif
}

avs_error_t
avs_net_tcp_socket_create(avs_net_socket_t **socket,
                          const avs_net_socket_configuration_t *config) {
    avs_error_t err =
            create_bare_socket(socket, _avs_net_create_tcp_socket, config);
#    if defined(AVS_COMMONS_NET_WITH_SOCKET_LOG)
    return init_debug_socket_if_applicable(socket, err);
#    elif defined(AVS_COMMONS_WITH_TRAFFIC_INTERCEPTOR)
    return init_traffic_interceptor_if_applicable(socket, AVS_NET_TCP_SOCKET,
                                                  err);
#    else
    return err;
#    endif
}

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO
avs_error_t
avs_net_dtls_socket_create(avs_net_socket_t **socket,
                           const avs_net_ssl_configuration_t *config) {
#        ifndef AVS_COMMONS_WITHOUT_TLS
    if (!config->prng_ctx) {
        LOG(ERROR, _("PRNG ctx MUST NOT be NULL"));
        return avs_errno(AVS_EINVAL);
    }
    avs_error_t err =
            create_bare_socket(socket, _avs_net_create_dtls_socket, config);
#            if defined(AVS_COMMONS_NET_WITH_SOCKET_LOG)
    return init_debug_socket_if_applicable(socket, err);
#            elif defined(AVS_COMMONS_WITH_TRAFFIC_INTERCEPTOR)
    return init_traffic_interceptor_if_applicable(socket, AVS_NET_DTLS_SOCKET,
                                                  err);
#            else
    return err;
#            endif
#        else  // AVS_COMMONS_WITHOUT_TLS
    (void) socket;
    (void) config;
    LOG(ERROR, _("could not create secure socket: (D)TLS support is disabled"));
    return avs_errno(AVS_ENOTSUP);
#        endif // AVS_COMMONS_WITHOUT_TLS
}

avs_error_t
avs_net_ssl_socket_create(avs_net_socket_t **socket,
                          const avs_net_ssl_configuration_t *config) {
#        ifndef AVS_COMMONS_WITHOUT_TLS
    if (!config->prng_ctx) {
        LOG(ERROR, _("PRNG ctx MUST NOT be NULL"));
        return avs_errno(AVS_EINVAL);
    }
    avs_error_t err =
            create_bare_socket(socket, _avs_net_create_ssl_socket, config);
#            if defined(AVS_COMMONS_NET_WITH_SOCKET_LOG)
    return init_debug_socket_if_applicable(socket, err);
#            elif defined(AVS_COMMONS_WITH_TRAFFIC_INTERCEPTOR)
    return init_traffic_interceptor_if_applicable(socket, AVS_NET_SSL_SOCKET,
                                                  err);
#            else
    return err;
#            endif
#        else  // AVS_COMMONS_WITHOUT_TLS
    (void) socket;
    (void) config;
    LOG(ERROR, _("could not create secure socket: (D)TLS support is disabled"));
    return avs_errno(AVS_ENOTSUP);
#        endif // AVS_COMMONS_WITHOUT_TLS
}
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO

#endif // AVS_COMMONS_WITH_AVS_NET
