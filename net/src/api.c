/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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
#include <avs_commons_config.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <avsystem/commons/memory.h>
#include <avsystem/commons/net.h>
#include <avsystem/commons/socket.h>
#include <avsystem/commons/socket_v_table.h>

#include "global.h"
#include "net_impl.h"
#include "api.h"

VISIBILITY_SOURCE_BEGIN

const avs_time_duration_t AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT = { 30, 0 };

avs_net_trusted_cert_info_t
avs_net_trusted_cert_info_from_file(const char *filename) {
    avs_net_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_NET_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_NET_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    return result;
}

avs_net_trusted_cert_info_t
avs_net_trusted_cert_info_from_path(const char *path) {
    avs_net_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_NET_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_NET_DATA_SOURCE_PATH;
    result.desc.info.path.path = path;
    return result;
}

avs_net_trusted_cert_info_t
avs_net_trusted_cert_info_from_buffer(const void *buffer,
                                      size_t buffer_size) {
    avs_net_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_NET_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_NET_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    return result;
}

avs_net_client_key_info_t
avs_net_client_key_info_from_file(const char *filename,
                                  const char *password) {
    avs_net_client_key_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_NET_SECURITY_INFO_CLIENT_KEY;
    result.desc.source = AVS_NET_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    result.desc.info.file.password = password;
    return result;
}

avs_net_client_key_info_t
avs_net_client_key_info_from_buffer(const void *buffer,
                                    size_t buffer_size,
                                    const char *password) {
    avs_net_client_key_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_NET_SECURITY_INFO_CLIENT_KEY;
    result.desc.source = AVS_NET_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    result.desc.info.buffer.password = password;
    return result;
}

avs_net_client_cert_info_t
avs_net_client_cert_info_from_file(const char *filename) {
    avs_net_client_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_NET_SECURITY_INFO_CLIENT_CERT;
    result.desc.source = AVS_NET_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    return result;
}

avs_net_client_cert_info_t
avs_net_client_cert_info_from_buffer(const void *buffer,
                                     size_t buffer_size) {
    avs_net_client_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_NET_SECURITY_INFO_CLIENT_CERT;
    result.desc.source = AVS_NET_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    return result;
}

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

#ifdef WITH_SOCKET_LOG
static int _avs_net_socket_debug = 0;

int avs_net_socket_debug(int value) {
    int prev_value = !!_avs_net_socket_debug;
    if (value >= 0) {
        _avs_net_socket_debug = !!value;
    }
    return prev_value;
}
#else
int avs_net_socket_debug(int value) {
    if (value > 0) {
        return -1;
    }
    return 0;
}
#endif

struct avs_net_abstract_socket_struct {
    const avs_net_socket_v_table_t * const operations;
};

int avs_net_socket_connect(avs_net_abstract_socket_t *socket,
                           const char *host,
                           const char *port) {
    return socket->operations->connect(socket, host, port);
}

int avs_net_socket_decorate(avs_net_abstract_socket_t *socket,
                            avs_net_abstract_socket_t *backend_socket) {
    return socket->operations->decorate(socket, backend_socket);
}

int avs_net_socket_send(avs_net_abstract_socket_t *socket,
                        const void *buffer,
                        size_t buffer_length) {
    return socket->operations->send(socket, buffer, buffer_length);
}

int avs_net_socket_send_to(avs_net_abstract_socket_t *socket,
                           const void *buffer,
                           size_t buffer_length,
                           const char *host,
                           const char *port) {
    return socket->operations->send_to(socket, buffer, buffer_length,
                                       host, port);
}

int avs_net_socket_receive(avs_net_abstract_socket_t *socket,
                           size_t *out_bytes_received,
                           void *buffer,
                           size_t buffer_length) {
    return socket->operations->receive(socket, out_bytes_received,
                                       buffer, buffer_length);
}

int avs_net_socket_receive_from(avs_net_abstract_socket_t *socket,
                                size_t *out_bytes_received,
                                void *buffer,
                                size_t buffer_length,
                                char *host, size_t host_size,
                                char *port, size_t port_size) {
    return socket->operations->receive_from(socket, out_bytes_received,
                                            buffer, buffer_length,
                                            host, host_size,
                                            port, port_size);
}

int avs_net_socket_bind(avs_net_abstract_socket_t *socket,
                        const char *address,
                        const char *port) {
    return socket->operations->bind(socket, address, port);
}

int avs_net_socket_accept(avs_net_abstract_socket_t *server_socket,
                          avs_net_abstract_socket_t *client_socket) {
    return server_socket->operations->accept(server_socket, client_socket);
}

int avs_net_socket_close(avs_net_abstract_socket_t *socket) {
    return socket->operations->close(socket);
}

int avs_net_socket_shutdown(avs_net_abstract_socket_t *socket) {
    return socket->operations->shutdown(socket);
}

int avs_net_socket_cleanup(avs_net_abstract_socket_t **socket) {
    if (*socket) {
        return (*socket)->operations->cleanup(socket);
    } else {
        return -1;
    }
}

const void *avs_net_socket_get_system(avs_net_abstract_socket_t *socket) {
    const void *out = NULL;
    if (socket->operations->get_system_socket(socket, &out) < 0) {
        return NULL;
    } else {
        return out;
    }
}

int avs_net_socket_interface_name(avs_net_abstract_socket_t *socket,
                                  avs_net_socket_interface_name_t *if_name) {
    return socket->operations->get_interface_name(socket, if_name);
}

int avs_net_socket_get_remote_host(avs_net_abstract_socket_t *socket,
                                   char *out_buffer, size_t out_buffer_size) {
    return socket->operations->get_remote_host(socket,
                                               out_buffer, out_buffer_size);
}

int avs_net_socket_get_remote_hostname(avs_net_abstract_socket_t *socket,
                                       char *out_buffer,
                                       size_t out_buffer_size) {
    return socket->operations->get_remote_hostname(socket,
                                                   out_buffer, out_buffer_size);
}

int avs_net_socket_get_remote_port(avs_net_abstract_socket_t *socket,
                                   char *out_buffer, size_t out_buffer_size) {
    return socket->operations->get_remote_port(socket,
                                               out_buffer, out_buffer_size);
}

int avs_net_socket_get_local_host(avs_net_abstract_socket_t *socket,
                                  char *out_buffer, size_t out_buffer_size) {
    return socket->operations->get_local_host(socket,
                                              out_buffer, out_buffer_size);
}

int avs_net_socket_get_local_port(avs_net_abstract_socket_t *socket,
                                  char *out_buffer, size_t out_buffer_size) {
    return socket->operations->get_local_port(socket,
                                              out_buffer, out_buffer_size);
}

int avs_net_socket_get_opt(avs_net_abstract_socket_t *socket,
                           avs_net_socket_opt_key_t option_key,
                           avs_net_socket_opt_value_t *out_option_value) {
    return socket->operations->get_opt(socket, option_key, out_option_value);
}

int avs_net_socket_set_opt(avs_net_abstract_socket_t *socket,
                           avs_net_socket_opt_key_t option_key,
                           avs_net_socket_opt_value_t option_value) {
    return socket->operations->set_opt(socket, option_key, option_value);
}

int avs_net_socket_errno(avs_net_abstract_socket_t *socket) {
    return socket->operations->get_errno(socket);
}

typedef int (*socket_constructor_t)(avs_net_abstract_socket_t **socket,
                                    const void *socket_configuration);

static socket_constructor_t
get_constructor_for_socket_type(avs_net_socket_type_t type) {
    switch (type) {
    case AVS_NET_TCP_SOCKET:
        return _avs_net_create_tcp_socket;
    case AVS_NET_UDP_SOCKET:
        return _avs_net_create_udp_socket;
    case AVS_NET_SSL_SOCKET:
    case AVS_NET_DTLS_SOCKET:
#ifdef WITH_SSL
        return type == AVS_NET_SSL_SOCKET ? _avs_net_create_ssl_socket
                                          : _avs_net_create_dtls_socket;
#else
        LOG(ERROR, "could not create secure socket: (D)TLS support is disabled");
        return NULL;
#endif // WITH_SSL
    default:
        LOG(ERROR, "unknown socket type: %d", (int) type);
        return NULL;
    }
}

static int create_bare_socket(avs_net_abstract_socket_t **socket,
                              avs_net_socket_type_t type,
                              const void *configuration) {
    if (_avs_net_ensure_global_state()) {
        LOG(ERROR, "avs_net global state initialization error");
        return -1;
    }

    socket_constructor_t constructor = get_constructor_for_socket_type(type);

    avs_net_socket_cleanup(socket);
    if (constructor) {
        return constructor(socket, configuration);
    } else {
        return -1;
    }
}

int avs_net_socket_decorate_in_place(avs_net_abstract_socket_t **socket,
                                     avs_net_socket_type_t new_type,
                                     const void *configuration) {
    avs_net_abstract_socket_t *new_socket = NULL;
    if (avs_net_socket_create(&new_socket, new_type, configuration)) {
        return -1;
    }
    if (avs_net_socket_decorate(new_socket, *socket)) {
        avs_net_socket_cleanup(&new_socket);
        return -1;
    }

    *socket = new_socket;
    return 0;
}

#ifdef WITH_SOCKET_LOG

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    avs_net_abstract_socket_t *socket;
} avs_net_socket_debug_t;

static FILE *volatile communication_log = NULL;

static void debug_init(void) {
    if (communication_log == NULL) {
        communication_log = fopen("DEBUG.log", "w");
    }
}

static int connect_debug(avs_net_abstract_socket_t *debug_socket,
                         const char *host,
                         const char *port) {
    int result = avs_net_socket_connect(
            ((avs_net_socket_debug_t *) debug_socket)->socket, host, port);
    if (result) {
        fprintf(communication_log,
                "Cannot connect to %s:%s\n", host, port);
    } else {
        fprintf(communication_log,
                "Connected to %s:%s\n", host, port);
    }
    return result;
}

static int decorate_debug(avs_net_abstract_socket_t *debug_socket,
                          avs_net_abstract_socket_t *backend_socket) {
    int result = avs_net_socket_decorate(
            ((avs_net_socket_debug_t *) debug_socket)->socket, backend_socket);
    if (result) {
        fprintf(communication_log, "Could not decorate socket\n");
    } else {
        fprintf(communication_log, "Socket successfully decorated\n");
    }
    return result;
}

static int send_debug(avs_net_abstract_socket_t *debug_socket,
                      const void *buffer,
                      size_t buffer_length) {
    int result = avs_net_socket_send(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            buffer, buffer_length);
    if (result) {
        fprintf(communication_log, "\n------SEND-FAILURE------\n");
    } else {
        fprintf(communication_log, "\n----------SEND----------\n");
        fwrite(buffer, 1, buffer_length, communication_log);
        fprintf(communication_log, "\n--------SEND-END--------\n");
        fflush(communication_log);
    }
    return result;
}

static int send_to_debug(avs_net_abstract_socket_t *debug_socket,
                         const void *buffer,
                         size_t buffer_length,
                         const char *host,
                         const char *port) {
    int result = avs_net_socket_send_to(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            buffer, buffer_length, host, port);
    if (result) {
        fprintf(communication_log, "\n----SEND-TO-FAILURE-----\n");
    } else {
        fprintf(communication_log, "\n--------SEND-TO---------\n");
        fprintf(communication_log, "%s:%s\n", host, port);
        fprintf(communication_log, "------------------------\n");
        fwrite(buffer, 1, buffer_length, communication_log);
        fprintf(communication_log, "\n--------SEND-END--------\n");
        fflush(communication_log);
    }
    return result;
}

static int receive_debug(avs_net_abstract_socket_t *debug_socket,
                         size_t *out_bytes_received,
                         void *buffer,
                         size_t buffer_length) {
    int result = avs_net_socket_receive(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_bytes_received, buffer, buffer_length);
    if (result < 0) {
        fprintf(communication_log, "\n------RECV-FAILURE------\n");
    } else {
        fprintf(communication_log, "\n----------RECV----------\n");
        fwrite(buffer, 1, (size_t) *out_bytes_received, communication_log);
        fprintf(communication_log, "\n--------RECV-END--------\n");
        fflush(communication_log);
    }
    return result;
}

static int receive_from_debug(avs_net_abstract_socket_t *debug_socket,
                              size_t *out_bytes_received,
                              void *buffer,
                              size_t buffer_length,
                              char *host, size_t host_size,
                              char *port, size_t port_size) {
    int result = avs_net_socket_receive_from(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_bytes_received,
            buffer, buffer_length, host, host_size, port, port_size);
    if (result < 0) {
        fprintf(communication_log, "\n----RECV-FROM-FAILURE----\n");
    } else {
        fprintf(communication_log, "\n--------RECV-FROM--------\n");
        fprintf(communication_log, "%s:%s\n", host, port);
        fprintf(communication_log, "---------------------------\n");
        fwrite(buffer, 1, (size_t) *out_bytes_received, communication_log);
        fprintf(communication_log, "\n--------RECV-END---------\n");
        fflush(communication_log);
    }
    return result;
}

static int bind_debug(avs_net_abstract_socket_t *debug_socket,
                      const char *localaddr,
                      const char *port) {
    int result = avs_net_socket_bind(
            ((avs_net_socket_debug_t *) debug_socket)->socket, localaddr, port);
    if (result) {
        fprintf(communication_log,
                "Cannot bind to %s:%s\n", localaddr, port);
    } else {
        fprintf(communication_log,
                "Socket bound to %s:%s\n", localaddr, port);
    }
    return result;
}

static int accept_debug(avs_net_abstract_socket_t *server_debug_socket,
                        avs_net_abstract_socket_t *new_debug_socket) {
    int result = avs_net_socket_accept(
            ((avs_net_socket_debug_t *) server_debug_socket)->socket,
            ((avs_net_socket_debug_t *) new_debug_socket)->socket);
    if (result) {
        fprintf(communication_log, "Accept failed\n");
    } else {
        fprintf(communication_log, "Accept successful\n");
    }
    return result;
}

static int close_debug(avs_net_abstract_socket_t *debug_socket) {
    int result = avs_net_socket_close(
            ((avs_net_socket_debug_t *) debug_socket)->socket);
    if (result) {
        fprintf(communication_log, "Socket closing failed\n");
    } else {
        fprintf(communication_log, "Socket closing successful\n");
    }
    return result;
}

static int shutdown_debug(avs_net_abstract_socket_t *debug_socket) {
    int result = avs_net_socket_shutdown(
            ((avs_net_socket_debug_t *) debug_socket)->socket);
    if (result) {
        fprintf(communication_log, "Socket shutdown failed\n");
    } else {
        fprintf(communication_log, "Socket shutdown successful\n");
    }
    return result;
}

static int interface_name_debug(avs_net_abstract_socket_t *debug_socket,
                                avs_net_socket_interface_name_t *if_name) {
    int result = avs_net_socket_interface_name(
            ((avs_net_socket_debug_t *) debug_socket)->socket, if_name);
    if (result) {
        fprintf(communication_log, "cannot get interface name\n");
    } else {
        fprintf(communication_log, "interface name: %s\n", *if_name);
    }
    return result;
}

static int remote_host_debug(avs_net_abstract_socket_t *debug_socket,
                             char *out_buffer, size_t out_buffer_size) {
    int result = avs_net_socket_get_remote_host(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_buffer, out_buffer_size);
    if (result) {
        fprintf(communication_log, "cannot get remote host\n");
    } else {
        fprintf(communication_log, "remote host: %s\n", out_buffer);
    }
    return result;
}

static int remote_hostname_debug(avs_net_abstract_socket_t *debug_socket,
                                 char *out_buffer, size_t out_buffer_size) {
    int result = avs_net_socket_get_remote_hostname(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_buffer, out_buffer_size);
    if (result) {
        fprintf(communication_log, "cannot get remote hostname\n");
    } else {
        fprintf(communication_log, "remote host: %s\n", out_buffer);
    }
    return result;
}

static int remote_port_debug(avs_net_abstract_socket_t *debug_socket,
                             char *out_buffer, size_t out_buffer_size) {
    int result = avs_net_socket_get_remote_port(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_buffer, out_buffer_size);
    if (result) {
        fprintf(communication_log, "cannot get remote port\n");
    } else {
        fprintf(communication_log, "remote port: %s\n", out_buffer);
    }
    return result;
}

static int local_host_debug(avs_net_abstract_socket_t *debug_socket,
                            char *out_buffer, size_t out_buffer_size) {
    int result = avs_net_socket_get_local_host(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_buffer, out_buffer_size);
    if (result) {
        fprintf(communication_log, "cannot get local host\n");
    } else {
        fprintf(communication_log, "local host: %s\n", out_buffer);
    }
    return result;
}

static int local_port_debug(avs_net_abstract_socket_t *debug_socket,
                            char *out_buffer, size_t out_buffer_size) {
    int result = avs_net_socket_get_local_port(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
            out_buffer, out_buffer_size);
    if (result) {
        fprintf(communication_log, "cannot get local port\n");
    } else {
        fprintf(communication_log, "local port: %s\n", out_buffer);
    }
    return result;
}

static int get_opt_debug(avs_net_abstract_socket_t *debug_socket,
                         avs_net_socket_opt_key_t option_key,
                         avs_net_socket_opt_value_t *out_option_value) {
    int result = avs_net_socket_get_opt(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
                                      option_key, out_option_value);
    if (result) {
        fprintf(communication_log, "cannot get opt %d\n", option_key);
    } else {
        fprintf(communication_log, "get opt: %d, value: "
                                   "%" PRId64 ".%09" PRId32 "\n",
                option_key, out_option_value->recv_timeout.seconds,
                out_option_value->recv_timeout.nanoseconds);
    }
    return result;
}

static int set_opt_debug(avs_net_abstract_socket_t *debug_socket,
                         avs_net_socket_opt_key_t option_key,
                         avs_net_socket_opt_value_t option_value) {
    int result = avs_net_socket_set_opt(
            ((avs_net_socket_debug_t *) debug_socket)->socket,
                                      option_key, option_value);
    if (result) {
        fprintf(communication_log, "cannot set opt %d\n", option_key);
    } else {
        fprintf(communication_log, "set opt: %d\n", option_key);
    }
    return result;
}

static int system_socket_debug(avs_net_abstract_socket_t *debug_socket,
                               const void **out) {
    *out = avs_net_socket_get_system(
            ((avs_net_socket_debug_t *) debug_socket)->socket);
    return *out ? 0 : -1;
}

static int errno_debug(avs_net_abstract_socket_t *debug_socket) {
    return avs_net_socket_errno(
            ((avs_net_socket_debug_t *) debug_socket)->socket);
}

static int cleanup_debug(avs_net_abstract_socket_t **debug_socket) {
    avs_net_socket_cleanup(&(*((avs_net_socket_debug_t **) debug_socket))->socket);
    avs_free(*debug_socket);
    *debug_socket = NULL;
    return 0;
}

static const avs_net_socket_v_table_t debug_vtable = {
    connect_debug,
    decorate_debug,
    send_debug,
    send_to_debug,
    receive_debug,
    receive_from_debug,
    bind_debug,
    accept_debug,
    close_debug,
    shutdown_debug,
    cleanup_debug,
    system_socket_debug,
    interface_name_debug,
    remote_host_debug,
    remote_hostname_debug,
    remote_port_debug,
    local_host_debug,
    local_port_debug,
    get_opt_debug,
    set_opt_debug,
    errno_debug
};

static int create_socket_debug(avs_net_abstract_socket_t **debug_socket,
                               avs_net_abstract_socket_t *backend_socket) {
    avs_net_socket_cleanup(debug_socket);

    avs_net_socket_debug_t *sock = (avs_net_socket_debug_t *)
            avs_malloc(sizeof(avs_net_socket_debug_t));
    *debug_socket = (avs_net_abstract_socket_t *) sock;
    if (*debug_socket) {
        avs_net_socket_debug_t new_socket = { &debug_vtable, NULL };
        new_socket.socket = backend_socket;
        memcpy(*debug_socket, &new_socket, sizeof(new_socket));
        return 0;
    } else {
        return -1;
    }
}

int avs_net_socket_create(avs_net_abstract_socket_t **debug_socket,
                          avs_net_socket_type_t type,
                          const void *configuration) {
    avs_net_abstract_socket_t *backend_socket = NULL;
    int result;

    if (_avs_net_socket_debug) {
        debug_init();
    }

    avs_net_socket_cleanup(debug_socket);
    result = create_bare_socket(debug_socket, type, configuration);
    if (!result && _avs_net_socket_debug) {
        debug_init();
        backend_socket = *debug_socket;
        *debug_socket = NULL;
        result = create_socket_debug(debug_socket, backend_socket);
        if (result) {
            avs_net_socket_cleanup(&backend_socket);
        }
    }
    return result;
}
#else

int avs_net_socket_create(avs_net_abstract_socket_t **socket,
                          avs_net_socket_type_t type,
                          const void *configuration) {
    return create_bare_socket(socket, type, configuration);
}

#endif /* WITH_SOCKET_LOG */

#if defined(WITH_SSL) && defined(AVS_UNIT_TESTING)
#include "test/starttls.c"
#endif
