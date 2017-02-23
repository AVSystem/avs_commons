/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include <tinydtls/dtls.h>

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

typedef struct {
    const avs_net_socket_v_table_t *const operations;
    dtls_context_t *context;

    avs_net_socket_type_t backend_type;
    avs_net_abstract_socket_t *backend_socket;
    int error_code;
    avs_net_ssl_version_t version;
    avs_ssl_additional_configuration_clb_t *additional_configuration_clb;
    avs_net_socket_configuration_t backend_configuration;
} ssl_socket_t;

#include "common.h"

static const avs_net_socket_v_table_t ssl_vtable = {
    connect_ssl,
    decorate_ssl,
    send_ssl,
    (avs_net_socket_send_to_t) unimplemented,
    receive_ssl,
    (avs_net_socket_receive_from_t) unimplemented,
    bind_ssl,
    (avs_net_socket_accept_t) unimplemented,
    close_ssl,
    shutdown_ssl,
    cleanup_ssl,
    system_socket_ssl,
    interface_name_ssl,
    remote_host_ssl,
    remote_port_ssl,
    local_port_ssl,
    get_opt_ssl,
    set_opt_ssl,
    errno_ssl
};

static int get_dtls_overhead(ssl_socket_t *socket,
                             int *out_header,
                             int *out_padding_size) {
    return -1;
}

static int send_ssl(avs_net_abstract_socket_t *ssl_socket,
                    const void *buffer,
                    size_t buffer_length) {
    return -1;
}

static int receive_ssl(avs_net_abstract_socket_t *ssl_socket,
                       size_t *out,
                       void *buffer,
                       size_t buffer_length) {
    return -1;
}

static int bind_ssl(avs_net_abstract_socket_t *socket,
                    const char *localaddr,
                    const char *port) {
    return -1;
}

static int shutdown_ssl(avs_net_abstract_socket_t *socket) {
    return -1;
}

static int cleanup_ssl(avs_net_abstract_socket_t **ssl_socket) {
    return -1;
}

static void close_ssl_raw(ssl_socket_t *socket) {
    return;
}

static int is_ssl_started(ssl_socket_t *socket) {
    return -1;
}

static int start_ssl(ssl_socket_t *socket, const char *host) {
    return -1;
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 avs_net_socket_type_t backend_type,
                                 const avs_net_ssl_configuration_t *configuration) {
    dtls_init();
}
