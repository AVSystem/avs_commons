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

#define DTLS_PSK
#include <tinydtls/dtls.h>

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

typedef struct {
    const avs_net_socket_v_table_t *const operations;
    dtls_context_t *ctx;

    avs_net_socket_type_t backend_type;
    avs_net_abstract_socket_t *backend_socket;
    int error_code;
    avs_net_ssl_version_t version;
    avs_ssl_additional_configuration_clb_t *additional_configuration_clb;
    avs_net_socket_configuration_t backend_configuration;
} ssl_socket_t;

#define NET_SSL_COMMON_PRIVATE_HEADER
#include "ssl_common.h"

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
    int *socket_fd = (int *) (intptr_t) avs_net_socket_get_system(ssl_socket);
    session_t session;
    session.size = sizeof(session.addr);

    ssize_t result = recvfrom(*socket_fd, buffer, buffer_length, 0,
                              &session.addr.sa, &session.size);
    if (result < 0) {
        return result;
    }
    return dtls_handle_message(((ssl_socket_t *) ssl_socket)->ctx, &session,
                               buffer, buffer_length);
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

static int configure_ssl_psk(ssl_socket_t *socket,
                             const avs_net_psk_t *psk) {
    return -1;
}

static int configure_ssl_certs(ssl_socket_t *socket,
                               const avs_net_certificate_info_t *cert_info) {
    LOG(ERROR, "tinyDTLS backend has no support for certificate mode yet");
    return -1;
}

static int configure_ssl(ssl_socket_t *socket,
                         const avs_net_ssl_configuration_t *configuration) {
    socket->backend_configuration = configuration->backend_configuration;

    switch (configuration->security.mode) {
    case AVS_NET_SECURITY_PSK:
        if (configure_ssl_psk(socket, &configuration->security.data.psk)) {
            return -1;
        }
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        if (configure_ssl_certs(socket, &configuration->security.data.cert)) {
            return -1;
        }
        break;
    default:
        assert(0 && "invalid enum value");
        return -1;
    }

    if (configuration->additional_configuration_clb
            && configuration->additional_configuration_clb(socket->ctx)) {
        LOG(ERROR, "Error while setting additional SSL configuration");
        return -1;
    }
    return 0;
}

static int dtls_write_handler(dtls_context_t *ctx,
                              session_t *session,
                              uint8 *buf,
                              size_t len) {
    return -1;
}

static int dtls_read_handler(dtls_context_t *ctx,
                             session_t *session,
                             uint8 *buf,
                             size_t len) {
    return -1;
}

static int dtls_event_handler(dtls_context_t *ctx,
                              session_t *session,
                              dtls_alert_level_t level,
                              unsigned short code) {
    LOG(TRACE, "Ignoring tinyDTLS event (session=%p, level=%d, code=%hu)",
        session, (int) level, code);
    return 0;
}

static int dtls_get_psk_info_handler(dtls_context_t *ctx,
                                     const session_t *session,
                                     dtls_credentials_type_t type,
                                     const unsigned char *desc,
                                     size_t desc_len,
                                     unsigned char *result,
                                     size_t result_length) {
    return -1;
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 avs_net_socket_type_t backend_type,
                                 const avs_net_ssl_configuration_t *configuration) {
    if (backend_type != AVS_NET_DTLS_SOCKET) {
        LOG(ERROR, "tinyDTLS backend supports DTLS sockets only");
        return -1;
    }
    dtls_init();

    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;

    socket->backend_type = backend_type;
    socket->ctx = dtls_new_context(NULL);
    if (!socket->ctx) {
        LOG(ERROR, "could not instantiate tinyDTLS context");
        return -1;
    }

    if (configure_ssl(socket, configuration)) {
        dtls_free_context(socket->ctx);
        socket->ctx = NULL;
        return -1;
    }

    static dtls_handler_t handlers = {
        .write = dtls_write_handler,
        .read = dtls_read_handler,
        .event = dtls_event_handler,
        .get_psk_info = dtls_get_psk_info_handler
    };
    dtls_set_handler(socket->ctx, &handlers);

    return 0;
}
