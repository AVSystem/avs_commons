/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014-2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <assert.h>
#include <string.h>

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#define inline
#endif

#include <mbedtls/ssl.h>

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    /*mbedtls_ssl_context context;*/
    mbedtls_x509_crt *ca_cert;
    mbedtls_x509_crt *client_cert;
    mbedtls_pk_context *pk_key;
    /*havege_state havege;*/
    avs_net_abstract_socket_t *tcp_socket;
    avs_net_socket_configuration_t backend_configuration;
} ssl_socket_t;

static int connect_ssl(avs_net_abstract_socket_t *ssl_socket,
                       const char* host,
                       const char *port);
static int decorate_ssl(avs_net_abstract_socket_t *socket,
                        avs_net_abstract_socket_t *backend_socket);
static int configure_ssl(ssl_socket_t *socket,
                         const avs_net_ssl_configuration_t *configuration);
static int send_ssl(avs_net_abstract_socket_t *ssl_socket,
                    const void *buffer,
                    size_t buffer_length);
static int receive_ssl(avs_net_abstract_socket_t *ssl_socket,
                       size_t *out,
                       void *buffer,
                       size_t buffer_length);
static int shutdown_ssl(avs_net_abstract_socket_t *socket);
static int close_ssl(avs_net_abstract_socket_t *ssl_socket);
static int cleanup_ssl(avs_net_abstract_socket_t **ssl_socket);
static int system_socket_ssl(avs_net_abstract_socket_t *ssl_socket,
                             const void **out);
static int interface_name_ssl(avs_net_abstract_socket_t *ssl_socket,
                              avs_net_socket_interface_name_t *if_name);
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

static int unimplemented() {
    return -1;
}

static const avs_net_socket_v_table_t ssl_vtable = {
    connect_ssl,
    decorate_ssl,
    send_ssl,
    (avs_net_socket_send_to_t) unimplemented,
    receive_ssl,
    (avs_net_socket_receive_from_t) unimplemented,
    (avs_net_socket_bind_t) unimplemented,
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
    set_opt_ssl
};

static int interface_name_ssl(avs_net_abstract_socket_t *ssl_socket_,
                              avs_net_socket_interface_name_t *if_name) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    if (ssl_socket->tcp_socket) {
        return avs_net_socket_interface_name(
                        (avs_net_abstract_socket_t *) ssl_socket->tcp_socket,
                        if_name);
    } else {
        return -1;
    }
}

static int remote_host_ssl(avs_net_abstract_socket_t *socket_,
                           char *out_buffer, size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    if (!socket->tcp_socket) {
        return -1;
    }
    return avs_net_socket_get_remote_host(socket->tcp_socket,
                                          out_buffer, out_buffer_size);
}

static int remote_port_ssl(avs_net_abstract_socket_t *socket_,
                           char *out_buffer, size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    if (!socket->tcp_socket) {
        return -1;
    }
    return avs_net_socket_get_remote_port(socket->tcp_socket,
                                          out_buffer, out_buffer_size);
}

static int local_port_ssl(avs_net_abstract_socket_t *socket_,
                          char *out_buffer, size_t out_buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    if (!socket->tcp_socket) {
        return -1;
    }
    return avs_net_socket_get_local_port(socket->tcp_socket,
                                         out_buffer, out_buffer_size);
}

static int get_opt_ssl(avs_net_abstract_socket_t *ssl_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    return avs_net_socket_get_opt(ssl_socket->tcp_socket, option_key,
                                  out_option_value);
}

static int set_opt_ssl(avs_net_abstract_socket_t *ssl_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t option_value) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    return avs_net_socket_set_opt(ssl_socket->tcp_socket, option_key,
                                  option_value);
}

static int system_socket_ssl(avs_net_abstract_socket_t *socket_,
                             const void **out) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    if (socket->tcp_socket) {
        *out = avs_net_socket_get_system(socket->tcp_socket);
    } else {
        *out = NULL;
    }
    return *out ? 0 : -1;
}

#define CREATE_OR_FAIL(type, ptr) \
do {\
    free(*ptr);\
    *ptr = (type *) calloc(1, sizeof(**ptr));\
    if (!*ptr) {\
        LOG(ERROR, "memory allocation error");\
        return -1;\
    }\
} while (0)

static int load_ca_certs(mbedtls_x509_crt **out,
                         const char *ca_cert_path,
                         const char *ca_cert_file,
                         const avs_net_ssl_raw_cert_t *ca_cert) {
    const int has_raw_cert = ca_cert && ca_cert->cert_der;

    if (!ca_cert_path && !ca_cert_file && !has_raw_cert) {
        LOG(ERROR, "no certificate for CA provided");
        return -1;
    }

    CREATE_OR_FAIL(mbedtls_x509_crt, out);

    if (ca_cert_path) {
        int failed = mbedtls_x509_crt_parse_path(*out, ca_cert_path);
        if (failed) {
            LOG(WARNING,
                "failed to parse %d certs in path <%s>", failed, ca_cert_path);
        }
    }
    if (ca_cert_file) {
        int failed = mbedtls_x509_crt_parse_file(*out, ca_cert_file);
        if (failed) {
            LOG(WARNING,
                "failed to parse %d certs in file <%s>", failed, ca_cert_file);
        }
    }
    if (has_raw_cert) {
        int failed = mbedtls_x509_crt_parse_der(
                *out,
                (const unsigned char *) ca_cert->cert_der, ca_cert->cert_size);
        if (failed) {
            LOG(WARNING, "failed to parse DER certificate: %d", failed);
        }
    }
    return 0;
}

static int is_private_key_valid(const avs_net_private_key_t *key) {
    assert(key);

    switch (key->source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (!key->data.file.path || !key->data.file.password) {
            LOG(ERROR, "private key with password not specified");
            return 0;
        }
        return 1;
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (!key->data.buffer.private_key) {
            LOG(ERROR, "private key not specified");
            return 0;
        }
        return 1;
    }
    assert(!"invalid enum value");
    return 0;
}

static int load_client_private_key(mbedtls_pk_context **pk_key,
                                   const avs_net_private_key_t *key) {
    if (!is_private_key_valid(key)) {
        return -1;
    }

    CREATE_OR_FAIL(mbedtls_pk_context, pk_key);

    switch (key->source) {
    case AVS_NET_DATA_SOURCE_FILE:
        return mbedtls_pk_parse_keyfile(*pk_key, key->data.file.path,
                                        key->data.file.password);
    case AVS_NET_DATA_SOURCE_BUFFER:
#warning "TODO: FIXME"
    default:
        assert(!"invalid enum value");
        return -1;
    }
}

static int is_client_cert_empty(const avs_net_client_cert_t *cert) {
    switch (cert->source) {
    case AVS_NET_DATA_SOURCE_FILE:
        return !cert->data.file;
    case AVS_NET_DATA_SOURCE_BUFFER:
        return !cert->data.buffer.cert_der;
    }
    assert(!"invalid enum value");
    return 1;
}

static int load_client_cert(mbedtls_x509_crt **client_cert,
                            mbedtls_pk_context **pk_key,
                            const avs_net_client_cert_t *cert,
                            const avs_net_private_key_t *key) {
    int failed;

    if (is_client_cert_empty(cert)) {
        LOG(TRACE, "client certificate not specified");
        return 0;
    }

    CREATE_OR_FAIL(mbedtls_x509_crt, client_cert);

    switch (cert->source) {
    case AVS_NET_DATA_SOURCE_FILE:
        failed = mbedtls_x509_crt_parse_file(*client_cert, cert->data.file);
        if (failed) {
            LOG(WARNING, "failed to parse %d certs in file <%s>",
                failed, cert->data.file);
        }
        break;
    case AVS_NET_DATA_SOURCE_BUFFER:
        failed = mbedtls_x509_crt_parse_der(
                *client_cert,
                (const unsigned char *) cert->data.buffer.cert_der,
                cert->data.buffer.cert_size);
        if (failed) {
            LOG(WARNING, "failed to parse DER certificate: %d", failed);
        }
    default:
        assert(!"invalid enum value");
        return -1;
    }

    if (load_client_private_key(pk_key, key)) {
        LOG(ERROR, "Error loading client private key");
        return -1;
    }

    return 0;
}

    static int server_auth_enabled(const avs_net_certificate_info_t *cert_info) {
    return cert_info->ca_cert_file
        || cert_info->ca_cert_path
        || cert_info->ca_cert_raw.cert_der;
}

static int configure_ssl_certs(ssl_socket_t *socket,
                               const avs_net_certificate_info_t *cert_info) {
    LOG(TRACE, "configure_ssl_certs");

    if (server_auth_enabled(cert_info)) {
        if (load_ca_certs(&socket->ca_cert,
                          cert_info->ca_cert_path,
                          cert_info->ca_cert_file,
                          &cert_info->ca_cert_raw)) {
            LOG(ERROR, "error loading CA certs");
            return -1;
        }
    } else {
        LOG(DEBUG, "Server authentication disabled");
    }

    if (load_client_cert(&socket->client_cert,
                         &socket->pk_key,
                         &cert_info->client_cert,
                         &cert_info->client_key)) {
        LOG(ERROR, "error loading client certificate");
        return -1;
    }

    return 0;
}

static int configure_ssl(ssl_socket_t *socket,
                         const avs_net_ssl_configuration_t *configuration) {
    LOG(TRACE, "configure_ssl(socket=%p, configuration=%p)",
              (void *) socket, (const void *) configuration);

    if (!configuration) {
        LOG(WARNING, "configuration not provided");
        return 0;
    }

    socket->backend_configuration = configuration->backend_configuration;

#warning "TODO: set_max_ssl_version(&socket->context, configuration->version)"

    switch (configuration->security.mode) {
    case AVS_NET_SECURITY_PSK:
#warning "TODO"
        assert(!"PSK not supported for now");
        return -1;
    case AVS_NET_SECURITY_CERTIFICATE:
        if (configure_ssl_certs(socket, &configuration->security.data.cert)) {
            return -1;
        }
        break;
    default:
        assert(!"invalid enum value");
        return -1;
    }

#warning "FIXME"
    /*if (configuration->additional_configuration_clb
            && configuration->additional_configuration_clb(&socket->context)) {
        LOG(ERROR, "Error while setting additional SSL configuration");
        return -1;
    }*/
    return 0;
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 const avs_net_ssl_configuration_t *configuration) {
    memset(socket, 0, sizeof (ssl_socket_t));
    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;

    return configure_ssl(socket, configuration);
}

int _avs_net_create_ssl_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    LOG(TRACE, "create_ssl_socket(socket=%p)", (void *) socket);

    *socket = (avs_net_abstract_socket_t *) malloc(sizeof (ssl_socket_t));
    if (*socket) {
        if (initialize_ssl_socket((ssl_socket_t *) * socket,
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

int _avs_net_create_dtls_socket(avs_net_abstract_socket_t **socket,
                                const void *socket_configuration) {
}
