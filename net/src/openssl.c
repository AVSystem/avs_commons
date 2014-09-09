/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

#define CERT_SUBJECT_NAME_SIZE 257

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    SSL_CTX *ctx;
    SSL *ssl;
    int verification;
#ifdef WITH_TRACE
    char *error_buffer;
#endif
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

#ifdef BIO_TYPE_SOURCE_SINK
static int avs_bio_write(BIO *bio, const char *data, int size) {
    if (!data || size <= 0) {
        return 0;
    }
    BIO_clear_retry_flags(bio);
    if (avs_net_socket_send(((ssl_socket_t *) bio->ptr)->tcp_socket,
                          data, (size_t) size)) {
        return -1;
    } else {
        return size;
    }
}

static int avs_bio_read(BIO *bio, char *buffer, int size) {
    size_t read_bytes;
    if (!buffer || size <= 0) {
        return 0;
    }
    BIO_clear_retry_flags(bio);
    if (avs_net_socket_receive(((ssl_socket_t *) bio->ptr)->tcp_socket,
                             &read_bytes, buffer, (size_t) size)) {
        return -1;
    } else {
        return (int) read_bytes;
    }
}

static int avs_bio_puts(BIO *bio, const char *data) {
    return avs_bio_write(bio, data, (int) strlen(data));
}

static int avs_bio_gets(BIO *bio, char *buffer, int size) {
    (void) bio;
    (void) buffer;
    (void) size;
    return -1;
}

static long avs_bio_ctrl(BIO *bio, int command, long intarg, void *ptrarg) {
    (void) bio;
    (void) intarg;
    (void) ptrarg;
    if (command == BIO_CTRL_FLUSH) {
        return 1; /* OpenSSL requirement */
    }
    return 0;
}

static int avs_bio_create(BIO *bio) {
    bio->init = 1;
    bio->num = 0;
    bio->ptr = NULL;
    bio->flags = 0;
    return 1;
}

static int avs_bio_destroy(BIO *bio) {
    if (!bio) {
        return 0;
    }
    bio->ptr = NULL; /* will be cleaned up elsewhere */
    bio->init = 0;
    bio->flags = 0;
    return 1;
}

static BIO_METHOD AVS_BIO = {
    (100 | BIO_TYPE_SOURCE_SINK),
    "avs_net",
    avs_bio_write,
    avs_bio_read,
    avs_bio_puts,
    avs_bio_gets,
    avs_bio_ctrl,
    avs_bio_create,
    avs_bio_destroy,
    NULL
};

static BIO *avs_bio_spawn(ssl_socket_t *socket) {
    BIO *bio = BIO_new(&AVS_BIO);
    if (bio) {
        bio->ptr = socket;
    }
    return bio;
}
#else /* BIO_TYPE_SOURCE_SINK */
static BIO *avs_bio_spawn(ssl_socket_t *socket) {
    const void *fd_ptr =
            avs_net_socket_get_system((avs_net_abstract_socket_t *) socket);
    return fd_ptr ? BIO_new_socket(*(const int *) fd_ptr, 0) : NULL;
}
#endif /* BIO_TYPE_SOURCE_SINK */

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

static int system_socket_ssl(avs_net_abstract_socket_t *ssl_socket_,
                             const void **out) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    if (ssl_socket->tcp_socket) {
        *out = avs_net_socket_get_system(ssl_socket->tcp_socket);
    } else {
        *out = NULL;
    }
    return *out ? 0 : -1;
}

static int verify_peer_subject_cn(ssl_socket_t *ssl_socket) {
    char host[NET_MAX_HOSTNAME_SIZE];
    char buffer[CERT_SUBJECT_NAME_SIZE];
    char *cn = NULL;
    X509* peer_certificate = NULL;

    if (remote_host_ssl((avs_net_abstract_socket_t *) ssl_socket,
                        host, sizeof(host))) {
        return -1;
    }

    /* check whether CN matches host portion of ACS URL */
    peer_certificate = SSL_get_peer_certificate(ssl_socket->ssl);
    if (!peer_certificate) {
        return -1;
    }
    X509_NAME_oneline(X509_get_subject_name(peer_certificate),
                      buffer, sizeof (buffer));
    X509_free(peer_certificate);

    cn = strstr(buffer, "CN=");
    if (cn != NULL) {
        char* cne = strchr(cn, '/');
        if (cne) *cne = '\0';
        cn += 3;
    }
    if (cn == NULL || strcmp(cn, host)) {
        return -1;
    }

    return 0;
}

static int ssl_handshake(ssl_socket_t *socket) {
    avs_net_socket_opt_value_t state_opt;
    if (avs_net_socket_get_opt(socket->tcp_socket,
                             AVS_NET_SOCKET_OPT_STATE, &state_opt)) {
        return -1;
    }
    if (state_opt.state == AVS_NET_SOCKET_STATE_CONSUMING) {
        return SSL_connect(socket->ssl);
    }
    if (state_opt.state == AVS_NET_SOCKET_STATE_SERVING) {
        return SSL_accept(socket->ssl);
    }
    return -1;
}

static int start_ssl(ssl_socket_t *socket) {
    BIO *bio = NULL;

    if (socket->ssl) {
        return -1;
    }

    socket->ssl = SSL_new(socket->ctx);
    if (!socket->ssl) {
        return -1;
    }

#ifdef SSL_MODE_AUTO_RETRY
    SSL_set_mode(socket->ssl, SSL_MODE_AUTO_RETRY);
#endif

    bio = avs_bio_spawn(socket);
    if (!bio) {
        return -1;
    }
    SSL_set_bio(socket->ssl, bio, bio);

    {
        int handshake_result = ssl_handshake(socket);
        if (handshake_result <= 0) {
            close_ssl((avs_net_abstract_socket_t *) socket);
            return -1;
        }
    }

    if (socket->verification && verify_peer_subject_cn(socket) != 0) {
        close_ssl((avs_net_abstract_socket_t *) socket);
        return -1;
    }

    return 0;
}

static int connect_ssl(avs_net_abstract_socket_t *socket_,
                       const char *host,
                       const char *port) {
    int result;
    ssl_socket_t *socket = (ssl_socket_t *) socket_;

    if (avs_net_socket_create(&socket->tcp_socket, AVS_NET_TCP_SOCKET,
                              &socket->backend_configuration)) {
        return -1;
    }
    if (avs_net_socket_connect(socket->tcp_socket, host, port)) {
        return -1;
    }

    result = start_ssl(socket);
    if (result) {
        avs_net_socket_cleanup(&socket->tcp_socket);
    }
    return result;
}

static int decorate_ssl(avs_net_abstract_socket_t *socket_,
                        avs_net_abstract_socket_t *backend_socket) {
    int result;
    ssl_socket_t *socket = (ssl_socket_t *) socket_;

    if (socket->tcp_socket) {
        avs_net_socket_cleanup(&socket->tcp_socket);
    }

    socket->tcp_socket = backend_socket;
    result = start_ssl(socket);
    if (result) {
        socket->tcp_socket = NULL;
    }
    return result;
}

static int load_ca_certs(const char *ca_cert_path,
                         const char *ca_cert_file,
                         ssl_socket_t *socket) {

    if (!ca_cert_path && !ca_cert_file) {
        return -1;
    }

    if (!SSL_CTX_load_verify_locations(socket->ctx,
                                       ca_cert_file,
                                       ca_cert_path)) {
        return -1;
    }
    if (!SSL_CTX_set_default_verify_paths(socket->ctx)) {
        return -1;
    }

    return 0;
}

static int password_cb(char *buf, int num, int rwflag, void *userdata) {
    int retval = snprintf(buf, (size_t) num, "%s", (const char *) userdata);
    (void) rwflag;
    return (retval < 0 || retval >= num) ? -1 : 0;
}

static int load_client_cert(const char *client_cert_file,
                            const char *client_key_file,
                            const char *client_key_password,
                            ssl_socket_t *socket) {

    if (!client_cert_file) {
        return 0;
    }
    if (!client_key_file || !client_key_password) {
        return -1;
    }

    if (!SSL_CTX_use_certificate_chain_file(socket->ctx, client_cert_file)) {
        return -1;
    }

    SSL_CTX_set_default_passwd_cb_userdata(socket->ctx,
                      /* const_cast */ (void *) (intptr_t) client_key_password);
    SSL_CTX_set_default_passwd_cb(socket->ctx, password_cb);

    if (!SSL_CTX_use_PrivateKey_file(socket->ctx,
                                     client_key_file,
                                     SSL_FILETYPE_PEM)) {
        return -1;
    }

    return 0;
}

static int server_auth_enabled(const avs_net_ssl_configuration_t *configuration) {
    return configuration->ca_cert_file || configuration->ca_cert_path;
}

static int configure_ssl(ssl_socket_t *socket,
                         const avs_net_ssl_configuration_t *configuration) {
    socket->backend_configuration = configuration->backend_configuration;

    ERR_clear_error();
    SSL_CTX_set_options(socket->ctx, (long) (SSL_OP_ALL | SSL_OP_NO_SSLv2));
    SSL_CTX_set_verify(socket->ctx, SSL_VERIFY_NONE, NULL);
#ifdef WITH_OPENSSL_CUSTOM_CIPHERS
    SSL_CTX_set_cipher_list(socket->ctx, WITH_OPENSSL_CUSTOM_CIPHERS);
#endif

    if (!configuration) {
        return 0;
    }

    if (server_auth_enabled(configuration)) {
        socket->verification = 1;
        SSL_CTX_set_verify(socket->ctx, SSL_VERIFY_PEER, NULL);
#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x00905100L)
        SSL_CTX_set_verify_depth(socket->ctx, 1);
#endif
        if (load_ca_certs(configuration->ca_cert_path,
                          configuration->ca_cert_file,
                          socket)) {
            return -1;
        }
    }

    if (load_client_cert(configuration->client_cert_file,
                         configuration->client_key_file,
                         configuration->client_key_password,
                         socket)) {
        return -1;
    }
    return 0;
}

static int shutdown_ssl(avs_net_abstract_socket_t *socket_) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    if (socket->tcp_socket) {
        return avs_net_socket_shutdown(socket->tcp_socket);
    } else {
        return 0;
    }
}

static int close_ssl(avs_net_abstract_socket_t *socket_) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    if (socket->ssl) {
        SSL_shutdown(socket->ssl);
        SSL_free(socket->ssl);
        socket->ssl = NULL;
    }
    if (socket->tcp_socket) {
        avs_net_socket_close(socket->tcp_socket);
        avs_net_socket_cleanup(&socket->tcp_socket);
    }

    return 0;
}

static int send_ssl(avs_net_abstract_socket_t *socket_,
                    const void *buffer,
                    size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result;

    result = SSL_write(socket->ssl, buffer, (int) buffer_length);
    if (result < 0 || (size_t) result < buffer_length) {
        return -1;
    }
    return 0;
}

static int receive_ssl(avs_net_abstract_socket_t *socket_,
                       size_t *out,
                       void *buffer,
                       size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result;

    result = SSL_read(socket->ssl, buffer, (int) buffer_length);
    if (result < 0) {
        *out = 0;
        return result;
    } else {
        if (RUNNING_ON_VALGRIND) {
            /* This is likely the ugliest piece of code in this library.
             *
             * This is here because OpenSSL uses some weird overoptimizations
             * that break documented ABIs and make Valgrind go crazy, reporting
             * errors about uninitialized memory everywhere.
             *
             * This basically copies memory onto itself in a way that makes
             * Valgrind think it has just been initialized.
             *
             * It itself contains a conditional jump depending on uninitialized
             * memory, so a Valgrind-level suppression is still necessary. */
            int i = 0;
            for (i = 0; i < result; ++i) {
                int j = 0;
                volatile uint8_t tmp = 0;
                for (j = 0; j < 8; ++j) {
                    if (((uint8_t *) buffer)[i] & (1 << j)) {
                        tmp |= (uint8_t) (1 << j);
                    }
                }
                ((uint8_t *) buffer)[i] = tmp;
            }
        }
        *out = (size_t) result;
        return 0;
    }
}

static int cleanup_ssl(avs_net_abstract_socket_t **socket_) {
    ssl_socket_t **socket = (ssl_socket_t **) socket_;

    close_ssl(*socket_);
    if ((*socket)->ssl) {
        SSL_shutdown((*socket)->ssl);
        SSL_free((*socket)->ssl);
        (*socket)->ssl = NULL;
    }
    if ((*socket)->ctx) {
        SSL_CTX_free((*socket)->ctx);
        (*socket)->ctx = NULL;
    }
#ifdef WITH_TRACE
    free((*socket)->error_buffer);
#endif
    free(*socket);
    *socket = NULL;
    return 0;
}

static int avs_ssl_init() {
    static volatile int initialized = 0;
    if (!initialized) {
        initialized = 1;

        SSL_library_init();
#ifdef WITH_TRACE
        SSL_load_error_strings();
#endif
        OpenSSL_add_all_algorithms();
        RAND_load_file("/dev/urandom", -1);
    }
    return 0;
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 const avs_net_ssl_configuration_t *configuration) {
    const SSL_METHOD *method = NULL;
    static const ssl_socket_t new_socket
            = { &ssl_vtable, NULL, NULL, 0,
#ifdef WITH_TRACE
                NULL,
#endif /* WITH_TRACE */
                NULL, { 0, 0, "", NULL } };

    memcpy(socket, &new_socket, sizeof (new_socket));
#ifdef WITH_TRACE
    socket->error_buffer = (char *) malloc(120); /* see 'man ERR_error_string' */
#endif /* WITH_TRACE */

    switch (configuration->version) {
#ifndef OPENSSL_NO_SSL2
    case AVS_NET_SSL_VERSION_SSLv2:
        method = SSLv2_client_method();
        break;
#endif

#ifndef OPENSSL_NO_SSL3
    case AVS_NET_SSL_VERSION_SSLv2_OR_3:
        method = SSLv23_client_method();
        break;

    case AVS_NET_SSL_VERSION_SSLv3:
        method = SSLv3_client_method();
        break;
#endif

#ifndef OPENSSL_NO_TLS1
    case AVS_NET_SSL_VERSION_TLSv1:
        method = TLSv1_client_method();
        break;

#if OPENSSL_VERSION_NUMBER >= 0x10001000L /* OpenSSL >= 1.0.1 */
    case AVS_NET_SSL_VERSION_TLSv1_1:
        method = TLSv1_1_client_method();
        break;

    case AVS_NET_SSL_VERSION_TLSv1_2:
        method = TLSv1_2_client_method();
        break;
#endif
#endif /* OPENSSL_NO_TLS1 */

    default:
        return -1;
    }

    /* older versions of OpenSSL expect non-const pointer here... */
    socket->ctx = SSL_CTX_new((SSL_METHOD *) (intptr_t) method);
    if (socket->ctx == NULL) {
        return -1;
    }

    return configure_ssl(socket, configuration);
}

int _avs_net_create_ssl_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    if (avs_ssl_init()) {
        return -1;
    }

    *socket = (avs_net_abstract_socket_t *) malloc(sizeof (ssl_socket_t));
    if (*socket) {
        if (initialize_ssl_socket((ssl_socket_t *) * socket,
                                  (const avs_net_ssl_configuration_t *)
                                  socket_configuration)) {
            avs_net_socket_cleanup(socket);
            return -1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}
