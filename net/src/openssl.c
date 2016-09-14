/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L /* for snprintf() on C89 and clock_gettime() */
#endif

#include <config.h>

#ifdef WITH_LWIP
#   include "lwip_compat.h"
#else
#   include <sys/socket.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

#define CERT_SUBJECT_NAME_SIZE 257

#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_PSK) /* OpenSSL >= 1.0.0 */
#define HAVE_OPENSSL_PSK
#endif

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    SSL_CTX *ctx;
    SSL *ssl;
    int verification;
    int error_code;
#ifdef AVS_LOG_WITH_TRACE
    char *error_buffer;
#endif
    int64_t next_deadline_ms;
    avs_net_socket_type_t backend_type;
    avs_net_abstract_socket_t *backend_socket;
    avs_net_socket_configuration_t backend_configuration;
    avs_net_resolved_endpoint_t endpoint_buffer;

#ifdef HAVE_OPENSSL_PSK
    avs_net_psk_t psk;
#endif
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

#ifdef AVS_LOG_WITH_TRACE

#define log_openssl_error(ssl_socket) \
    LOG(ERROR, "%s", ERR_error_string(ERR_get_error(), ssl_socket->error_buffer))

#else /* !AVS_LOG_WITH_TRACE */

#define log_openssl_error(socket) \
    LOG(ERROR, "OpenSSL error %lu", ERR_get_error())

#endif /* AVS_LOG_WITH_TRACE */

static int get_socket_inner_mtu_or_zero(avs_net_abstract_socket_t *sock) {
    avs_net_socket_opt_value_t opt_value;
    if (avs_net_socket_get_opt(sock, AVS_NET_SOCKET_OPT_INNER_MTU,
                               &opt_value)) {
        return 0;
    } else {
        return opt_value.mtu;
    }
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int get_explicit_iv_length(EVP_CIPHER_CTX *cipher_ctx) {
    /* adapted from do_dtls1_write() in OpenSSL */
    int mode = EVP_CIPHER_CTX_mode(cipher_ctx);
    if (mode == EVP_CIPH_CBC_MODE) {
        int eivlen = EVP_CIPHER_CTX_iv_length(cipher_ctx);
        if (eivlen > 1) {
            return eivlen;
        }
    }
#ifdef EVP_GCM_TLS_EXPLICIT_IV_LEN
    else if (mode == EVP_CIPH_GCM_MODE) {
        return EVP_GCM_TLS_EXPLICIT_IV_LEN;
    }
#endif
#ifdef EVP_CCM_TLS_EXPLICIT_IV_LEN
    else if (mode == EVP_CIPH_CCM_MODE) {
        return EVP_CCM_TLS_EXPLICIT_IV_LEN;
    }
#endif
    return 0;
}

#ifndef SSL3_RT_MAX_COMPRESSED_OVERHEAD
/* this is the value in OpenSSL 1.x */
#define SSL3_RT_MAX_COMPRESSED_OVERHEAD 1024
#endif

static int get_dtls_overhead(ssl_socket_t *socket,
                             int *out_header,
                             int *out_padding_size) {
    *out_header = DTLS1_RT_HEADER_LENGTH;
    *out_padding_size = 0;
    if (socket && socket->ssl) {
        /* querying OpenSSL internals, but there seem to be no other way */
        EVP_CIPHER_CTX *cipher_ctx = socket->ssl->enc_write_ctx;
        EVP_MD_CTX *md_ctx = socket->ssl->write_hash;
        /* actual logic is inspired by GnuTLS' record_overhead() */
        if (cipher_ctx) {
            int block_size = EVP_CIPHER_CTX_block_size(cipher_ctx);
            if (block_size < 0) {
                return -1;
            }
            if (!(EVP_CIPHER_CTX_flags(cipher_ctx) & EVP_CIPH_NO_PADDING)) {
                *out_padding_size = block_size;
            }
            *out_header += get_explicit_iv_length(cipher_ctx);
        }
        /* adapted from mac_size calculation in dtls1_do_write() in OpenSSL */
#ifdef EVP_CIPH_GCM_MODE
        if (md_ctx && !(cipher_ctx
                    && EVP_CIPHER_CTX_mode(cipher_ctx) == EVP_CIPH_GCM_MODE)) {
            *out_header += EVP_MD_CTX_size(md_ctx);
        }
#endif
        if (SSL_get_current_compression(socket->ssl) != NULL) {
            *out_header += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
        }
    }
    return 0;
}
#else
static int get_dtls_overhead(ssl_socket_t *socket,
                             int *out_header,
                             int *out_padding_size) {
    /* OpenSSL 1.1 hides its internals, but also does not allow to query the
     * currently used ciphers in any other way, so we're screwed :( */
    (void) socket;
    (void) out_header;
    (void) out_padding_size;
    return -1;
}
#endif

#ifdef BIO_TYPE_SOURCE_SINK

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define BIO_set_init(bio, value) ((bio)->init = (value))
#define BIO_get_data(bio) ((bio)->ptr)
#define BIO_set_data(bio, data) ((bio)->ptr = (data))
#endif

static int avs_bio_write(BIO *bio, const char *data, int size) {
    if (!data || size < 0) {
        return 0;
    }
    BIO_clear_retry_flags(bio);
    if (avs_net_socket_send(
            ((ssl_socket_t *) BIO_get_data(bio))->backend_socket,
            data, (size_t) size)) {
        return -1;
    } else {
        return size;
    }
}

static int64_t current_time_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t) t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static avs_net_timeout_t get_socket_timeout(avs_net_abstract_socket_t *sock) {
    avs_net_socket_opt_value_t opt_value;
    avs_net_socket_get_opt(sock, AVS_NET_SOCKET_OPT_RECV_TIMEOUT, &opt_value);
    return opt_value.recv_timeout;
}

static void set_socket_timeout(avs_net_abstract_socket_t *sock,
                               avs_net_timeout_t timeout) {
    avs_net_socket_opt_value_t opt_value;
    opt_value.recv_timeout = timeout;
    avs_net_socket_set_opt(sock, AVS_NET_SOCKET_OPT_RECV_TIMEOUT, opt_value);
}

static avs_net_timeout_t adjust_receive_timeout(ssl_socket_t *sock) {
    avs_net_timeout_t socket_timeout = get_socket_timeout(sock->backend_socket);
    if (sock->next_deadline_ms >= 0) {
        int64_t now_ms = current_time_ms();
        avs_net_timeout_t timeout =
                (avs_net_timeout_t) (sock->next_deadline_ms - now_ms);
        if (socket_timeout <= 0 || socket_timeout > timeout) {
            set_socket_timeout(sock->backend_socket, timeout);
        }
    }
    return socket_timeout;
}

static int avs_bio_read(BIO *bio, char *buffer, int size) {
    ssl_socket_t *sock = (ssl_socket_t *) BIO_get_data(bio);
    avs_net_timeout_t prev_timeout = -1;
    size_t read_bytes;
    int result;
    if (!buffer || size < 0) {
        return 0;
    }
    BIO_clear_retry_flags(bio);
    if (sock->backend_type == AVS_NET_UDP_SOCKET) {
        prev_timeout = adjust_receive_timeout(sock);
    }
    if (avs_net_socket_receive(sock->backend_socket,
                               &read_bytes, buffer, (size_t) size)) {
        result = -1;
    } else {
        result = (int) read_bytes;
    }
    if (sock->backend_type == AVS_NET_UDP_SOCKET) {
        set_socket_timeout(sock->backend_socket, prev_timeout);
    }
    return result;
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

static int get_dtls_fallback_mtu_or_zero(ssl_socket_t *sock) {
    char host[NET_MAX_HOSTNAME_SIZE];
    if (avs_net_socket_get_remote_host(sock->backend_socket,
                                       host, sizeof(host))) {
        return 0;
    } else {
        if (strchr(host, ':')) { /* IPv6 */
            return 1232; /* 1280 - 48 */
        } else {
            return 548; /* 576 - 28 */
        }
    }
}

static long avs_bio_ctrl(BIO *bio, int command, long intarg, void *ptrarg) {
    ssl_socket_t *sock = (ssl_socket_t *) BIO_get_data(bio);
    (void) sock;
    (void) intarg;
    (void) ptrarg;
    switch (command) {
    case BIO_CTRL_FLUSH:
        return 1;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L /* OpenSSL >= 1.0.1 */
    case BIO_CTRL_DGRAM_QUERY_MTU:
        return get_socket_inner_mtu_or_zero(sock->backend_socket);
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        sock->next_deadline_ms =
                (int64_t) ((const struct timeval *) ptrarg)->tv_sec * 1000 +
                ((const struct timeval *) ptrarg)->tv_usec / 1000;
        return 0;
    case BIO_CTRL_DGRAM_GET_PEER:
        memcpy(ptrarg, sock->backend_configuration.preferred_endpoint->data.buf,
               sock->backend_configuration.preferred_endpoint->size);
        return sock->backend_configuration.preferred_endpoint->size;
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        return get_dtls_fallback_mtu_or_zero(sock);
#endif
    default:
        return 0;
    }
}

static int avs_bio_create(BIO *bio) {
    BIO_set_init(bio, 1);
    BIO_set_data(bio, NULL);
    BIO_set_flags(bio, 0);
    return 1;
}

static int avs_bio_destroy(BIO *bio) {
    if (!bio) {
        return 0;
    }
    BIO_set_data(bio, NULL); /* will be cleaned up elsewhere */
    BIO_set_init(bio, 0);
    BIO_set_flags(bio, 0);
    return 1;
}

static BIO_METHOD *AVS_BIO = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int avs_bio_init(void) {
    static BIO_METHOD AVS_BIO_IMPL = {
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
    AVS_BIO = &AVS_BIO_IMPL;
    return 0;
}
#else
static int avs_bio_init(void) {
    assert(!AVS_BIO);
    /* BIO_meth_set_* return 1 on success */
    if (!((AVS_BIO = BIO_meth_new(100 | BIO_TYPE_SOURCE_SINK, "avs_net"))
            && BIO_meth_set_write(AVS_BIO, avs_bio_write)
            && BIO_meth_set_read(AVS_BIO, avs_bio_read)
            && BIO_meth_set_puts(AVS_BIO, avs_bio_puts)
            && BIO_meth_set_gets(AVS_BIO, avs_bio_gets)
            && BIO_meth_set_ctrl(AVS_BIO, avs_bio_ctrl)
            && BIO_meth_set_create(AVS_BIO, avs_bio_create)
            && BIO_meth_set_destroy(AVS_BIO, avs_bio_destroy))) {
        if (AVS_BIO) {
            BIO_meth_free(AVS_BIO);
            AVS_BIO = NULL;
        }
        return -1;
    }
    return 0;
}
#endif

static BIO *avs_bio_spawn(ssl_socket_t *socket) {
    BIO *bio = BIO_new(AVS_BIO);
    if (bio) {
        BIO_set_data(bio, socket);
    }
    return bio;
}
#else /* BIO_TYPE_SOURCE_SINK */
static BIO *avs_bio_spawn(ssl_socket_t *socket) {
    const void *fd_ptr =
            avs_net_socket_get_system((avs_net_abstract_socket_t *) socket);
    if (fd_ptr) {
        int fd = *(const int *) fd_ptr;
        if (socket->backend_type == AVS_NET_TCP_SOCKET) {
            return BIO_new_socket(fd, 0);
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L /* OpenSSL >= 1.0.1 */
        if (socket->backend_type == AVS_NET_UDP_SOCKET) {
            BIO *bio = BIO_new_dgram(fd, 0);
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0,
                     socket->backend_configuration.preferred_endpoint->data);
            return bio;
        }
#endif
    }
    return NULL;
}
#endif /* BIO_TYPE_SOURCE_SINK */

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

static int get_opt_ssl(avs_net_abstract_socket_t *ssl_socket_,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    int retval;
    ssl_socket->error_code = 0;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_INNER_MTU:
    {
        int mtu = get_socket_inner_mtu_or_zero(ssl_socket->backend_socket);
        if (mtu <= 0) {
            mtu = get_dtls_fallback_mtu_or_zero(ssl_socket);
        }
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

static int system_socket_ssl(avs_net_abstract_socket_t *ssl_socket_,
                             const void **out) {
    ssl_socket_t *ssl_socket = (ssl_socket_t *) ssl_socket_;
    if (ssl_socket->backend_socket) {
        *out = avs_net_socket_get_system(ssl_socket->backend_socket);
        ssl_socket->error_code =
                avs_net_socket_errno(ssl_socket->backend_socket);
    } else {
        *out = NULL;
        ssl_socket->error_code = EBADF;
    }
    return *out ? 0 : -1;
}

static void close_ssl_raw(ssl_socket_t *socket) {
    if (socket->ssl) {
        SSL_shutdown(socket->ssl);
        SSL_free(socket->ssl);
        socket->ssl = NULL;
    }
    if (socket->backend_socket) {
        avs_net_socket_close(socket->backend_socket);
        avs_net_socket_cleanup(&socket->backend_socket);
    }
}

static int close_ssl(avs_net_abstract_socket_t *socket_) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    LOG(TRACE, "close_ssl(socket=%p)", (void *) socket);
    close_ssl_raw(socket);
    socket->error_code = 0;
    return 0;
}

static int verify_peer_subject_cn(ssl_socket_t *ssl_socket,
                                  const char *host) {
    char buffer[CERT_SUBJECT_NAME_SIZE];
    char *cn = NULL;
    X509* peer_certificate = NULL;

    /* check whether CN matches host portion of ACS URL */
    peer_certificate = SSL_get_peer_certificate(ssl_socket->ssl);
    if (!peer_certificate) {
        LOG(ERROR, "Cannot load peer certificate");
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
        LOG(ERROR, "Subject CN(%s) does not match ACS URL (%s)", cn, host);
        return -1;
    }

    return 0;
}

static int ssl_handshake(ssl_socket_t *socket) {
    avs_net_socket_opt_value_t state_opt;
    if (avs_net_socket_get_opt(socket->backend_socket,
                               AVS_NET_SOCKET_OPT_STATE, &state_opt)) {
        LOG(ERROR, "ssl_handshake: could not get socket state");
        return -1;
    }
    if (state_opt.state == AVS_NET_SOCKET_STATE_CONSUMING) {
        return SSL_connect(socket->ssl);
    }
    if (state_opt.state == AVS_NET_SOCKET_STATE_SERVING) {
        return SSL_accept(socket->ssl);
    }
    LOG(ERROR, "ssl_handshake: invalid socket state");
    return -1;
}

static int start_ssl(ssl_socket_t *socket, const char *host) {
    BIO *bio = NULL;
    LOG(TRACE, "start_ssl(socket=%p)", (void *) socket);

    socket->ssl = SSL_new(socket->ctx);
    if (!socket->ssl) {
        socket->error_code = ENOMEM;
        return -1;
    }
    SSL_set_app_data(socket->ssl, socket);

#ifdef SSL_MODE_AUTO_RETRY
    SSL_set_mode(socket->ssl, SSL_MODE_AUTO_RETRY);
#endif

    bio = avs_bio_spawn(socket);
    if (!bio) {
        LOG(ERROR, "cannot create BIO object");
        socket->error_code = ENOMEM;
        return -1;
    }
    SSL_set_bio(socket->ssl, bio, bio);

    {
        int handshake_result = ssl_handshake(socket);
        if (handshake_result <= 0) {
            LOG(ERROR, "SSL handshake failed.");
            log_openssl_error(socket);
            LOG(TRACE, "handshake_result = %d", handshake_result);
            socket->error_code = EPROTO;
            return -1;
        }
    }

    if (socket->verification && verify_peer_subject_cn(socket, host) != 0) {
        LOG(ERROR, "server certificate verification failure");
        socket->error_code = EPROTO;
        return -1;
    }

    socket->error_code = 0;
    return 0;
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

    if (socket->ssl) {
        LOG(ERROR, "SSL socket already connected");
        socket->error_code = EISCONN;
        return -1;
    }
    if (ensure_have_backend_socket(socket)) {
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

    if (socket->ssl) {
        LOG(ERROR, "SSL socket already connected");
        socket->error_code = EISCONN;
        return -1;
    }
    if (socket->backend_socket) {
        avs_net_socket_cleanup(&socket->backend_socket);
    }

    WRAP_ERRNO_IMPL(socket, backend_socket, result,
                    avs_net_socket_get_remote_host(backend_socket,
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

static int load_ca_certs(ssl_socket_t *socket,
                         const char *ca_cert_path,
                         const char *ca_cert_file,
                         const avs_net_ssl_raw_cert_t *ca_cert) {
    const int has_files = ca_cert_path || ca_cert_file;
    const int has_raw_cert = ca_cert && ca_cert->cert_der;

    if (!has_files && !has_raw_cert) {
        LOG(ERROR, "no certificate for CA provided");
        return -1;
    }

    if (has_files) {
        if (!SSL_CTX_load_verify_locations(socket->ctx,
                                           ca_cert_file,
                                           ca_cert_path)) {
            return -1;
        }
        if (!SSL_CTX_set_default_verify_paths(socket->ctx)) {
            return -1;
        }
    }

    if (has_raw_cert) {
        const unsigned char *cert_data = (const unsigned char*)&ca_cert->cert_der;
        X509 *cert = d2i_X509(NULL, &cert_data, (int)ca_cert->cert_size);
        X509_STORE *store = SSL_CTX_get_cert_store(socket->ctx);

        if (!cert || !store || !X509_STORE_add_cert(store, cert)) {
            log_openssl_error(socket);
            X509_free(cert);
            return -1;
        }
    }

    return 0;
}

static int password_cb(char *buf, int num, int rwflag, void *userdata) {
    int retval = snprintf(buf, (size_t) num, "%s", (const char *) userdata);
    (void) rwflag;
    return (retval < 0 || retval >= num) ? -1 : retval;
}

#ifndef OPENSSL_NO_EC
static const EC_POINT *get_ec_public_key(ssl_socket_t *socket) {
    X509 *cert = NULL;
    EVP_PKEY *evp_key = NULL;
    EC_KEY *ec_key = NULL;
    const EC_POINT *point = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* HACK: temporary SSL context to obtain X509 cert */
    SSL *ssl = SSL_new(socket->ctx);
    if (!ssl) {
        return NULL;
    }
    cert = SSL_get_certificate(ssl);
#else
    cert = SSL_CTX_get0_certificate(socket->ctx);
#endif

    if (!cert
            || !(evp_key = X509_get_pubkey(cert))
            || !(ec_key = EVP_PKEY_get1_EC_KEY(evp_key))
            || !(point = EC_KEY_get0_public_key(ec_key))) {
        log_openssl_error(socket);
        point = NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_free(ssl);
#endif
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_key);
    return point;
}

static EC_KEY *ec_key_from_raw_private_key(ssl_socket_t *socket,
                                           const avs_net_ssl_raw_key_t *key) {
    const EC_POINT *public_key = NULL;
    BIGNUM *private_key = NULL;
    EC_KEY *ec_key = NULL;
    int curve_id = OBJ_txt2nid(key->curve_name);
    if (curve_id == NID_undef) {
        LOG(ERROR, "unknown curve: %s", key->curve_name);
        return NULL;
    }

    if (!(public_key = get_ec_public_key(socket))) {
        return NULL;
    }

    if (!(private_key = BN_bin2bn((const unsigned char*)key->private_key,
                                  (int)key->private_key_size, NULL))
            || !(ec_key = EC_KEY_new_by_curve_name(curve_id))
            || !EC_KEY_set_public_key(ec_key, public_key)
            || !EC_KEY_set_private_key(ec_key, private_key)) {
        log_openssl_error(socket);
        BN_free(private_key);
        EC_KEY_free(ec_key);
        return NULL;
    }

    BN_free(private_key);
    return ec_key;
}

static int load_client_key_from_data(ssl_socket_t *socket,
                                     const avs_net_ssl_raw_key_t *key) {
    EC_KEY *ec_key = NULL;
    EVP_PKEY *evp_key = NULL;

    if (!(ec_key = ec_key_from_raw_private_key(socket, key))) {
        LOG(ERROR, "could not decode EC private key");
        log_openssl_error(socket);
        return -1;
    }

    if (!(evp_key = EVP_PKEY_new())
            || !EVP_PKEY_assign_EC_KEY(evp_key, ec_key)) {
        log_openssl_error(socket);
        LOG(ERROR, "could not create EVP_PKEY");
        EC_KEY_free(ec_key);
        EVP_PKEY_free(evp_key);
        return -1;
    }

    if (!SSL_CTX_use_PrivateKey(socket->ctx, evp_key)) {
        LOG(ERROR, "could not set private key");
        log_openssl_error(socket);
        EVP_PKEY_free(evp_key);
        return -1;
    }

    EVP_PKEY_free(evp_key);
    return 0;
}
#else
#define load_client_key_from_data(...) ((int) -1)
#endif

static int load_client_key_from_file(ssl_socket_t *socket,
                                     const char *client_key_file,
                                     const char *client_key_password) {
    SSL_CTX_set_default_passwd_cb_userdata(
            socket->ctx,
            /* const_cast */ (void *) (intptr_t) client_key_password);
    SSL_CTX_set_default_passwd_cb(socket->ctx, password_cb);

    if (!SSL_CTX_use_PrivateKey_file(socket->ctx,
                                     client_key_file,
                                     SSL_FILETYPE_PEM)) {
        log_openssl_error(socket);
        return -1;
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

static int load_client_private_key(ssl_socket_t *socket,
                                   const avs_net_private_key_t *key) {
    if (!is_private_key_valid(key)) {
        return -1;
    }

    switch (key->source) {
    case AVS_NET_DATA_SOURCE_FILE:
        return load_client_key_from_file(socket, key->data.file.path,
                                         key->data.file.password);
    case AVS_NET_DATA_SOURCE_BUFFER:
        return load_client_key_from_data(socket, &key->data.buffer);
    }
    assert(!"invalid enum value");
    return -1;
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

static int load_client_cert(ssl_socket_t *socket,
                            const avs_net_client_cert_t *cert,
                            const avs_net_private_key_t *key) {
    int result = 0;

    if (is_client_cert_empty(cert)) {
        LOG(TRACE, "client certificate not specified");
        return 0;
    }

    switch (cert->source) {
    case AVS_NET_DATA_SOURCE_FILE:
        result = SSL_CTX_use_certificate_chain_file(socket->ctx,
                                                    cert->data.file);
        break;
    case AVS_NET_DATA_SOURCE_BUFFER:
        result = SSL_CTX_use_certificate_ASN1(
                    socket->ctx, (int)cert->data.buffer.cert_size,
                    (const unsigned char*)cert->data.buffer.cert_der);
        break;
    default:
        assert(!"invalid enum value");
        return -1;
    }

    if (!result) {
        log_openssl_error(socket);
        return -1;
    }

    if (load_client_private_key(socket, key)) {
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

    if (cert_info->ca_cert_raw.cert_der
            && cert_info->ca_cert_raw.cert_size == 0) {
        LOG(ERROR, "invalid certificate info: non-NULL raw certificate of size "
            "0 given");
        return -1;
    }

    if (server_auth_enabled(cert_info)) {
        socket->verification = 1;
        SSL_CTX_set_verify(socket->ctx, SSL_VERIFY_PEER, NULL);
#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x00905100L)
        SSL_CTX_set_verify_depth(socket->ctx, 1);
#endif
        if (load_ca_certs(socket, cert_info->ca_cert_path,
                          cert_info->ca_cert_file,
                          &cert_info->ca_cert_raw)) {
            LOG(ERROR, "Error loading CA certs");
            return -1;
        }
    } else {
        LOG(DEBUG, "Server authentication disabled");
    }

    if (load_client_cert(socket,
                         &cert_info->client_cert, &cert_info->client_key)) {
        LOG(ERROR, "Error loading client certificate");
        return -1;
    }

    return 0;
}

#ifdef HAVE_OPENSSL_PSK
static unsigned int psk_client_cb(SSL *ssl,
                                  const char *hint,
                                  char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len) {
    ssl_socket_t *socket = (ssl_socket_t*)SSL_get_app_data(ssl);

    (void)hint;

    if (!socket
            || !socket->psk.psk
            || max_psk_len < socket->psk.psk_size
            || !socket->psk.identity
            || max_identity_len < socket->psk.identity_size + 1) {
        return 0;
    }

    memcpy(psk, socket->psk.psk, socket->psk.psk_size);
    memcpy(identity, socket->psk.identity, socket->psk.identity_size);
    identity[socket->psk.identity_size] = '\0';

    return (unsigned int) socket->psk.psk_size;
}

static void free_psk(avs_net_psk_t *psk) {
    free(psk->psk);
    psk->psk = NULL;
    free(psk->identity);
    psk->identity = NULL;
}

static int configure_ssl_psk(ssl_socket_t *socket,
                             const avs_net_psk_t *psk) {
    LOG(TRACE, "configure_ssl_psk");

    free_psk(&socket->psk);

    socket->psk.psk_size = psk->psk_size;
    socket->psk.psk = (char*)malloc(psk->psk_size);
    if (!socket->psk.psk) {
        LOG(ERROR, "out of memory");
        return -1;
    }

    socket->psk.identity_size = psk->identity_size;
    socket->psk.identity = (char*)malloc(psk->identity_size);
    if (!socket->psk.identity) {
        LOG(ERROR, "out of memory");
        free_psk(&socket->psk);
        return -1;
    }

    memcpy(socket->psk.psk, psk->psk, psk->psk_size);
    memcpy(socket->psk.identity, psk->identity, psk->identity_size);

    SSL_CTX_set_psk_client_callback(socket->ctx, psk_client_cb);

    return 0;
}
#else
static int configure_ssl_psk(ssl_socket_t *socket,
                             const avs_net_psk_t *psk) {
    (void) socket;
    (void) psk;
    LOG(ERROR, "PSK not supported in this version of OpenSSL");
    return -1;
}
#endif

static int configure_cipher_list(ssl_socket_t *socket,
                                 const char *cipher_list) {
    static const char *DEFAULT_OPENSSL_CIPHER_LIST = "DEFAULT";

    if (SSL_CTX_set_cipher_list(socket->ctx, cipher_list)) {
        return 0;
    }

    LOG(WARNING, "could not set cipher list to %s, using %s",
        cipher_list, DEFAULT_OPENSSL_CIPHER_LIST);
    log_openssl_error(socket);

    if (SSL_CTX_set_cipher_list(socket->ctx, DEFAULT_OPENSSL_CIPHER_LIST)) {
        return 0;
    }

    LOG(ERROR, "could not set cipher list to %s", DEFAULT_OPENSSL_CIPHER_LIST);
    log_openssl_error(socket);
    return -1;
}

static int configure_ssl(ssl_socket_t *socket,
                         const avs_net_ssl_configuration_t *configuration) {
    LOG(TRACE, "configure_ssl(socket=%p, configuration=%p)",
        (void *) socket, (const void *) configuration);

    socket->backend_configuration = configuration->backend_configuration;
    if (!socket->backend_configuration.preferred_endpoint) {
        socket->backend_configuration.preferred_endpoint =
                &socket->endpoint_buffer;
    }

    ERR_clear_error();
    SSL_CTX_set_options(socket->ctx, (long) (SSL_OP_ALL | SSL_OP_NO_SSLv2));
    if (socket->backend_type == AVS_NET_UDP_SOCKET) {
        SSL_CTX_set_read_ahead(socket->ctx, 1);
    }
    SSL_CTX_set_verify(socket->ctx, SSL_VERIFY_NONE, NULL);

#ifdef WITH_OPENSSL_CUSTOM_CIPHERS
    if (configure_cipher_list(socket, WITH_OPENSSL_CUSTOM_CIPHERS)) {
        return -1;
    }
#endif /* WITH_OPENSSL_CUSTOM_CIPHERS */

    if (!configuration) {
        LOG(WARNING, "configuration not provided");
        return 0;
    }

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
        assert(!"invalid enum value");
        return -1;
    }

    if (configuration->additional_configuration_clb
            && configuration->additional_configuration_clb(socket->ctx)) {
        LOG(ERROR, "Error while setting additional SSL configuration");
        return -1;
    }
    return 0;
}

static int bind_ssl(avs_net_abstract_socket_t *socket_,
                    const char *localaddr,
                    const char *port) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int retval;
    if (ensure_have_backend_socket(socket)) {
        return -1;
    }
    WRAP_ERRNO(socket, retval, avs_net_socket_bind(socket->backend_socket,
                                                   localaddr, port));
    return retval;
}

static int shutdown_ssl(avs_net_abstract_socket_t *socket_) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int retval;
    WRAP_ERRNO(socket, retval, avs_net_socket_shutdown(socket->backend_socket));
    return retval;
}

static int send_ssl(avs_net_abstract_socket_t *socket_,
                    const void *buffer,
                    size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result;

    LOG(TRACE, "send_ssl(socket=%p, buffer=%p, buffer_length=%lu)",
        (void *) socket, buffer, (unsigned long) buffer_length);

    errno = 0;
    result = SSL_write(socket->ssl, buffer, (int) buffer_length);
    if (result < 0 || (size_t) result < buffer_length) {
        (void) ((socket->error_code =
                        avs_net_socket_errno(socket->backend_socket))
                || (socket->error_code = errno)
                || (socket->error_code = EPROTO));
        LOG(ERROR, "write failed");
        return -1;
    } else {
        socket->error_code = 0;
        return 0;
    }
}

static int receive_ssl(avs_net_abstract_socket_t *socket_,
                       size_t *out,
                       void *buffer,
                       size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result;
    LOG(TRACE, "receive_ssl(socket=%p, buffer=%p, buffer_length=%lu)",
        (void *) socket, buffer, (unsigned long) buffer_length);

    errno = 0;
    result = SSL_read(socket->ssl, buffer, (int) buffer_length);
    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(&result, sizeof(result));
    if (result < 0) {
        (void) ((socket->error_code =
                        avs_net_socket_errno(socket->backend_socket))
                || (socket->error_code = errno)
                || (socket->error_code = EPROTO));
        *out = 0;
        return result;
    } else {
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(buffer, result);
        *out = (size_t) result;
        socket->error_code = 0;
        return 0;
    }
}

static int errno_ssl(avs_net_abstract_socket_t *net_socket) {
    return ((ssl_socket_t *) net_socket)->error_code;
}

static int cleanup_ssl(avs_net_abstract_socket_t **socket_) {
    ssl_socket_t **socket = (ssl_socket_t **) socket_;
    LOG(TRACE, "cleanup_ssl(*socket=%p)", (void *) *socket);

#ifdef HAVE_OPENSSL_PSK
    free_psk(&(*socket)->psk);
#endif

    close_ssl(*socket_);
    if ((*socket)->ctx) {
        SSL_CTX_free((*socket)->ctx);
        (*socket)->ctx = NULL;
    }
#ifdef AVS_LOG_WITH_TRACE
    free((*socket)->error_buffer);
#endif
    free(*socket);
    *socket = NULL;
    return 0;
}

static int avs_ssl_init() {
    static volatile int initialized = 0;
    if (!initialized) {
        int result = 0;
        LOG(TRACE, "OpenSSL initialization");

        SSL_library_init();
#ifdef AVS_LOG_WITH_TRACE
        SSL_load_error_strings();
#endif
        OpenSSL_add_all_algorithms();
        if (!RAND_load_file("/dev/urandom", -1)) {
            LOG(WARNING, "RAND_load_file error");
            result = -1;
        }
        /* On some OpenSSL version, RAND_load file causes hell to break loose.
         * Get rid of any "uninitialized" memory that it created :( */
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(0, sbrk(0));
        if (avs_bio_init()) {
            LOG(WARNING, "avs_bio_init error");
            result = -1;
        }
        initialized = (result ? result : 1);
    }
    return initialized < 0 ? initialized : 0;
}

static const SSL_METHOD *stream_method(avs_net_ssl_version_t version) {
    switch (version) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(OPENSSL_NO_SSL2)
    case AVS_NET_SSL_VERSION_SSLv2:
        return SSLv2_method();
#endif

    case AVS_NET_SSL_VERSION_SSLv2_OR_3:
        return SSLv23_method();

#ifndef OPENSSL_NO_SSL3
    case AVS_NET_SSL_VERSION_SSLv3:
        return SSLv3_method();
#endif

#ifndef OPENSSL_NO_TLS1
    case AVS_NET_SSL_VERSION_TLSv1:
        return TLSv1_method();

#if OPENSSL_VERSION_NUMBER >= 0x10001000L /* OpenSSL >= 1.0.1 */
    case AVS_NET_SSL_VERSION_TLSv1_1:
        return TLSv1_1_method();

    case AVS_NET_SSL_VERSION_TLSv1_2:
        return TLSv1_2_method();
#endif
#endif /* OPENSSL_NO_TLS1 */

    default:
        return NULL;
    }
}

static const SSL_METHOD *dgram_method(avs_net_ssl_version_t version) {
    switch (version) {
#if OPENSSL_VERSION_NUMBER >= 0x10001000L /* OpenSSL >= 1.0.1 */
    case AVS_NET_SSL_VERSION_TLSv1:
    case AVS_NET_SSL_VERSION_TLSv1_1:
        return DTLSv1_method();
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L /* OpenSSL >= 1.0.2 */
    case AVS_NET_SSL_VERSION_TLSv1_2:
        return DTLSv1_2_method();
#endif

    default:
        return NULL;
    }
}

static const SSL_METHOD *ssl_method(avs_net_socket_type_t backend_type,
                                    avs_net_ssl_version_t version) {
    switch (backend_type) {
    case AVS_NET_TCP_SOCKET:
        return stream_method(version);
    case AVS_NET_UDP_SOCKET:
        return dgram_method(version);
    default:
        return NULL;
    }
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 avs_net_socket_type_t backend_type,
                                 const avs_net_ssl_configuration_t *configuration) {
    const SSL_METHOD *method = NULL;

    memset(socket, 0, sizeof(*socket));
    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;
#ifdef AVS_LOG_WITH_TRACE
    socket->error_buffer = (char *) malloc(120); /* see 'man ERR_error_string' */
    if (!socket->error_buffer) {
        LOG(WARNING, "Cannot create buffer for OpenSSL error strings");
    }
#endif /* AVS_LOG_WITH_TRACE */
    socket->backend_type = backend_type;

    if (!(method = ssl_method(backend_type, configuration->version))) {
        LOG(ERROR, "Unsupported SSL version");
        return -1;
    }

    /* older versions of OpenSSL expect non-const pointer here... */
    socket->ctx = SSL_CTX_new((SSL_METHOD *) (intptr_t) method);
    if (socket->ctx == NULL) {
        log_openssl_error(socket);
        return -1;
    }

    if (configure_ssl(socket, configuration)) {
        SSL_CTX_free(socket->ctx);
        socket->ctx = NULL;
        return -1;
    }

    return 0;
}

static int create_ssl_socket(avs_net_abstract_socket_t **socket,
                             avs_net_socket_type_t backend_type,
                             const void *socket_configuration) {
    LOG(TRACE, "create_ssl_socket(socket=%p)", (void *) socket);

    if (!socket_configuration) {
        LOG(ERROR, "SSL configuration not specified");
        return -1;
    }

    if (avs_ssl_init()) {
        LOG(ERROR, "OpenSSL initialization error");
        return -1;
    }

    *socket = (avs_net_abstract_socket_t *) malloc(sizeof (ssl_socket_t));
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

int _avs_net_create_ssl_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return create_ssl_socket(socket, AVS_NET_TCP_SOCKET, socket_configuration);
}

int _avs_net_create_dtls_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
    return create_ssl_socket(socket, AVS_NET_UDP_SOCKET, socket_configuration);
}
