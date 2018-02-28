/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_config.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sys/time.h> // for struct timeval

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>

#include <avsystem/commons/errno.h>
#include <avsystem/commons/time.h>

#include "net_impl.h"

VISIBILITY_SOURCE_BEGIN

#define CERT_SUBJECT_NAME_SIZE 257

#define TRUNCATION_BUFFER_SIZE 128

#ifdef OPENSSL_VERSION_NUMBER
#define MAKE_OPENSSL_VER(Major, Minor, Fix) \
        (((Major) << 28) | ((Minor) << 20) | ((Fix) << 12))

#define OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix) \
        (OPENSSL_VERSION_NUMBER >= MAKE_OPENSSL_VER(Major, Minor, Fix))
#else
#define OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix) 0
#endif

#define OPENSSL_VERSION_NUMBER_LT(Major, Minor, Fix) \
        (!OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix))

#if (!defined(EVP_PKEY_EC) || defined(OPENSSL_NO_EC)) && defined(WITH_EC_KEY)
#warning "Detected OpenSSL version does not support EC keys - disabling"
#undef WITH_EC_KEY
#endif

#if (OPENSSL_VERSION_NUMBER_LT(1,0,0) || defined(OPENSSL_NO_PSK)) && defined(WITH_PSK)
#warning "Detected OpenSSL version does not support PSK - disabling"
#undef WITH_PSK
#endif

#if OPENSSL_VERSION_NUMBER_LT(1,0,1) && defined(WITH_DTLS)
#warning "Detected OpenSSL version does not support DTLS - disabling"
#undef WITH_DTLS
#endif

#ifndef HEADER_SSL_H
/*
 * Try to support some OpenSSL-like compatibility layers, which tend to not have
 * everything implemented.
 */
#define FAKE_OPENSSL
#endif

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    SSL_CTX *ctx;
    SSL *ssl;
    int verification;
    int error_code;
    avs_time_real_t next_deadline;
    avs_net_socket_type_t backend_type;
    avs_net_abstract_socket_t *backend_socket;
    avs_net_dtls_handshake_timeouts_t dtls_handshake_timeouts;
    avs_net_socket_configuration_t backend_configuration;
    avs_net_resolved_endpoint_t endpoint_buffer;

#ifdef WITH_PSK
    avs_net_owned_psk_t psk;
#endif
} ssl_socket_t;

#define NET_SSL_COMMON_INTERNALS
#include "ssl_common.h"

#define log_openssl_error() \
    do { \
        char error_buffer[256]; /* see 'man ERR_error_string' */ \
        LOG(ERROR, "%s", ERR_error_string(ERR_get_error(), error_buffer)); \
    } while (0)

#ifdef WITH_DTLS
#if OPENSSL_VERSION_NUMBER_LT(1,1,0)
static const EVP_CIPHER *get_evp_cipher(SSL *ssl) {
    EVP_CIPHER_CTX *ctx = ssl->enc_write_ctx;
    return ctx ? ctx->cipher : NULL;
}

static const EVP_MD *get_evp_md(SSL *ssl) {
    EVP_MD_CTX *ctx = ssl->write_hash;
    return ctx ? ctx->digest : NULL;
}
#else /* OpenSSL >= 1.1.0 */
static const EVP_CIPHER *get_evp_cipher(SSL *ssl) {
    const SSL_CIPHER *ssl_cipher = SSL_get_current_cipher(ssl);
    return ssl_cipher
            ? EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(ssl_cipher)) : NULL;
}

static const EVP_MD *get_evp_md(SSL *ssl) {
    const SSL_CIPHER *ssl_cipher = SSL_get_current_cipher(ssl);
    return ssl_cipher
            ? EVP_get_digestbynid(SSL_CIPHER_get_digest_nid(ssl_cipher)) : NULL;
}
#endif

/* values from OpenSSL 1.x */
#ifndef EVP_GCM_TLS_EXPLICIT_IV_LEN
#define EVP_GCM_TLS_EXPLICIT_IV_LEN 8
#endif
#ifndef EVP_CCM_TLS_EXPLICIT_IV_LEN
#define EVP_CCM_TLS_EXPLICIT_IV_LEN 8
#endif
#ifndef SSL3_RT_MAX_COMPRESSED_OVERHEAD
#define SSL3_RT_MAX_COMPRESSED_OVERHEAD 1024
#endif

static int get_explicit_iv_length(const EVP_CIPHER *cipher) {
    /* adapted from do_dtls1_write() in OpenSSL */
    int mode = EVP_CIPHER_mode(cipher);
    if (mode == EVP_CIPH_CBC_MODE) {
        int eivlen = EVP_CIPHER_iv_length(cipher);
        if (eivlen > 1) {
            return eivlen;
        }
    }
#ifdef EVP_CIPH_GCM_MODE
    else if (mode == EVP_CIPH_GCM_MODE) {
        return EVP_GCM_TLS_EXPLICIT_IV_LEN;
    }
#endif
#ifdef EVP_CIPH_CCM_MODE
    else if (mode == EVP_CIPH_CCM_MODE) {
        return EVP_CCM_TLS_EXPLICIT_IV_LEN;
    }
#endif
    return 0;
}

static int cipher_is_aead(const EVP_CIPHER *cipher) {
#ifdef EVP_CIPH_FLAG_AEAD_CIPHER
    if (cipher) {
        return !!(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER);
    }
#endif
    (void) cipher;
    return 0;
}

static bool cipher_has_suffix(const char *cipher_desc, const char *suffix) {
    const char *found = strstr(cipher_desc, suffix);
    if (!found) {
        return false;
    }
    found += strlen(suffix);
    return *found == '\0';
}

static bool cipher_is_ccm8(const char *cipher_desc) {
    return cipher_has_suffix(cipher_desc, "-CCM8");
}

static bool cipher_is_chachapoly(const char *cipher_desc) {
    return cipher_has_suffix(cipher_desc, "-CHACHA20-POLY1305");
}

/* values from OpenSSL-git */
#ifndef EVP_CCM_TLS_TAG_LEN
#define EVP_CCM_TLS_TAG_LEN 16
#endif
#ifndef EVP_CCM8_TLS_TAG_LEN
#define EVP_CCM8_TLS_TAG_LEN 8
#endif
#ifndef EVP_CHACHAPOLY_TLS_TAG_LEN
#define EVP_CHACHAPOLY_TLS_TAG_LEN 16
#endif

static int aead_cipher_tag_len(SSL *ssl) {
    const EVP_CIPHER *cipher = get_evp_cipher(ssl);
    assert(cipher_is_aead(cipher));
    const char *cipher_name = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl));

    if (cipher_is_ccm8(cipher_name)) {
        return EVP_CCM8_TLS_TAG_LEN;
    } else if (cipher_is_chachapoly(cipher_name)) {
        return EVP_CHACHAPOLY_TLS_TAG_LEN;
    } else if (EVP_CIPHER_mode(cipher) & EVP_CIPH_CCM_MODE) {
        return EVP_CCM_TLS_TAG_LEN;
    } else if (EVP_CIPHER_mode(cipher) & EVP_CIPH_GCM_MODE) {
        return EVP_GCM_TLS_TAG_LEN;
    }

    LOG(ERROR, "Unsupported cipher mode");
    return -1;
}

static int get_dtls_overhead(ssl_socket_t *socket,
                             int *out_header,
                             int *out_padding_size) {
    *out_header = DTLS1_RT_HEADER_LENGTH;
    *out_padding_size = 0;
    if (!socket || !socket->ssl) {
        return 0;
    }

    /* actual logic is inspired by OpenSSL's ssl_cipher_get_overhead */
    const EVP_CIPHER *cipher = get_evp_cipher(socket->ssl);
    if (!cipher) {
        return -1;
    }

    *out_header += get_explicit_iv_length(cipher);

    if (cipher_is_aead(cipher)) {
        int tag_len = aead_cipher_tag_len(socket->ssl);
        if (tag_len < 0) {
            return -1;
        }
        *out_header += tag_len;
    } else {
        const EVP_MD *md = get_evp_md(socket->ssl);
        if (md) {
            *out_header += EVP_MD_size(md);
        }

        int block_size = EVP_CIPHER_block_size(cipher);
        if (block_size < 0) {
            return -1;
        }

        if (!(EVP_CIPHER_flags(cipher) & EVP_CIPH_NO_PADDING)) {
            *out_padding_size = block_size;
        }
    }

    if (SSL_get_current_compression(socket->ssl) != NULL) {
        *out_header += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
    }
    return 0;
}
#else /* WITH_DTLS */
static int get_dtls_overhead(ssl_socket_t *socket,
                             int *out_header,
                             int *out_padding_size) {
    (void) socket;
    (void) out_header;
    (void) out_padding_size;
    return -1;
}
#endif /* WITH_DTLS */

#ifdef BIO_TYPE_SOURCE_SINK

#if OPENSSL_VERSION_NUMBER_LT(1,1,0)
#define BIO_set_init(bio, value) ((bio)->init = (value))
#define BIO_get_data(bio) ((bio)->ptr)
#define BIO_set_data(bio, data) ((bio)->ptr = (data))
#endif

static int avs_bio_write(BIO *bio, const char *data, int size) {
    ssl_socket_t *sock = (ssl_socket_t *) BIO_get_data(bio);
    if (!sock->backend_socket) {
        // see receive_ssl() for explanation why this might happen
        return -1;
    }
    sock->error_code = 0;
    if (!data || size < 0) {
        return 0;
    }
    BIO_clear_retry_flags(bio);
    if (avs_net_socket_send(sock->backend_socket, data, (size_t) size)) {
        sock->error_code = avs_net_socket_errno(sock->backend_socket);
        return -1;
    } else {
        return size;
    }
}

static avs_time_duration_t get_socket_timeout(avs_net_abstract_socket_t *sock) {
    avs_net_socket_opt_value_t opt_value;
    if (avs_net_socket_get_opt(sock, AVS_NET_SOCKET_OPT_RECV_TIMEOUT, &opt_value)) {
        return AVS_TIME_DURATION_INVALID;
    }
    return opt_value.recv_timeout;
}

static void set_socket_timeout(avs_net_abstract_socket_t *sock,
                               avs_time_duration_t timeout) {
    avs_net_socket_opt_value_t opt_value;
    opt_value.recv_timeout = timeout;
    avs_net_socket_set_opt(sock, AVS_NET_SOCKET_OPT_RECV_TIMEOUT, opt_value);
}

static avs_time_duration_t adjust_receive_timeout(ssl_socket_t *sock) {
    avs_time_duration_t socket_timeout =
            get_socket_timeout(sock->backend_socket);
    if (avs_time_real_valid(sock->next_deadline)) {
        avs_time_real_t now = avs_time_real_now();
        avs_time_duration_t timeout =
                avs_time_real_diff(sock->next_deadline, now);
        if (!avs_time_duration_valid(socket_timeout)
                || avs_time_duration_less(socket_timeout,
                                          AVS_TIME_DURATION_ZERO)
                || avs_time_duration_less(timeout, socket_timeout)) {
            set_socket_timeout(sock->backend_socket, timeout);
        }
    }
    return socket_timeout;
}

static bool socket_is_datagram(ssl_socket_t *sock) {
    return sock->backend_type == AVS_NET_UDP_SOCKET
            || sock->backend_type == AVS_NET_DTLS_SOCKET;
}

static int avs_bio_read(BIO *bio, char *buffer, int size) {
    ssl_socket_t *sock = (ssl_socket_t *) BIO_get_data(bio);
    avs_time_duration_t prev_timeout = AVS_TIME_DURATION_INVALID;
    size_t read_bytes;
    int result;
    if (!sock->backend_socket) {
        // see receive_ssl() for explanation why this might happen
        return -1;
    }
    sock->error_code = 0;
    if (!buffer || size < 0) {
        return 0;
    }
    BIO_clear_retry_flags(bio);
    if (socket_is_datagram(sock)) {
        prev_timeout = adjust_receive_timeout(sock);
    }
    if (avs_net_socket_receive(sock->backend_socket,
                               &read_bytes, buffer, (size_t) size)) {
        result = -1;
        sock->error_code = avs_net_socket_errno(sock->backend_socket);
    } else {
        result = (int) read_bytes;
    }
    if (socket_is_datagram(sock)) {
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

#ifdef WITH_DTLS
static int compare_durations(const avs_time_duration_t *left,
                             const avs_time_duration_t *right) {
    assert(avs_time_duration_valid(*left));
    assert(avs_time_duration_valid(*right));
    if (avs_time_duration_less(*left, *right)) {
        return -1;
    } else if (avs_time_duration_less(*right, *left)) {
        return 1;
    } else {
        return 0;
    }
}
#endif // WITH_DTLS

static long avs_bio_ctrl(BIO *bio, int command, long intarg, void *ptrarg) {
    ssl_socket_t *sock = (ssl_socket_t *) BIO_get_data(bio);
    (void) sock;
    (void) intarg;
    (void) ptrarg;
    switch (command) {
    case BIO_CTRL_FLUSH:
        return 1;
#ifdef WITH_DTLS
    case BIO_CTRL_DGRAM_QUERY_MTU:
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        return get_socket_inner_mtu_or_zero(sock->backend_socket);
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT: {
        struct timeval next_deadline = *(const struct timeval *) ptrarg;
        avs_time_real_t now = avs_time_real_now();
        avs_time_duration_t next_timeout = {
            .seconds = next_deadline.tv_sec - now.since_real_epoch.seconds,
            .nanoseconds = (int32_t) (next_deadline.tv_usec * 1000)
                    - now.since_real_epoch.nanoseconds
        };
        if (next_timeout.nanoseconds < 0) {
            next_timeout.seconds--;
            next_timeout.nanoseconds += 1000000000;
        }
        if (compare_durations(
                &next_timeout, &sock->dtls_handshake_timeouts.min) < 0) {
            next_timeout = sock->dtls_handshake_timeouts.min;
        } else if (compare_durations(
                &next_timeout, &sock->dtls_handshake_timeouts.max) > 0) {
            next_timeout = sock->dtls_handshake_timeouts.max;
        }
        sock->next_deadline = avs_time_real_add(now, next_timeout);
        return 0;
    }
    case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
    case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
        if (sock->error_code == ETIMEDOUT) {
            sock->error_code = 0;
            return 1;
        } else {
            return 0;
        }
    case BIO_CTRL_DGRAM_GET_PEER:
        memcpy(ptrarg, sock->backend_configuration.preferred_endpoint->data.buf,
               sock->backend_configuration.preferred_endpoint->size);
        return sock->backend_configuration.preferred_endpoint->size;
#endif // WITH_DTLS
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

#if OPENSSL_VERSION_NUMBER_LT(1,1,0)
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
#define avs_bio_init() 0

static BIO *avs_bio_spawn(ssl_socket_t *socket) {
    const void *fd_ptr =
            avs_net_socket_get_system((avs_net_abstract_socket_t *) socket);
    if (fd_ptr) {
        int fd = *(const int *) fd_ptr;
        if (!socket_is_datagram(socket)) {
            return BIO_new_socket(fd, 0);
        }
#ifdef WITH_DTLS
        if (socket_is_datagram(socket)) {
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

static bool socket_can_communicate(avs_net_abstract_socket_t *socket) {
    avs_net_socket_opt_value_t opt;
    return socket
            && !avs_net_socket_get_opt(socket, AVS_NET_SOCKET_OPT_STATE, &opt)
            && (opt.state == AVS_NET_SOCKET_STATE_ACCEPTED
                    || opt.state == AVS_NET_SOCKET_STATE_CONNECTED);
}

static void close_ssl_raw(ssl_socket_t *socket) {
    if (socket->ssl) {
        if (socket_can_communicate(socket->backend_socket)) {
            // SSL_shutdown attempts to send and receive packets,
            // so do it only if we know we can do it
            SSL_shutdown(socket->ssl);
        }
        SSL_free(socket->ssl);
        socket->ssl = NULL;
    }
    if (socket->backend_socket) {
        avs_net_socket_close(socket->backend_socket);
    }
}

static int verify_peer_subject_cn(ssl_socket_t *ssl_socket,
                                  const char *host) {
    char buffer[CERT_SUBJECT_NAME_SIZE];
    char *cn = NULL;
    X509* peer_certificate = NULL;

    /* check whether CN matches host portion of the URL */
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
        LOG(ERROR, "Subject CN(%s) does not match the URL (%s)", cn, host);
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
    if (state_opt.state == AVS_NET_SOCKET_STATE_CONNECTED) {
        return SSL_connect(socket->ssl);
    }
    if (state_opt.state == AVS_NET_SOCKET_STATE_ACCEPTED) {
#ifndef FAKE_OPENSSL
        return SSL_accept(socket->ssl);
#else
        LOG(ERROR, "Server mode not supported for this library version");
        return -1;
#endif
    }
    LOG(ERROR, "ssl_handshake: invalid socket state");
    return -1;
}

#if !defined(WITH_PSK) && !defined(SSL_set_app_data)
/*
 * SSL_set_app_data is not available in some versions, but also not used
 * anywhere if PSK is not used.
 */
#define SSL_set_app_data(S, Arg) ((void) 0)
/*
 * To be extra safe, make attempt to use SSL_get_app_data() deliberately
 * a compilation error in such case.
 */
#define SSL_get_app_data @@@@@
#endif

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
            log_openssl_error();
            LOG(TRACE, "handshake_result = %d", handshake_result);
            if (!socket->error_code) {
                socket->error_code = EPROTO;
            }
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

static bool is_ssl_started(ssl_socket_t *socket) {
    return socket->ssl != NULL;
}

#warning "TODO: Session resumption support"
static bool is_session_resumed(ssl_socket_t *socket) {
    (void) socket;
    return false;
}

static int password_cb(char *buf, int num, int rwflag, void *userdata) {
    if (!userdata) {
        buf[0] = '\0';
        return 0;
    }
    int retval = snprintf(buf, (size_t) num, "%s", (const char *) userdata);
    (void) rwflag;
    return (retval < 0 || retval >= num) ? -1 : retval;
}

typedef struct {
    EVP_PKEY *private_key;
    X509 *client_cert;
    STACK_OF(X509) *additional_ca_certs;
} pkcs12_unpacked_t;

#ifndef FAKE_OPENSSL
static void pkcs12_unpacked_delete(pkcs12_unpacked_t **pkcs12) {
    if (!*pkcs12) {
        return;
    }
    if ((*pkcs12)->additional_ca_certs) {
        sk_X509_pop_free((*pkcs12)->additional_ca_certs, X509_free);
    }
    if ((*pkcs12)->client_cert) {
        X509_free((*pkcs12)->client_cert);
    }
    if ((*pkcs12)->private_key) {
        EVP_PKEY_free((*pkcs12)->private_key);
    }
    free(*pkcs12);
    *pkcs12 = NULL;
}

static pkcs12_unpacked_t *
pkcs12_unpacked_new(const void *data,
                    size_t size,
                    const char *password) {
    if (!data) {
        LOG(ERROR, "cannot parse NULL pkcs12 data");
        return NULL;
    }
    if (!size) {
        LOG(ERROR, "cannot parse 0 sized pkcs12 data");
        return NULL;
    }
    long length = (long) (unsigned) size;
    PKCS12 *ctx = d2i_PKCS12(NULL, (const unsigned char **) &data, length);
    pkcs12_unpacked_t *result = NULL;
    if (!ctx) {
        goto cleanup;
    }

    result = (pkcs12_unpacked_t *) calloc(1, sizeof(pkcs12_unpacked_t));
    if (!result) {
        goto cleanup;
    }

    if (!PKCS12_parse(ctx, password, &result->private_key, &result->client_cert,
                      &result->additional_ca_certs)) {
        log_openssl_error();
        pkcs12_unpacked_delete(&result);
        goto cleanup;
    }

cleanup:
    if (ctx) {
        PKCS12_free(ctx);
    }
    return result;
}

static pkcs12_unpacked_t *
pkcs12_unpacked_new_from_file(const char *pkcs12_file,
                              const char *pkcs12_password) {
    pkcs12_unpacked_t *result = NULL;
    void *pkcs12_data = NULL;
    FILE *f = fopen(pkcs12_file, "rb");
    if (!f) {
        LOG(ERROR, "cannot open %s for parsing", pkcs12_file);
        return NULL;
    }

    if (fseek(f, 0L, SEEK_END)) {
        goto cleanup;
    }

    long length_signed = ftell(f);
    if (length_signed < 0
            || fseek(f, 0L, SEEK_SET)) {
        goto cleanup;
    }

    size_t length = (size_t) length_signed;
    if (!(pkcs12_data = malloc(length))
            || fread(pkcs12_data, 1, length, f) != length) {
        goto cleanup;
    }
    result = pkcs12_unpacked_new(pkcs12_data, length, pkcs12_password);

cleanup:
    if (f) {
        fclose(f);
    }
    free(pkcs12_data);
    return result;
}

static int load_ca_certs_from_pkcs12_unpacked(ssl_socket_t *socket,
                                              pkcs12_unpacked_t *pkcs12) {
    if (!pkcs12) {
        return -1;
    }
    if (pkcs12->additional_ca_certs) {
        X509_STORE *store = SSL_CTX_get_cert_store(socket->ctx);
        for (int i = 0; i < sk_X509_num(pkcs12->additional_ca_certs); ++i) {
            if (!X509_STORE_add_cert(
                        store, sk_X509_value(pkcs12->additional_ca_certs, i))) {
                log_openssl_error();
                return -1;
            }
        }
    }
    return 0;
}

static int load_ca_certs_from_pkcs12_file(ssl_socket_t *socket,
                                          const char *file,
                                          const char *password) {
    if (!file) {
        LOG(ERROR, "invalid file provided");
        return -1;
    }
    pkcs12_unpacked_t *pkcs12 =
            pkcs12_unpacked_new_from_file(file, password);
    int retval = load_ca_certs_from_pkcs12_unpacked(socket, pkcs12);
    pkcs12_unpacked_delete(&pkcs12);
    return retval;
}

static int load_ca_certs_from_pkcs12(ssl_socket_t *socket,
                                     const void *data,
                                     size_t size,
                                     const char *password) {
    pkcs12_unpacked_t *pkcs12 = pkcs12_unpacked_new(data, size, password);
    int retval = load_ca_certs_from_pkcs12_unpacked(socket, pkcs12);
    pkcs12_unpacked_delete(&pkcs12);
    return retval;
}

static int load_client_key_from_pkcs12_unpacked(ssl_socket_t *socket,
                                                pkcs12_unpacked_t *pkcs12) {
    if (!pkcs12 || !pkcs12->private_key
        || (SSL_CTX_use_PrivateKey(socket->ctx, pkcs12->private_key) != 1)) {
        log_openssl_error();
        return -1;
    }
    return 0;
}

#ifdef WITH_EC_KEY
static int load_client_key_from_pkcs8(ssl_socket_t *socket,
                                      const void *data,
                                      size_t size,
                                      const char *password) {
    SSL_CTX_set_default_passwd_cb_userdata(
            socket->ctx,
            /* const_cast */ (void *) (intptr_t) password);
    SSL_CTX_set_default_passwd_cb(socket->ctx, password_cb);

    /**
     * We support EC keys only at the moment, as OpenSSL does not seem to have
     * a method for auto-detection of key type.
     */
    if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, socket->ctx,
                                    (unsigned char *) (intptr_t) data,
                                    (long) size) != 1) {
        log_openssl_error();
        return -1;
    }
    return 0;
}

static int load_client_key_from_pkcs12(ssl_socket_t *socket,
                                       const void *data,
                                       size_t size,
                                       const char *password) {
    pkcs12_unpacked_t *pkcs12 = pkcs12_unpacked_new(data, size, password);
    int retval = load_client_key_from_pkcs12_unpacked(socket, pkcs12);
    pkcs12_unpacked_delete(&pkcs12);
    return retval;
}
#endif // WITH_EC_KEY

static int load_client_key_from_pkcs12_file(ssl_socket_t *socket,
                                            const char *client_key_file,
                                            const char *client_key_password) {
    pkcs12_unpacked_t *pkcs12 =
            pkcs12_unpacked_new_from_file(client_key_file, client_key_password);
    int retval = load_client_key_from_pkcs12_unpacked(socket, pkcs12);
    pkcs12_unpacked_delete(&pkcs12);
    return retval;
}

static int load_client_cert_from_pkcs12_unpacked(ssl_socket_t *socket,
                                                 pkcs12_unpacked_t *pkcs12) {
    if (!pkcs12) {
        return -1;
    }
    /**
     * There are two cases here apparently:
     * 1. There was some private key and a certificate associated with it, in
     *    which case we are interested in pkcs12->client_cert.
     *
     * 2. There were no private keys, therefore every certificate is considered
     *    "additional", and lands at pkcs12->additional_ca_certs stack.
     */
    X509 *cert = NULL;
    if (pkcs12->private_key && pkcs12->client_cert) {
        cert = pkcs12->client_cert;
    } else if (!pkcs12->private_key && pkcs12->additional_ca_certs) {
        cert = sk_X509_value(pkcs12->additional_ca_certs, 0);
    } else {
        return -1;
    }
    return SSL_CTX_use_certificate(socket->ctx, cert) == 1 ? 0 : -1;
}

static int load_client_cert_from_pkcs12(ssl_socket_t *socket,
                                        const void *data,
                                        size_t size,
                                        const char *password) {
    pkcs12_unpacked_t *pkcs12 = pkcs12_unpacked_new(data, size, password);
    int retval = load_client_cert_from_pkcs12_unpacked(socket, pkcs12);
    pkcs12_unpacked_delete(&pkcs12);
    return retval;
}

static int load_client_cert_from_pkcs12_file(ssl_socket_t *socket,
                                             const char *client_cert_file,
                                             const char *client_cert_password) {
    pkcs12_unpacked_t *pkcs12 =
            pkcs12_unpacked_new_from_file(client_cert_file, client_cert_password);
    int retval = load_client_cert_from_pkcs12_unpacked(socket, pkcs12);
    pkcs12_unpacked_delete(&pkcs12);
    return retval;
}
#else // FAKE_OPENSSL
#define load_ca_certs_from_pkcs12_file(socket, file, password) \
        (((void) (socket)), ((void) (file)), ((void) (password)), -1)
#define load_client_key_from_pkcs12_file(socket, file, password) \
        (((void) (socket)), ((void) (file)), ((void) (password)), -1)
#define load_client_cert_from_pkcs12_file(socket, file, password) \
        (((void) (socket)), ((void) (file)), ((void) (password)), -1)
#endif

static int load_ca_certs_from_paths(ssl_socket_t *socket,
                                    const avs_net_certificate_info_t *cert_info) {
    const char *ca_cert_path = cert_info->trusted_certs.impl.data.paths.cert_path;
    const char *ca_cert_file = cert_info->trusted_certs.impl.data.paths.cert_file;
    if (!ca_cert_path && !ca_cert_file) {
        LOG(ERROR, "CA cert path and CA cert file not provided");
        return -1;
    }
    if (!SSL_CTX_load_verify_locations(socket->ctx, ca_cert_file,
                                       ca_cert_path)) {
        log_openssl_error();
        return -1;
    }
    if (!SSL_CTX_set_default_verify_paths(socket->ctx)) {
        log_openssl_error();
        return -1;
    }
    return 0;
}

static int
load_ca_certs_from_x509(ssl_socket_t *socket, const void *data, size_t size) {
    if (!data || !size) {
        LOG(ERROR, "invalid DER CA certificate provided");
        return -1;
    }
#ifdef FAKE_OPENSSL
    (void) socket;
    LOG(ERROR, "DER certificates not supported for this library version");
    return -1;
#else
    const unsigned char *cert_data = (const unsigned char *) data;
    X509 *cert = d2i_X509(NULL, &cert_data, (int) size);
    X509_STORE *store = SSL_CTX_get_cert_store(socket->ctx);

    if (!cert || !store || !X509_STORE_add_cert(store, cert)) {
        log_openssl_error();
        X509_free(cert);
        return -1;
    }
#endif
    return 0;
}

static int load_ca_certs_from_memory(ssl_socket_t *socket,
                                     const avs_net_trusted_cert_source_t *certs) {
    switch (certs->impl.format) {
    case AVS_NET_DATA_FORMAT_DER:
        return load_ca_certs_from_x509(socket, certs->impl.data.cert.data,
                                       certs->impl.data.cert.size);
    case AVS_NET_DATA_FORMAT_PKCS12:
        return load_ca_certs_from_pkcs12(socket, certs->impl.data.cert.data,
                                         certs->impl.data.cert.size,
                                         certs->impl.data.cert.password);
    default:
        LOG(ERROR, "unsupported CA certs format");
        return -1;
    }
    return 0;
}

static int load_ca_certs_from_file(ssl_socket_t *socket,
                                   const avs_net_trusted_cert_source_t *certs) {
    if (certs->impl.format != AVS_NET_DATA_FORMAT_PKCS12) {
        LOG(ERROR, "unsupported CA certs format");
        return -1;
    }
    return load_ca_certs_from_pkcs12_file(socket, certs->impl.data.file.path,
                                          certs->impl.data.file.password);
}

#ifdef WITH_EC_KEY
static const EC_POINT *get_ec_public_key(ssl_socket_t *socket) {
    X509 *cert = NULL;
    EVP_PKEY *evp_key = NULL;
    EC_KEY *ec_key = NULL;
    const EC_POINT *point = NULL;

#if OPENSSL_VERSION_NUMBER_LT(1,1,0)
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
        log_openssl_error();
        point = NULL;
    }

#if OPENSSL_VERSION_NUMBER_LT(1,1,0)
    SSL_free(ssl);
#endif
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_key);
    return point;
}

static EC_KEY *ec_key_from_raw_private_key(ssl_socket_t *socket,
                                           const avs_net_ssl_raw_ec_t *key) {
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
        log_openssl_error();
        BN_free(private_key);
        EC_KEY_free(ec_key);
        return NULL;
    }

    BN_free(private_key);
    return ec_key;
}

static int load_client_key_from_ec(ssl_socket_t *socket,
                                   const avs_net_ssl_raw_ec_t *key) {
    if (!key->private_key || !key->private_key_size) {
        LOG(ERROR, "EC private key not provided");
        return -1;
    }
    if (!key->curve_name) {
        LOG(ERROR, "EC curve name not provided");
        return -1;
    }
    EC_KEY *ec_key = NULL;
    EVP_PKEY *evp_key = NULL;

    if (!(ec_key = ec_key_from_raw_private_key(socket, key))) {
        LOG(ERROR, "could not decode EC private key");
        log_openssl_error();
        return -1;
    }

    if (!(evp_key = EVP_PKEY_new())
            || !EVP_PKEY_assign_EC_KEY(evp_key, ec_key)) {
        log_openssl_error();
        LOG(ERROR, "could not create EVP_PKEY");
        EC_KEY_free(ec_key);
        EVP_PKEY_free(evp_key);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey(socket->ctx, evp_key) != 1) {
        LOG(ERROR, "could not set private key");
        log_openssl_error();
        EVP_PKEY_free(evp_key);
        return -1;
    }

    EVP_PKEY_free(evp_key);
    return 0;
}

static int load_client_key_from_data(ssl_socket_t *socket,
                                     const avs_net_private_key_t *key) {
    switch (key->impl.format) {
    case AVS_NET_DATA_FORMAT_EC:
        return load_client_key_from_ec(socket, &key->impl.data.ec);
    case AVS_NET_DATA_FORMAT_PKCS8:
        return load_client_key_from_pkcs8(socket, key->impl.data.pkcs8.data,
                                          key->impl.data.pkcs8.size,
                                          key->impl.data.pkcs8.password);
    case AVS_NET_DATA_FORMAT_PKCS12:
        return load_client_key_from_pkcs12(socket, key->impl.data.pkcs12.data,
                                           key->impl.data.pkcs12.size,
                                           key->impl.data.pkcs12.password);
    default:
        LOG(ERROR, "unsupported in memory private key format");
        return -1;
    }
}
#else /* WITH_EC_KEY */
#define load_client_key_from_data(...) ((int) -1)
#endif /* WITH_EC_KEY */

static int load_client_key_from_typed_file(ssl_socket_t *socket,
                                           const char *client_key_file,
                                           const char *client_key_password,
                                           int type) {
    if (!client_key_file) {
        LOG(ERROR, "private key not specified");
        return -1;
    }
    SSL_CTX_set_default_passwd_cb_userdata(
            socket->ctx,
            /* const_cast */ (void *) (intptr_t) client_key_password);
    SSL_CTX_set_default_passwd_cb(socket->ctx, password_cb);

    if (SSL_CTX_use_PrivateKey_file(socket->ctx, client_key_file, type) != 1) {
        log_openssl_error();
        return -1;
    }

    return 0;
}

static int load_client_key_from_file(ssl_socket_t *socket,
                                     const avs_net_private_key_t *pkey) {
    switch (pkey->impl.format) {
    case AVS_NET_DATA_FORMAT_PEM:
        return load_client_key_from_typed_file(socket,
                                               pkey->impl.data.file.path,
                                               pkey->impl.data.file.password,
                                               SSL_FILETYPE_PEM);
    case AVS_NET_DATA_FORMAT_DER:
        return load_client_key_from_typed_file(socket,
                                               pkey->impl.data.file.path,
                                               pkey->impl.data.file.password,
                                               SSL_FILETYPE_ASN1);
    case AVS_NET_DATA_FORMAT_PKCS12:
        return load_client_key_from_pkcs12_file(socket,
                                                pkey->impl.data.file.path,
                                                pkey->impl.data.file.password);
    default:
        LOG(ERROR, "unsupported client key file format");
        return -1;
    }
}

static int load_client_private_key(ssl_socket_t *socket,
                                   const avs_net_private_key_t *key) {
    switch (key->impl.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        return load_client_key_from_file(socket, key);
    case AVS_NET_DATA_SOURCE_BUFFER:
        return load_client_key_from_data(socket, key);
    default:
        assert(0 && "invalid enum value");
        return -1;
    }
}

static int load_client_cert_from_file(ssl_socket_t *socket,
                                      const avs_net_client_cert_t *cert) {
    switch (cert->impl.format) {
    case AVS_NET_DATA_FORMAT_PEM:
        if (SSL_CTX_use_certificate_chain_file(socket->ctx,
                                               cert->impl.data.file.path)
                == 1) {
            return 0;
        }
        return -1;
    case AVS_NET_DATA_FORMAT_PKCS12:
        return load_client_cert_from_pkcs12_file(socket,
                                                 cert->impl.data.file.path,
                                                 cert->impl.data.file.password);
    default:
        LOG(ERROR, "unsupported client cert format");
    }
    return -1;
}

static int load_client_cert_from_der(ssl_socket_t *socket,
                                     const void *data,
                                     size_t size) {
    if (!data || !size) {
        LOG(ERROR, "invalid client DER certificate provided");
        return -1;
    }
#ifdef FAKE_OPENSSL
    LOG(ERROR, "Loading certificates from memory not supported for this "
               "library version");
    return -1;
#else
    unsigned char *der = (unsigned char *) (intptr_t) data;
    if (SSL_CTX_use_certificate_ASN1(socket->ctx, (int) size, der) != 1) {
        return -1;
    }
#endif
    return 0;
}

static int load_client_cert_from_memory(ssl_socket_t *socket,
                                        const avs_net_client_cert_t *cert) {
    switch (cert->impl.format) {
    case AVS_NET_DATA_FORMAT_DER:
        return load_client_cert_from_der(socket, cert->impl.data.cert.data,
                                         cert->impl.data.cert.size);
    case AVS_NET_DATA_FORMAT_PKCS12:
        return load_client_cert_from_pkcs12(socket, cert->impl.data.pkcs12.data,
                                            cert->impl.data.pkcs12.size,
                                            cert->impl.data.pkcs12.password);
    default:
        LOG(ERROR, "unsupported in memory client certificate format");
        return -1;
    }
}

static int load_client_cert(ssl_socket_t *socket,
                            const avs_net_client_cert_t *cert,
                            const avs_net_private_key_t *key) {
    int result = -1;

    if (is_client_cert_empty(cert)) {
        LOG(TRACE, "client certificate not specified");
        return 0;
    }

    switch (cert->impl.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        result = load_client_cert_from_file(socket, cert);
        break;
    case AVS_NET_DATA_SOURCE_BUFFER:
        result = load_client_cert_from_memory(socket, cert);
        break;
    default:
        assert(0 && "invalid enum value");
        goto error;
    }

    if (result) {
        goto error;
    }

    if (load_client_private_key(socket, key)) {
        LOG(ERROR, "Error loading client private key");
        goto error;
    }

    return 0;
error:
    if (result) {
        log_openssl_error();
        return -1;
    }

    return 0;
}

static int configure_ssl_certs(ssl_socket_t *socket,
                               const avs_net_certificate_info_t *cert_info) {
    LOG(TRACE, "configure_ssl_certs");

    if (cert_info->server_cert_validation) {
        socket->verification = 1;
        SSL_CTX_set_verify(socket->ctx, SSL_VERIFY_PEER, NULL);
#if !defined(FAKE_OPENSSL) && OPENSSL_VERSION_NUMBER_LT(0,9,5)
        SSL_CTX_set_verify_depth(socket->ctx, 1);
#endif
        switch (cert_info->trusted_certs.impl.source) {
        case AVS_NET_DATA_SOURCE_PATHS:
            if (load_ca_certs_from_paths(socket, cert_info)) {
                LOG(ERROR, "Error loading CA certs from paths");
                return -1;
            }
            break;
        case AVS_NET_DATA_SOURCE_FILE:
            if (load_ca_certs_from_file(socket, &cert_info->trusted_certs)) {
                LOG(ERROR, "Error loading CA certs from file");
                return -1;
            }
            break;
        case AVS_NET_DATA_SOURCE_BUFFER:
            if (load_ca_certs_from_memory(socket, &cert_info->trusted_certs)) {
                LOG(ERROR, "Error loading CA certs from memory buffer");
                return -1;
            }
            break;
        default:
            LOG(ERROR, "Unsupported CA source");
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

#ifdef WITH_PSK
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

static int configure_ssl_psk(ssl_socket_t *socket,
                             const avs_net_psk_t *psk) {
    LOG(TRACE, "configure_ssl_psk");

    int result = _avs_net_psk_copy(&socket->psk, psk);
    if (result) {
        return result;
    }

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

#ifdef WITH_OPENSSL_CUSTOM_CIPHERS
static int configure_cipher_list(ssl_socket_t *socket,
                                 const char *cipher_list) {
    static const char *DEFAULT_OPENSSL_CIPHER_LIST = "DEFAULT";

    if (SSL_CTX_set_cipher_list(socket->ctx, cipher_list)) {
        return 0;
    }

    LOG(WARNING, "could not set cipher list to %s, using %s",
        cipher_list, DEFAULT_OPENSSL_CIPHER_LIST);
    log_openssl_error();

    if (SSL_CTX_set_cipher_list(socket->ctx, DEFAULT_OPENSSL_CIPHER_LIST)) {
        return 0;
    }

    LOG(ERROR, "could not set cipher list to %s", DEFAULT_OPENSSL_CIPHER_LIST);
    log_openssl_error();
    return -1;
}
#endif /* WITH_OPENSSL_CUSTOM_CIPHERS */

static int configure_ssl(ssl_socket_t *socket,
                         const avs_net_ssl_configuration_t *configuration) {
    LOG(TRACE, "configure_ssl(socket=%p, configuration=%p)",
        (void *) socket, (const void *) configuration);

    if (!configuration) {
        LOG(WARNING, "configuration not provided");
        return 0;
    }

    socket->backend_configuration = configuration->backend_configuration;
    if (!socket->backend_configuration.preferred_endpoint) {
        socket->backend_configuration.preferred_endpoint =
                &socket->endpoint_buffer;
    }

    ERR_clear_error();
    SSL_CTX_set_options(socket->ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_verify(socket->ctx, SSL_VERIFY_NONE, NULL);

#ifdef WITH_OPENSSL_CUSTOM_CIPHERS
    if (configure_cipher_list(socket, WITH_OPENSSL_CUSTOM_CIPHERS)) {
        return -1;
    }
#endif /* WITH_OPENSSL_CUSTOM_CIPHERS */

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

    socket->dtls_handshake_timeouts = (configuration->dtls_handshake_timeouts
            ? *configuration->dtls_handshake_timeouts
            : DEFAULT_DTLS_HANDSHAKE_TIMEOUTS);
    if (configuration->additional_configuration_clb
            && configuration->additional_configuration_clb(socket->ctx)) {
        LOG(ERROR, "Error while setting additional SSL configuration");
        return -1;
    }
    return 0;
}

static void update_send_or_recv_error_code(ssl_socket_t *socket) {
    (void) (socket->error_code
            || (socket->error_code =
                    avs_net_socket_errno(socket->backend_socket))
            || (socket->error_code = errno)
            || (socket->error_code = EPROTO));
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
        update_send_or_recv_error_code(socket);
        LOG(ERROR, "write failed");
        return -1;
    } else {
        socket->error_code = 0;
        return 0;
    }
}

static int receive_ssl(avs_net_abstract_socket_t *socket_,
                       size_t *out_bytes_received,
                       void *buffer,
                       size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result = 0;
    LOG(TRACE, "receive_ssl(socket=%p, buffer=%p, buffer_length=%lu)",
        (void *) socket, buffer, (unsigned long) buffer_length);

    errno = 0;
    result = SSL_read(socket->ssl, buffer, (int) buffer_length);
    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(&result, sizeof(result));
    if (result < 0) {
        update_send_or_recv_error_code(socket);
        *out_bytes_received = 0;
        return result;
    } else {
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(buffer, result);
        *out_bytes_received = (size_t) result;
        socket->error_code = 0;
        if (socket_is_datagram(socket)
                && buffer_length > 0
                && (size_t) result == buffer_length) {
            // Check whether the message is truncated;
            // Normally we could use SSL_pending(), but on some versions of
            // OpenSSL, it is broken and always return 0 for DTLS; see
            // https://github.com/openssl/openssl/issues/5478 for details.
            // We resort to this hack of calling SSL_read() with actual network
            // communication blocked.
            avs_net_abstract_socket_t *backend_socket = socket->backend_socket;
            socket->backend_socket = NULL;
            do {
                char truncation_buffer[TRUNCATION_BUFFER_SIZE];
                if ((result = SSL_read(socket->ssl, truncation_buffer,
                                       (int) sizeof(truncation_buffer))) > 0
                        && !socket->error_code) {
                    LOG(WARNING, "receive_ssl: message truncated");
                    socket->error_code = EMSGSIZE;
                }
            } while (result > 0);
            socket->backend_socket = backend_socket;
            if (socket->error_code) {
                return -1;
            }
        }
    }
    return 0;
}

static int cleanup_ssl(avs_net_abstract_socket_t **socket_) {
    ssl_socket_t **socket = (ssl_socket_t **) socket_;
    LOG(TRACE, "cleanup_ssl(*socket=%p)", (void *) *socket);

#ifdef WITH_PSK
    _avs_net_psk_cleanup(&(*socket)->psk);
#endif

    close_ssl(*socket_);
    avs_net_socket_cleanup(&(*socket)->backend_socket);
    if ((*socket)->ctx) {
        SSL_CTX_free((*socket)->ctx);
        (*socket)->ctx = NULL;
    }
    free(*socket);
    *socket = NULL;
    return 0;
}

static void cleanup_ssl_global(void) {
    // do nothing
}

static int initialize_ssl_global(void) {
    LOG(TRACE, "OpenSSL initialization");

    SSL_library_init();
#ifdef AVS_LOG_WITH_TRACE
    SSL_load_error_strings();
#endif
    OpenSSL_add_all_algorithms();
    if (!RAND_load_file("/dev/urandom", -1)) {
        LOG(WARNING, "RAND_load_file error");
        return -1;
    }
    /* On some OpenSSL version, RAND_load file causes hell to break loose.
     * Get rid of any "uninitialized" memory that it created :( */
    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(0, sbrk(0));
    if (avs_bio_init()) {
        LOG(WARNING, "avs_bio_init error");
        return -1;
    }
    return 0;
}

#ifndef FAKE_OPENSSL
#define OPENSSL_METHOD(Proto) Proto##_method
#else
/* Allow the compatibility layer libraries to work at least for client mode */
#define OPENSSL_METHOD(Proto) Proto##_client_method
#endif

#if OPENSSL_VERSION_NUMBER_LT(1,1,0)
static const SSL_METHOD *stream_method(avs_net_ssl_version_t version) {
    switch (version) {
    case AVS_NET_SSL_VERSION_DEFAULT:
    case AVS_NET_SSL_VERSION_SSLv2_OR_3:
        return OPENSSL_METHOD(SSLv23)();

#ifndef OPENSSL_NO_SSL2
    case AVS_NET_SSL_VERSION_SSLv2:
        return OPENSSL_METHOD(SSLv2)();
#endif

#ifndef OPENSSL_NO_SSL3
    case AVS_NET_SSL_VERSION_SSLv3:
        return OPENSSL_METHOD(SSLv3)();
#endif

#ifndef OPENSSL_NO_TLS1
    case AVS_NET_SSL_VERSION_TLSv1:
        return OPENSSL_METHOD(TLSv1)();

#if OPENSSL_VERSION_NUMBER_GE(1,0,1)
    case AVS_NET_SSL_VERSION_TLSv1_1:
        return OPENSSL_METHOD(TLSv1_1)();

    case AVS_NET_SSL_VERSION_TLSv1_2:
        return OPENSSL_METHOD(TLSv1_2)();
#endif
#endif /* OPENSSL_NO_TLS1 */

    default:
        return NULL;
    }
}

#ifndef WITH_DTLS
#define dgram_method(x) ((void)(x), (const SSL_METHOD*)NULL)
#else /* WITH_DTLS */

static const SSL_METHOD *dgram_method(avs_net_ssl_version_t version) {
    switch (version) {
    case AVS_NET_SSL_VERSION_DEFAULT:
#if OPENSSL_VERSION_NUMBER_GE(1,0,2)
        return OPENSSL_METHOD(DTLS)();

    case AVS_NET_SSL_VERSION_TLSv1_2:
        return OPENSSL_METHOD(DTLSv1_2)();
#endif

#if OPENSSL_VERSION_NUMBER_GE(1,0,1)
    case AVS_NET_SSL_VERSION_TLSv1:
    case AVS_NET_SSL_VERSION_TLSv1_1:
        return OPENSSL_METHOD(DTLSv1)();
#endif

    default:
        return NULL;
    }
}

#endif /* WITH_DTLS */

static SSL_CTX *make_ssl_context(bool dtls, avs_net_ssl_version_t version) {
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx = NULL;
    if (dtls) {
        method = dgram_method(version);
    } else {
        method = stream_method(version);
    }
    if (!method) {
        LOG(ERROR, "Unsupported SSL version");
        return NULL;
    }
    /* older versions of OpenSSL expect non-const pointer here... */
    if (!(ctx = SSL_CTX_new((SSL_METHOD *) (intptr_t) method))) {
        log_openssl_error();
    }
    return ctx;
}
#else /* OpenSSL >= 1.1.0 */
static int stream_proto_version(avs_net_ssl_version_t version) {
    switch (version) {
    case AVS_NET_SSL_VERSION_DEFAULT:
    case AVS_NET_SSL_VERSION_SSLv2_OR_3:
        return 0;
    case AVS_NET_SSL_VERSION_SSLv3:
        return SSL3_VERSION;
    case AVS_NET_SSL_VERSION_TLSv1:
        return TLS1_VERSION;
    case AVS_NET_SSL_VERSION_TLSv1_1:
        return TLS1_1_VERSION;
    case AVS_NET_SSL_VERSION_TLSv1_2:
        return TLS1_2_VERSION;
    default:
        return -1;
    }
}

#ifndef WITH_DTLS
#define dgram_proto_version(x) ((void)(x), -1)
#else /* WITH_DTLS */

static int dgram_proto_version(avs_net_ssl_version_t version) {
    switch (version) {
    case AVS_NET_SSL_VERSION_DEFAULT:
        return 0;
    case AVS_NET_SSL_VERSION_TLSv1:
    case AVS_NET_SSL_VERSION_TLSv1_1:
        return DTLS1_VERSION;
    case AVS_NET_SSL_VERSION_TLSv1_2:
        return DTLS1_2_VERSION;
    default:
        return -1;
    }
}

#endif /* WITH_DTLS */

static SSL_CTX *make_ssl_context(bool dtls,
                                 avs_net_ssl_version_t version) {
    const SSL_METHOD *method = NULL;
    int ossl_proto_version = 0;
    SSL_CTX *ctx = NULL;
    if (!dtls) {
        method = OPENSSL_METHOD(TLS)();
        ossl_proto_version = stream_proto_version(version);
    }
#ifdef WITH_DTLS
    else {
        method = OPENSSL_METHOD(DTLS)();
        ossl_proto_version = dgram_proto_version(version);
    }
#endif
    if (ossl_proto_version < 0) {
        LOG(ERROR, "Unsupported SSL version");
        return NULL;
    }
    if (!method) {
        LOG(ERROR, "Could not get OpenSSL method handle");
        return NULL;
    }
    if (!(ctx = SSL_CTX_new(method))) {
        log_openssl_error();
        return NULL;
    }
    if (ossl_proto_version
            && !SSL_CTX_set_min_proto_version(ctx, ossl_proto_version)) {
        log_openssl_error();
        return NULL;
    }
    return ctx;
}
#endif

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 avs_net_socket_type_t backend_type,
                                 const avs_net_ssl_configuration_t *configuration) {
    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;
    socket->backend_type = backend_type;

    if (!(socket->ctx = make_ssl_context(socket_is_datagram(socket),
                                         configuration->version))) {
        return -1;
    }

    if (configure_ssl(socket, configuration)) {
        SSL_CTX_free(socket->ctx);
        socket->ctx = NULL;
        return -1;
    }

    return 0;
}
