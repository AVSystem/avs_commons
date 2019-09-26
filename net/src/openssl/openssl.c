/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

// NOTE: OpenSSL headers sometimes (depending on a version) contain some of the
// symbols poisoned via inclusion of avs_commons_config.h. Therefore they must
// be included first.
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <avs_commons_config.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sys/time.h> // for struct timeval

#include <avsystem/commons/errno_map.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/stream/stream_membuf.h>
#include <avsystem/commons/time.h>

#include "../global.h"
#include "../net_impl.h"

#include "common.h"
#ifdef WITH_X509
#    include "data_loader.h"
#endif // WITH_X509

VISIBILITY_SOURCE_BEGIN

#define CERT_SUBJECT_NAME_SIZE 257

#define TRUNCATION_BUFFER_SIZE 128

#ifdef OPENSSL_VERSION_NUMBER
#    define MAKE_OPENSSL_VER(Major, Minor, Fix) \
        (((Major) << 28) | ((Minor) << 20) | ((Fix) << 12))

#    define OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix) \
        (OPENSSL_VERSION_NUMBER >= MAKE_OPENSSL_VER(Major, Minor, Fix))
#else
#    define OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix) 0
#endif

#define OPENSSL_VERSION_NUMBER_LT(Major, Minor, Fix) \
    (!OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix))

#if (OPENSSL_VERSION_NUMBER_LT(1, 0, 0) || defined(OPENSSL_NO_PSK)) \
        && defined(WITH_PSK)
#    warning "Detected OpenSSL version does not support PSK - disabling"
#    undef WITH_PSK
#endif

#if OPENSSL_VERSION_NUMBER_LT(1, 0, 1) && defined(WITH_DTLS)
#    warning "Detected OpenSSL version does not support DTLS - disabling"
#    undef WITH_DTLS
#endif

typedef struct {
    const avs_net_socket_v_table_t *const operations;
    SSL_CTX *ctx;
    SSL *ssl;
    int verification;
    avs_error_t bio_error;
    avs_time_real_t next_deadline;
    avs_net_socket_type_t backend_type;
    avs_net_socket_t *backend_socket;
    avs_net_dtls_handshake_timeouts_t dtls_handshake_timeouts;
    avs_net_socket_configuration_t backend_configuration;
    avs_net_resolved_endpoint_t endpoint_buffer;

#ifdef WITH_PSK
    avs_net_owned_psk_t psk;
#endif

    /// Set of ciphersuites configured by user
    avs_net_socket_tls_ciphersuites_t enabled_ciphersuites;
    /// Non empty, when custom server hostname shall be used.
    char server_name_indication[256];
} ssl_socket_t;

#define NET_SSL_COMMON_INTERNALS
#include "../ssl_common.h"

#ifdef WITH_DTLS
#    if OPENSSL_VERSION_NUMBER_LT(1, 1, 0)
static const EVP_CIPHER *get_evp_cipher(SSL *ssl) {
    EVP_CIPHER_CTX *ctx = ssl->enc_write_ctx;
    return ctx ? ctx->cipher : NULL;
}

static const EVP_MD *get_evp_md(SSL *ssl) {
    EVP_MD_CTX *ctx = ssl->write_hash;
    return ctx ? ctx->digest : NULL;
}
#    else /* OpenSSL >= 1.1.0 */
static const EVP_CIPHER *get_evp_cipher(SSL *ssl) {
    const SSL_CIPHER *ssl_cipher = SSL_get_current_cipher(ssl);
    return ssl_cipher
                   ? EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(ssl_cipher))
                   : NULL;
}

static const EVP_MD *get_evp_md(SSL *ssl) {
    const SSL_CIPHER *ssl_cipher = SSL_get_current_cipher(ssl);
    return ssl_cipher
                   ? EVP_get_digestbynid(SSL_CIPHER_get_digest_nid(ssl_cipher))
                   : NULL;
}
#    endif

/* values from OpenSSL 1.x */
#    ifndef EVP_GCM_TLS_EXPLICIT_IV_LEN
#        define EVP_GCM_TLS_EXPLICIT_IV_LEN 8
#    endif
#    ifndef EVP_CCM_TLS_EXPLICIT_IV_LEN
#        define EVP_CCM_TLS_EXPLICIT_IV_LEN 8
#    endif
#    ifndef SSL3_RT_MAX_COMPRESSED_OVERHEAD
#        define SSL3_RT_MAX_COMPRESSED_OVERHEAD 1024
#    endif

static int get_explicit_iv_length(const EVP_CIPHER *cipher) {
    /* adapted from do_dtls1_write() in OpenSSL */
    int mode = EVP_CIPHER_mode(cipher);
    if (mode == EVP_CIPH_CBC_MODE) {
        int eivlen = EVP_CIPHER_iv_length(cipher);
        if (eivlen > 1) {
            return eivlen;
        }
    }
#    ifdef EVP_CIPH_GCM_MODE
    else if (mode == EVP_CIPH_GCM_MODE) {
        return EVP_GCM_TLS_EXPLICIT_IV_LEN;
    }
#    endif
#    ifdef EVP_CIPH_CCM_MODE
    else if (mode == EVP_CIPH_CCM_MODE) {
        return EVP_CCM_TLS_EXPLICIT_IV_LEN;
    }
#    endif
    return 0;
}

static int cipher_is_aead(const EVP_CIPHER *cipher) {
#    ifdef EVP_CIPH_FLAG_AEAD_CIPHER
    if (cipher) {
        return !!(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER);
    }
#    endif
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
#    ifndef EVP_CCM_TLS_TAG_LEN
#        define EVP_CCM_TLS_TAG_LEN 16
#    endif
#    ifndef EVP_CCM8_TLS_TAG_LEN
#        define EVP_CCM8_TLS_TAG_LEN 8
#    endif
#    ifndef EVP_CHACHAPOLY_TLS_TAG_LEN
#        define EVP_CHACHAPOLY_TLS_TAG_LEN 16
#    endif

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

static avs_error_t get_dtls_overhead(ssl_socket_t *socket,
                                     int *out_header,
                                     int *out_padding_size) {
    if (!is_ssl_started(socket)) {
        return avs_errno(AVS_EBADF);
    }
    *out_header = DTLS1_RT_HEADER_LENGTH;
    *out_padding_size = 0;

    /* actual logic is inspired by OpenSSL's ssl_cipher_get_overhead */
    const EVP_CIPHER *cipher = get_evp_cipher(socket->ssl);
    if (!cipher) {
        return avs_errno(AVS_EBADF);
    }

    *out_header += get_explicit_iv_length(cipher);

    if (cipher_is_aead(cipher)) {
        int tag_len = aead_cipher_tag_len(socket->ssl);
        if (tag_len < 0) {
            return avs_errno(AVS_ENOTSUP);
        }
        *out_header += tag_len;
    } else {
        const EVP_MD *md = get_evp_md(socket->ssl);
        if (md) {
            *out_header += EVP_MD_size(md);
        }

        int block_size = EVP_CIPHER_block_size(cipher);
        if (block_size < 0) {
            return avs_errno(AVS_EBADF);
        }

        if (!(EVP_CIPHER_flags(cipher) & EVP_CIPH_NO_PADDING)) {
            *out_padding_size = block_size;
        }
    }

    if (SSL_get_current_compression(socket->ssl) != NULL) {
        *out_header += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
    }
    return AVS_OK;
}
#else  /* WITH_DTLS */
static avs_error_t get_dtls_overhead(ssl_socket_t *socket,
                                     int *out_header,
                                     int *out_padding_size) {
    (void) socket;
    (void) out_header;
    (void) out_padding_size;
    return avs_errno(AVS_ENOTSUP);
}
#endif /* WITH_DTLS */

#ifdef BIO_TYPE_SOURCE_SINK

#    if OPENSSL_VERSION_NUMBER_LT(1, 1, 0)
#        define BIO_set_init(bio, value) ((bio)->init = (value))
#        define BIO_get_data(bio) ((bio)->ptr)
#        define BIO_set_data(bio, data) ((bio)->ptr = (data))
#    endif

static int avs_bio_write(BIO *bio, const char *data, int size) {
    ssl_socket_t *sock = (ssl_socket_t *) BIO_get_data(bio);
    if (!sock->backend_socket) {
        // see receive_ssl() for explanation why this might happen
        return -1;
    }
    if (!data || size < 0) {
        sock->bio_error = AVS_OK;
        return 0;
    }
    BIO_clear_retry_flags(bio);
    if (avs_is_err((sock->bio_error = avs_net_socket_send(
                            sock->backend_socket, data, (size_t) size)))) {
        return -1;
    } else {
        return size;
    }
}

static avs_time_duration_t get_socket_timeout(avs_net_socket_t *sock) {
    avs_net_socket_opt_value_t opt_value;
    if (avs_is_err(avs_net_socket_get_opt(sock, AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                                          &opt_value))) {
        return AVS_TIME_DURATION_INVALID;
    }
    return opt_value.recv_timeout;
}

static void set_socket_timeout(avs_net_socket_t *sock,
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
    if (!buffer || size < 0) {
        sock->bio_error = AVS_OK;
        return 0;
    }
    BIO_clear_retry_flags(bio);
    if (socket_is_datagram(sock)) {
        prev_timeout = adjust_receive_timeout(sock);
    }
    if (avs_is_err((sock->bio_error = avs_net_socket_receive(
                            sock->backend_socket, &read_bytes, buffer,
                            (size_t) size)))) {
        result = -1;
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

#    ifdef WITH_DTLS
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
#    endif // WITH_DTLS

static long avs_bio_ctrl(BIO *bio, int command, long intarg, void *ptrarg) {
    ssl_socket_t *sock = (ssl_socket_t *) BIO_get_data(bio);
    (void) sock;
    (void) intarg;
    (void) ptrarg;
    switch (command) {
    case BIO_CTRL_FLUSH:
        return 1;
#    ifdef WITH_DTLS
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
        if (compare_durations(&next_timeout, &sock->dtls_handshake_timeouts.min)
                < 0) {
            next_timeout = sock->dtls_handshake_timeouts.min;
        } else if (compare_durations(&next_timeout,
                                     &sock->dtls_handshake_timeouts.max)
                   > 0) {
            next_timeout = sock->dtls_handshake_timeouts.max;
        }
        sock->next_deadline = avs_time_real_add(now, next_timeout);
        return 0;
    }
    case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
    case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
        if (sock->bio_error.category == AVS_ERRNO_CATEGORY
                && sock->bio_error.code == AVS_ETIMEDOUT) {
            sock->bio_error = AVS_OK;
            return 1;
        } else {
            return 0;
        }
    case BIO_CTRL_DGRAM_GET_PEER:
        memcpy(ptrarg, sock->backend_configuration.preferred_endpoint->data.buf,
               sock->backend_configuration.preferred_endpoint->size);
        return sock->backend_configuration.preferred_endpoint->size;
#    endif // WITH_DTLS
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

#    if OPENSSL_VERSION_NUMBER_LT(1, 1, 0)
static int avs_bio_init(void) {
    static BIO_METHOD AVS_BIO_IMPL = { (100 | BIO_TYPE_SOURCE_SINK),
                                       "avs_net",
                                       avs_bio_write,
                                       avs_bio_read,
                                       avs_bio_puts,
                                       avs_bio_gets,
                                       avs_bio_ctrl,
                                       avs_bio_create,
                                       avs_bio_destroy,
                                       NULL };
    AVS_BIO = &AVS_BIO_IMPL;
    return 0;
}
#    else
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
#    endif

static BIO *avs_bio_spawn(ssl_socket_t *socket) {
    BIO *bio = BIO_new(AVS_BIO);
    if (bio) {
        BIO_set_data(bio, socket);
    }
    return bio;
}
#else /* BIO_TYPE_SOURCE_SINK */
#    define avs_bio_init() 0

static BIO *avs_bio_spawn(ssl_socket_t *socket) {
    const void *fd_ptr = avs_net_socket_get_system((avs_net_socket_t *) socket);
    if (fd_ptr) {
        int fd = *(const int *) fd_ptr;
        if (!socket_is_datagram(socket)) {
            return BIO_new_socket(fd, 0);
        }
#    ifdef WITH_DTLS
        if (socket_is_datagram(socket)) {
            BIO *bio = BIO_new_dgram(fd, 0);
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0,
                     socket->backend_configuration.preferred_endpoint->data);
            return bio;
        }
#    endif
    }
    return NULL;
}
#endif /* BIO_TYPE_SOURCE_SINK */

static bool socket_can_communicate(avs_net_socket_t *socket) {
    avs_net_socket_opt_value_t opt;
    return socket
           && avs_is_ok(avs_net_socket_get_opt(socket, AVS_NET_SOCKET_OPT_STATE,
                                               &opt))
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

static int verify_peer_subject_cn(ssl_socket_t *ssl_socket, const char *host) {
    char buffer[CERT_SUBJECT_NAME_SIZE];
    char *cn = NULL;
    X509 *peer_certificate = NULL;

    /* check whether CN matches host portion of the URL */
    peer_certificate = SSL_get_peer_certificate(ssl_socket->ssl);
    if (!peer_certificate) {
        LOG(ERROR, "Cannot load peer certificate");
        return -1;
    }
    X509_NAME_oneline(X509_get_subject_name(peer_certificate), buffer,
                      sizeof(buffer));
    X509_free(peer_certificate);

    cn = strstr(buffer, "CN=");
    if (cn != NULL) {
        char *cne = strchr(cn, '/');
        if (cne)
            *cne = '\0';
        cn += 3;
    }
    if (cn == NULL || strcmp(cn, host)) {
        LOG(ERROR, "Subject CN(%s) does not match the URL (%s)", cn, host);
        return -1;
    }

    return 0;
}

static avs_error_t ssl_handshake(ssl_socket_t *socket) {
    avs_net_socket_opt_value_t state_opt;
    avs_error_t err =
            avs_net_socket_get_opt(socket->backend_socket,
                                   AVS_NET_SOCKET_OPT_STATE, &state_opt);
    if (avs_is_err(err)) {
        LOG(ERROR, "ssl_handshake: could not get socket state");
        return err;
    }
    socket->bio_error = AVS_OK;
    int result;
    if (state_opt.state == AVS_NET_SOCKET_STATE_CONNECTED) {
        result = SSL_connect(socket->ssl);
    } else if (state_opt.state == AVS_NET_SOCKET_STATE_ACCEPTED) {
        result = SSL_accept(socket->ssl);
    } else {
        LOG(ERROR, "ssl_handshake: invalid socket state");
        return avs_errno(AVS_EBADF);
    }
    if (result <= 0) {
        if (avs_is_err(socket->bio_error)) {
            return socket->bio_error;
        } else {
            return avs_errno(AVS_EPROTO);
        }
    }
    return AVS_OK;
}

#if !defined(WITH_PSK) && !defined(SSL_set_app_data)
/*
 * SSL_set_app_data is not available in some versions, but also not used
 * anywhere if PSK is not used.
 */
#    define SSL_set_app_data(S, Arg) ((void) 0)
/*
 * To be extra safe, make attempt to use SSL_get_app_data() deliberately
 * a compilation error in such case.
 */
#    define SSL_get_app_data @ @ @ @ @
#endif

static int configure_cipher_list(ssl_socket_t *socket,
                                 const char *cipher_list) {
    LOG(DEBUG, "cipher list: %s", cipher_list);
    if (SSL_CTX_set_cipher_list(socket->ctx, cipher_list)) {
        return 0;
    }

    LOG(WARNING, "could not set cipher list to %s", cipher_list);
    log_openssl_error();
    return -1;
}

static avs_error_t
ids_to_cipher_list(ssl_socket_t *socket,
                   const avs_net_socket_tls_ciphersuites_t *suites,
                   char **out_cipher_list) {
    if (!suites) {
        return avs_errno(AVS_EINVAL);
    }

    avs_stream_t *stream = avs_stream_membuf_create();
    if (!stream) {
        return avs_errno(AVS_ENOMEM);
    }

    bool first = true;
    avs_error_t err = AVS_OK;

    for (size_t i = 0; i < suites->num_ids; ++i) {
        if (suites->ids[i] > UINT16_MAX) {
            LOG(DEBUG, "ignoring unexpectedly large cipher ID: 0x%x",
                suites->ids[i]);
            continue;
        }

        unsigned char id_as_chars[] = { (unsigned char) ((suites->ids[i]) >> 8),
                                        (unsigned char) ((suites->ids[i])
                                                         & 0xFF) };
        const SSL_CIPHER *cipher = SSL_CIPHER_find(socket->ssl, id_as_chars);
        if (!cipher) {
            LOG(DEBUG, "ignoring unsupported cipher ID: 0x%04x",
                suites->ids[i]);
            continue;
        }

        if (first) {
            first = false;
        } else {
            err = avs_stream_write(stream, ":", 1);
        }

        if (avs_is_ok(err)) {
            const char *name = SSL_CIPHER_get_name(cipher);
            err = avs_stream_write(stream, name, strlen(name));
        }
    }

    (void) (avs_is_err(err)
            || avs_is_err((err = avs_stream_write(stream, "", 1)))
            || avs_is_err((err = avs_stream_membuf_take_ownership(
                                   stream, (void **) out_cipher_list, NULL))));
    avs_stream_cleanup(&stream);
    return err;
}

static avs_error_t start_ssl(ssl_socket_t *socket, const char *host) {
    BIO *bio = NULL;
    LOG(TRACE, "start_ssl(socket=%p)", (void *) socket);

    socket->ssl = SSL_new(socket->ctx);
    if (!socket->ssl) {
        return avs_errno(AVS_ENOMEM);
    }
    SSL_set_app_data(socket->ssl, socket);

    if (socket->enabled_ciphersuites.ids != NULL) {
        char *ciphersuites_string = NULL;
        avs_error_t err =
                ids_to_cipher_list(socket, &socket->enabled_ciphersuites,
                                   &ciphersuites_string);
        if (avs_is_err(err)) {
            assert(!ciphersuites_string);
            return err;
        }

        int result = configure_cipher_list(socket, ciphersuites_string);
        avs_free(ciphersuites_string);
        if (result) {
            return avs_errno(AVS_EINVAL);
        }
    }

#ifdef SSL_MODE_AUTO_RETRY
    SSL_set_mode(socket->ssl, SSL_MODE_AUTO_RETRY);
#endif

    if (SSL_set_tlsext_host_name(
                socket->ssl,
                // NOTE: this ugly cast is required because openssl does
                // drop const qualifiers...
                (void *) (intptr_t) (socket->server_name_indication[0]
                                             ? socket->server_name_indication
                                             : host))
            == 0) {
        LOG(ERROR, "cannot setup SNI extension");
        return avs_errno(AVS_ENOMEM);
    }

    bio = avs_bio_spawn(socket);
    if (!bio) {
        LOG(ERROR, "cannot create BIO object");
        return avs_errno(AVS_ENOMEM);
    }
    SSL_set_bio(socket->ssl, bio, bio);

    avs_error_t err = ssl_handshake(socket);
    if (avs_is_err(err)) {
        LOG(ERROR, "SSL handshake failed.");
        log_openssl_error();
        return err;
    }

    if (socket->verification && verify_peer_subject_cn(socket, host) != 0) {
        LOG(ERROR, "server certificate verification failure");
        return avs_errno(AVS_EPROTO);
    }

    return AVS_OK;
}

static bool is_ssl_started(ssl_socket_t *socket) {
    return socket->ssl != NULL;
}

static bool is_session_resumed(ssl_socket_t *socket) {
    (void) socket;
    return false;
}

#ifdef WITH_X509
static avs_error_t
configure_ssl_certs(ssl_socket_t *socket,
                    const avs_net_certificate_info_t *cert_info) {
    LOG(TRACE, "configure_ssl_certs");

    if (cert_info->server_cert_validation) {
        socket->verification = 1;
        SSL_CTX_set_verify(socket->ctx, SSL_VERIFY_PEER, NULL);
#    if OPENSSL_VERSION_NUMBER_LT(0, 9, 5)
        SSL_CTX_set_verify_depth(socket->ctx, 1);
#    endif
        avs_error_t err =
                _avs_net_openssl_load_ca_certs(socket->ctx,
                                               &cert_info->trusted_certs);
        if (avs_is_err(err)) {
            LOG(ERROR, "could not load CA chain");
            return err;
        }
    } else {
        LOG(DEBUG, "Server authentication disabled");
    }

    if (cert_info->client_cert.desc.source != AVS_NET_DATA_SOURCE_EMPTY) {
        avs_error_t err =
                _avs_net_openssl_load_client_cert(socket->ctx,
                                                  &cert_info->client_cert);
        if (avs_is_err(err)) {
            LOG(ERROR, "could not load client certificate");
            return err;
        }
        if (avs_is_err((err = _avs_net_openssl_load_client_key(
                                socket->ctx, &cert_info->client_key)))) {
            LOG(ERROR, "could not load client private key");
            return err;
        }
    } else {
        LOG(TRACE, "client certificate not specified");
    }

    return AVS_OK;
}
#else
static avs_error_t
configure_ssl_certs(ssl_socket_t *socket,
                    const avs_net_certificate_info_t *cert_info) {
    (void) socket;
    (void) psk;
    LOG(ERROR, "X.509 support disabled");
    return avs_errno(AVS_ENOTSUP);
}
#endif // WITH_X509

#ifdef WITH_PSK
static unsigned int psk_client_cb(SSL *ssl,
                                  const char *hint,
                                  char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len) {
    ssl_socket_t *socket = (ssl_socket_t *) SSL_get_app_data(ssl);

    (void) hint;

    if (!socket || !socket->psk.psk || max_psk_len < socket->psk.psk_size
            || !socket->psk.identity
            || max_identity_len < socket->psk.identity_size + 1) {
        return 0;
    }

    memcpy(psk, socket->psk.psk, socket->psk.psk_size);
    memcpy(identity, socket->psk.identity, socket->psk.identity_size);
    identity[socket->psk.identity_size] = '\0';

    return (unsigned int) socket->psk.psk_size;
}

static avs_error_t configure_ssl_psk(ssl_socket_t *socket,
                                     const avs_net_psk_info_t *psk) {
    LOG(TRACE, "configure_ssl_psk");

    avs_error_t err = _avs_net_psk_copy(&socket->psk, psk);
    if (avs_is_ok(err)) {
        SSL_CTX_set_psk_client_callback(socket->ctx, psk_client_cb);
    }
    return err;
}
#else
static avs_error_t configure_ssl_psk(ssl_socket_t *socket,
                                     const avs_net_psk_info_t *psk) {
    (void) socket;
    (void) psk;
    LOG(ERROR, "PSK not supported in this version of OpenSSL");
    return avs_errno(AVS_ENOTSUP);
}
#endif

static avs_error_t
configure_ssl(ssl_socket_t *socket,
              const avs_net_ssl_configuration_t *configuration) {
    LOG(TRACE, "configure_ssl(socket=%p, configuration=%p)", (void *) socket,
        (const void *) configuration);

    if (!configuration) {
        LOG(WARNING, "configuration not provided");
        return AVS_OK;
    }

    socket->backend_configuration = configuration->backend_configuration;
    if (!socket->backend_configuration.preferred_endpoint) {
        socket->backend_configuration.preferred_endpoint =
                &socket->endpoint_buffer;
    }

    ERR_clear_error();
    SSL_CTX_set_options(socket->ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_verify(socket->ctx, SSL_VERIFY_NONE, NULL);

    avs_error_t err;
    switch (configuration->security.mode) {
    case AVS_NET_SECURITY_PSK:
        err = configure_ssl_psk(socket, &configuration->security.data.psk);
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        err = configure_ssl_certs(socket, &configuration->security.data.cert);
        break;
    default:
        AVS_UNREACHABLE("invalid enum value");
        err = avs_errno(AVS_EBADF);
    }
    if (avs_is_err(err)) {
        return err;
    }

    socket->dtls_handshake_timeouts =
            (configuration->dtls_handshake_timeouts
                     ? *configuration->dtls_handshake_timeouts
                     : DEFAULT_DTLS_HANDSHAKE_TIMEOUTS);

    if (configuration->server_name_indication) {
        size_t len = strlen(configuration->server_name_indication);
        if (len >= sizeof(socket->server_name_indication)) {
            LOG(ERROR, "SNI is too long (maximum allowed size is %u)",
                (unsigned) sizeof(socket->server_name_indication) - 1);
            return avs_errno(AVS_ENOBUFS);
        }
        memcpy(socket->server_name_indication,
               configuration->server_name_indication, len + 1);
    }

    if (configuration->additional_configuration_clb
            && configuration->additional_configuration_clb(socket->ctx)) {
        LOG(ERROR, "Error while setting additional SSL configuration");
        return avs_errno(AVS_EPIPE);
    }
    return AVS_OK;
}

static avs_error_t
send_ssl(avs_net_socket_t *socket_, const void *buffer, size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result;

    LOG(TRACE, "send_ssl(socket=%p, buffer=%p, buffer_length=%lu)",
        (void *) socket, buffer, (unsigned long) buffer_length);

    errno = 0;
    socket->bio_error = AVS_OK;
    result = SSL_write(socket->ssl, buffer, (int) buffer_length);
    if (result < 0 || (size_t) result < buffer_length) {
        LOG(ERROR, "write failed");
        return avs_is_ok(socket->bio_error) ? avs_errno(AVS_EPROTO)
                                            : socket->bio_error;
    } else {
        return AVS_OK;
    }
}

static avs_error_t receive_ssl(avs_net_socket_t *socket_,
                               size_t *out_bytes_received,
                               void *buffer,
                               size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result = 0;
    LOG(TRACE, "receive_ssl(socket=%p, buffer=%p, buffer_length=%lu)",
        (void *) socket, buffer, (unsigned long) buffer_length);

    errno = 0;
    socket->bio_error = AVS_OK;
    result = SSL_read(socket->ssl, buffer, (int) buffer_length);
    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(&result, sizeof(result));
    if (result < 0) {
        *out_bytes_received = 0;
        return avs_is_ok(socket->bio_error) ? avs_errno(AVS_EPROTO)
                                            : socket->bio_error;
    } else {
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(buffer, result);
        *out_bytes_received = (size_t) result;
        socket->bio_error = AVS_OK;
        if (socket_is_datagram(socket) && buffer_length > 0
                && (size_t) result == buffer_length) {
            // Check whether the message is truncated;
            // Normally we could use SSL_pending(), but on some versions of
            // OpenSSL, it is broken and always return 0 for DTLS; see
            // https://github.com/openssl/openssl/issues/5478 for details.
            // We resort to this hack of calling SSL_read() with actual network
            // communication blocked.
            avs_net_socket_t *backend_socket = socket->backend_socket;
            socket->backend_socket = NULL;
            do {
                char truncation_buffer[TRUNCATION_BUFFER_SIZE];
                if ((result = SSL_read(socket->ssl, truncation_buffer,
                                       (int) sizeof(truncation_buffer)))
                                > 0
                        && avs_is_ok(socket->bio_error)) {
                    LOG(WARNING, "receive_ssl: message truncated");
                    socket->bio_error = avs_errno(AVS_EMSGSIZE);
                }
            } while (result > 0);
            socket->backend_socket = backend_socket;
            if (avs_is_err(socket->bio_error)) {
                return socket->bio_error;
            }
        }
    }
    return AVS_OK;
}

static avs_error_t cleanup_ssl(avs_net_socket_t **socket_) {
    ssl_socket_t **socket = (ssl_socket_t **) socket_;
    LOG(TRACE, "cleanup_ssl(*socket=%p)", (void *) *socket);

#ifdef WITH_PSK
    _avs_net_psk_cleanup(&(*socket)->psk);
#endif

    avs_error_t err = close_ssl(*socket_);
    add_err(&err, avs_net_socket_cleanup(&(*socket)->backend_socket));
    if ((*socket)->ctx) {
        SSL_CTX_free((*socket)->ctx);
        (*socket)->ctx = NULL;
    }
    avs_free(*socket);
    *socket = NULL;
    return err;
}

void _avs_net_cleanup_global_ssl_state(void) {
    // do nothing
}

avs_error_t _avs_net_initialize_global_ssl_state(void) {
    LOG(TRACE, "OpenSSL initialization");

    SSL_library_init();
#ifdef AVS_LOG_WITH_TRACE
    SSL_load_error_strings();
#endif
    OpenSSL_add_all_algorithms();
    if (!RAND_load_file("/dev/urandom", -1)) {
        LOG(WARNING, "RAND_load_file error");
        return avs_errno(AVS_ENOTSUP);
    }
    /* On some OpenSSL version, RAND_load file causes hell to break loose.
     * Get rid of any "uninitialized" memory that it created :( */
    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(0, sbrk(0));
    if (avs_bio_init()) {
        LOG(WARNING, "avs_bio_init error");
        return avs_errno(AVS_ENOMEM);
    }
    return AVS_OK;
}

#define OPENSSL_METHOD(Proto) Proto##_method

#if OPENSSL_VERSION_NUMBER_LT(1, 1, 0)
static const SSL_METHOD *stream_method(avs_net_ssl_version_t version) {
    switch (version) {
    case AVS_NET_SSL_VERSION_DEFAULT:
    case AVS_NET_SSL_VERSION_SSLv2_OR_3:
        return OPENSSL_METHOD(SSLv23)();

#    ifndef OPENSSL_NO_SSL2
    case AVS_NET_SSL_VERSION_SSLv2:
        return OPENSSL_METHOD(SSLv2)();
#    endif

#    ifndef OPENSSL_NO_SSL3
    case AVS_NET_SSL_VERSION_SSLv3:
        return OPENSSL_METHOD(SSLv3)();
#    endif

#    ifndef OPENSSL_NO_TLS1
    case AVS_NET_SSL_VERSION_TLSv1:
        return OPENSSL_METHOD(TLSv1)();

#        if OPENSSL_VERSION_NUMBER_GE(1, 0, 1)
    case AVS_NET_SSL_VERSION_TLSv1_1:
        return OPENSSL_METHOD(TLSv1_1)();

    case AVS_NET_SSL_VERSION_TLSv1_2:
        return OPENSSL_METHOD(TLSv1_2)();
#        endif
#    endif /* OPENSSL_NO_TLS1 */

    default:
        return NULL;
    }
}

#    ifndef WITH_DTLS
#        define dgram_method(x) ((void) (x), (const SSL_METHOD *) NULL)
#    else /* WITH_DTLS */

static const SSL_METHOD *dgram_method(avs_net_ssl_version_t version) {
    switch (version) {
    case AVS_NET_SSL_VERSION_DEFAULT:
#        if OPENSSL_VERSION_NUMBER_GE(1, 0, 2)
        return OPENSSL_METHOD(DTLS)();

    case AVS_NET_SSL_VERSION_TLSv1_2:
        return OPENSSL_METHOD(DTLSv1_2)();
#        endif

#        if OPENSSL_VERSION_NUMBER_GE(1, 0, 1)
    case AVS_NET_SSL_VERSION_TLSv1:
    case AVS_NET_SSL_VERSION_TLSv1_1:
        return OPENSSL_METHOD(DTLSv1)();
#        endif

    default:
        return NULL;
    }
}

#    endif /* WITH_DTLS */

static avs_error_t
make_ssl_context(SSL_CTX **out_ctx, bool dtls, avs_net_ssl_version_t version) {
    const SSL_METHOD *method = NULL;
    *out_ctx = NULL;
    if (dtls) {
        method = dgram_method(version);
    } else {
        method = stream_method(version);
    }
    if (!method) {
        LOG(ERROR, "Unsupported SSL version");
        return avs_errno(AVS_ENOTSUP);
    }
    /* older versions of OpenSSL expect non-const pointer here... */
    if (!(*out_ctx = SSL_CTX_new((SSL_METHOD *) (intptr_t) method))) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }
    return AVS_OK;
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

#    ifndef WITH_DTLS
#        define dgram_proto_version(x) ((void) (x), -1)
#    else /* WITH_DTLS */

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

#    endif /* WITH_DTLS */

static avs_error_t
make_ssl_context(SSL_CTX **out_ctx, bool dtls, avs_net_ssl_version_t version) {
    const SSL_METHOD *method = NULL;
    int ossl_proto_version = 0;
    *out_ctx = NULL;
    if (!dtls) {
        method = OPENSSL_METHOD(TLS)();
        ossl_proto_version = stream_proto_version(version);
    }
#    ifdef WITH_DTLS
    else {
        method = OPENSSL_METHOD(DTLS)();
        ossl_proto_version = dgram_proto_version(version);
    }
#    endif
    if (ossl_proto_version < 0) {
        LOG(ERROR, "Unsupported SSL version");
        return avs_errno(AVS_ENOTSUP);
    }
    if (!method) {
        LOG(ERROR, "Could not get OpenSSL method handle");
        return avs_errno(AVS_ENOTSUP);
    }
    if (!(*out_ctx = SSL_CTX_new(method))) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }
    if (ossl_proto_version
            && !SSL_CTX_set_min_proto_version(*out_ctx, ossl_proto_version)) {
        log_openssl_error();
        SSL_CTX_free(*out_ctx);
        *out_ctx = NULL;
        return avs_errno(AVS_ENOTSUP);
    }
    return AVS_OK;
}
#endif

static avs_error_t
initialize_ssl_socket(ssl_socket_t *socket,
                      avs_net_socket_type_t backend_type,
                      const avs_net_ssl_configuration_t *configuration) {
    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;
    socket->backend_type = backend_type;

    avs_error_t err = make_ssl_context(&socket->ctx, socket_is_datagram(socket),
                                       configuration->version);
    if (avs_is_ok(err)
            && avs_is_err((err = configure_ssl(socket, configuration)))) {
        SSL_CTX_free(socket->ctx);
        socket->ctx = NULL;
    }

    return err;
}
