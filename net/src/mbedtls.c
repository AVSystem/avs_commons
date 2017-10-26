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
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#define inline
#endif

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/timing.h>
#ifdef WITH_MBEDTLS_LOGS
#include <mbedtls/debug.h>
#endif // WITH_MBEDTLS_LOGS

#include "net_impl.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    mbedtls_x509_crt *ca_cert;
    mbedtls_x509_crt *client_cert;
    mbedtls_pk_context *pk_key;
} ssl_socket_certs_t;

typedef struct {
    avs_net_owned_psk_t value;
    int *ciphersuites;
} ssl_socket_psk_t;

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    /* At most one of "context_valid" and "stored_session_valid" might be true
     * at a given time; these refer to the fields in the "state" union. */
    struct {
        bool context_valid : 1;
        bool stored_session_valid : 1;
        bool session_restored : 1;
        bool use_session_resumption : 1;
    } flags;
    union {
        // used when the socket is ready for communication
        mbedtls_ssl_context context;
        // may be used to store pre-existing session when the socket is closed
        mbedtls_ssl_session stored_session;
    } state;
    mbedtls_ssl_config config;
    avs_net_security_mode_t security_mode;
    union {
        ssl_socket_certs_t cert;
        ssl_socket_psk_t psk;
    } security;
    mbedtls_timing_delay_context timer;
    avs_net_socket_type_t backend_type;
    avs_net_abstract_socket_t *backend_socket;
    int error_code;
    avs_net_socket_configuration_t backend_configuration;
} ssl_socket_t;

static bool is_ssl_started(ssl_socket_t *socket) {
    return socket->flags.context_valid;
}

static bool is_session_resumed(ssl_socket_t *socket) {
    return socket->flags.session_restored;
}

static mbedtls_ssl_context *get_context(ssl_socket_t *socket) {
    assert(socket->flags.context_valid);
    return &socket->state.context;
}

static mbedtls_ssl_session *get_stored_session(ssl_socket_t *socket) {
    assert(socket->flags.stored_session_valid);
    return &socket->state.stored_session;
}

#ifdef WITH_MBEDTLS_LOGS
static void debug_mbedtls(void *ctx, int level, const char *file, int line, const char *str) {
    (void) ctx;
    (void) level;
    const size_t len = strlen(str);
    const char *msg = str;
    char msgbuf[len+1];
    if (len > 0 && str[len-1] == '\n') {
        memset(msgbuf, 0, len);
        memcpy(msgbuf, str, len-1);
        msg = msgbuf;
    }
    avs_log_internal_l__(AVS_LOG_TRACE, "mbedtls", file, (unsigned) line, "%s", msg);
}
#endif // WITH_MBEDTLS_LOGS

#define NET_SSL_COMMON_INTERNALS
#include "ssl_common.h"

static struct {
    // this weighs almost 40KB because of HAVEGE state
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
} AVS_SSL_GLOBAL;

static void cleanup_ssl_global(void) {
    mbedtls_ctr_drbg_free(&AVS_SSL_GLOBAL.rng);
    mbedtls_entropy_free(&AVS_SSL_GLOBAL.entropy);
}

static int initialize_ssl_global(void) {
    mbedtls_entropy_init(&AVS_SSL_GLOBAL.entropy);
    mbedtls_ctr_drbg_init(&AVS_SSL_GLOBAL.rng);
    int result = mbedtls_ctr_drbg_seed(&AVS_SSL_GLOBAL.rng,
                                       mbedtls_entropy_func,
                                       &AVS_SSL_GLOBAL.entropy, NULL, 0);
    if (result) {
        LOG(ERROR, "mbedtls_ctr_drbg_seed() failed: %d", result);
        cleanup_ssl_global();
    }
    return result;
}

static int avs_bio_recv(void *ctx, unsigned char *buf, size_t len,
                        uint32_t timeout_ms) {
    ssl_socket_t *socket = (ssl_socket_t *) ctx;
    avs_net_socket_opt_value_t orig_timeout;
    avs_net_socket_opt_value_t new_timeout;
    size_t read_bytes;
    int result;
    socket->error_code = 0;
    if (avs_net_socket_get_opt(socket->backend_socket,
                               AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                               &orig_timeout)) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    new_timeout = orig_timeout;
    if (timeout_ms) {
        new_timeout.recv_timeout =
                avs_time_duration_from_scalar(timeout_ms, AVS_TIME_MS);
    }
    avs_net_socket_set_opt(socket->backend_socket,
                           AVS_NET_SOCKET_OPT_RECV_TIMEOUT, new_timeout);
    if (avs_net_socket_receive(socket->backend_socket, &read_bytes, buf, len)) {
        socket->error_code = avs_net_socket_errno(socket->backend_socket);
        if (socket->error_code == ETIMEDOUT) {
            result = MBEDTLS_ERR_SSL_TIMEOUT;
        } else {
            result = MBEDTLS_ERR_NET_RECV_FAILED;
        }
    } else {
        result = (int) read_bytes;
    }
    avs_net_socket_set_opt(socket->backend_socket,
                           AVS_NET_SOCKET_OPT_RECV_TIMEOUT, orig_timeout);
    return result;
}

static int avs_bio_send(void *ctx, const unsigned char *buf, size_t len) {
    ssl_socket_t *socket = (ssl_socket_t *) ctx;
    socket->error_code = 0;
    if (avs_net_socket_send(socket->backend_socket, buf, len)) {
        socket->error_code = avs_net_socket_errno(socket->backend_socket);
        return MBEDTLS_ERR_NET_SEND_FAILED;
    } else {
        return (int) len;
    }
}

static int get_dtls_overhead(ssl_socket_t *socket,
                             int *out_header,
                             int *out_padding_size) {
    if (!is_ssl_started(socket)) {
        return -1;
    }

    const mbedtls_ssl_ciphersuite_t *ciphersuite =
            mbedtls_ssl_ciphersuite_from_string(
                    mbedtls_ssl_get_ciphersuite(get_context(socket)));

    int result = mbedtls_ssl_get_record_expansion(get_context(socket));
    if (result == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE
            || result == MBEDTLS_ERR_SSL_INTERNAL_ERROR) {
        /* This is either a result of compression mode or some internal error,
         * and in both cases we can't predict the size. */
        return -1;
    }

    const mbedtls_cipher_info_t *cipher =
            mbedtls_cipher_info_from_type(ciphersuite->cipher);

    *out_padding_size = 0;
    if (cipher->mode == MBEDTLS_MODE_CBC) {
        *out_padding_size = (int) cipher->block_size;
        /* Looking at the mbedtls_ssl_get_record_expansion it adds size
         * of the block to the record size, and we don't want that */
        result -= (int) cipher->block_size;
    }

    *out_header = result;
    return 0;
}

static void close_ssl_raw(ssl_socket_t *socket) {
    if (socket->backend_socket) {
        avs_net_socket_close(socket->backend_socket);
    }

    if (socket->flags.context_valid) {
        assert(!socket->flags.stored_session_valid);
        mbedtls_ssl_session tmp_session;
        if (socket->flags.use_session_resumption
                && socket->config.endpoint == MBEDTLS_SSL_IS_CLIENT) {
            mbedtls_ssl_session_init(&tmp_session);
            if (mbedtls_ssl_get_session(get_context(socket), &tmp_session)) {
                mbedtls_ssl_session_free(&tmp_session);
            } else {
                socket->flags.stored_session_valid = true;
            }
        }

        mbedtls_ssl_free(get_context(socket));
        socket->flags.context_valid = false;

        if (socket->flags.stored_session_valid) {
            socket->state.stored_session = tmp_session;
        }
    }
}

static int set_min_ssl_version(mbedtls_ssl_config *config,
                               avs_net_ssl_version_t version) {
    switch (version) {
    case AVS_NET_SSL_VERSION_DEFAULT:
    case AVS_NET_SSL_VERSION_SSLv2_OR_3:
    case AVS_NET_SSL_VERSION_SSLv3:
        mbedtls_ssl_conf_min_version(config,
                                     MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_0);
        return 0;
    case AVS_NET_SSL_VERSION_TLSv1:
        mbedtls_ssl_conf_min_version(config,
                                     MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_1);
        return 0;
    case AVS_NET_SSL_VERSION_TLSv1_1:
        mbedtls_ssl_conf_min_version(config,
                                     MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_2);
        return 0;
    case AVS_NET_SSL_VERSION_TLSv1_2:
        mbedtls_ssl_conf_min_version(config,
                                     MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_3);
        return 0;
    default:
        LOG(ERROR, "Unsupported SSL version");
        return -1;
    }
}

static uint8_t is_verification_enabled(ssl_socket_t *socket) {
    return socket->security_mode == AVS_NET_SECURITY_CERTIFICATE
            && socket->security.cert.ca_cert != NULL;
}

static void initialize_cert_security(ssl_socket_t *socket) {
    if (socket->security.cert.ca_cert) {
        mbedtls_ssl_conf_authmode(&socket->config, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&socket->config,
                                  socket->security.cert.ca_cert, NULL);
    } else {
        mbedtls_ssl_conf_authmode(&socket->config, MBEDTLS_SSL_VERIFY_NONE);
    }

    if (socket->security.cert.client_cert && socket->security.cert.pk_key) {
        mbedtls_ssl_conf_own_cert(&socket->config,
                                  socket->security.cert.client_cert,
                                  socket->security.cert.pk_key);
    }
}

typedef void foreach_psk_ciphersuite_cb_t(int suite, void *arg);

static void foreach_psk_ciphersuite(const int *suites,
                                    foreach_psk_ciphersuite_cb_t callback,
                                    void *arg) {
    for (; suites && *suites; ++suites) {
        const mbedtls_ssl_ciphersuite_t *info =
                mbedtls_ssl_ciphersuite_from_id(*suites);
        if (mbedtls_ssl_ciphersuite_uses_psk(info)) {
            callback(*suites, arg);
        }
    }
}

static void enumerate_psk_ciphersuites(int suite, void *count) {
    (void) suite;
    ++*((size_t *) count);
}

static void fill_psk_ciphersuites(int suite, void *out_it) {
    *(*(int **) out_it)++ = suite;
}

static int *init_psk_ciphersuites(const mbedtls_ssl_config *config) {
    size_t ciphersuite_count = 0;
    const int *all_suites;
    int *psk_suites;
    int *psk_suite_it;

    all_suites = config->ciphersuite_list[0];
    foreach_psk_ciphersuite(all_suites, enumerate_psk_ciphersuites,
                            &ciphersuite_count);
    if (!(psk_suites = (int *) calloc(ciphersuite_count + 1, sizeof(int)))) {
        LOG(ERROR, "out of memory");
        return NULL;
    }
    psk_suite_it = psk_suites;
    foreach_psk_ciphersuite(all_suites, fill_psk_ciphersuites, &psk_suite_it);

    return psk_suites;
}

static int initialize_psk_security(ssl_socket_t *socket) {
    if (!(socket->security.psk.ciphersuites =
            init_psk_ciphersuites(&socket->config))) {
        socket->error_code = ENOMEM;
        return -1;
    }

    /* mbedtls_ssl_conf_psk() makes copies of the buffers */
    /* We set the values directly instead, to avoid that. */
    socket->config.psk = (unsigned char *) socket->security.psk.value.psk;
    socket->config.psk_len = socket->security.psk.value.psk_size;
    socket->config.psk_identity =
            (unsigned char *) socket->security.psk.value.identity;
    socket->config.psk_identity_len = socket->security.psk.value.identity_size;

    mbedtls_ssl_conf_ciphersuites(&socket->config,
                                  socket->security.psk.ciphersuites);
    return 0;
}

static int transport_for_socket_type(avs_net_socket_type_t backend_type) {
    switch (backend_type) {
    case AVS_NET_TCP_SOCKET:
    case AVS_NET_SSL_SOCKET:
        return MBEDTLS_SSL_TRANSPORT_STREAM;
    case AVS_NET_UDP_SOCKET:
    case AVS_NET_DTLS_SOCKET:
        return MBEDTLS_SSL_TRANSPORT_DATAGRAM;
    default:
        assert(0 && "invalid enum value");
        return -1;
    }
}

static int configure_ssl(ssl_socket_t *socket,
                         const avs_net_ssl_configuration_t *configuration) {
    mbedtls_ssl_config_init(&socket->config);
    /* HACK: The config is always initialized with MBEDTLS_SSL_IS_SERVER even
     * though it may be later reused in a client context. This is because the
     * default server-side config initializes pretty much everything that the
     * default client-side config does (aside from endpoint, authmode and
     * session_tickets, which are just flags that are trivial to set manually),
     * and more. So it's safer to initialize it with server-side defaults and
     * then repurpose as a client-side config rather than vice versa. Details:
     * https://github.com/ARMmbed/mbedtls/blob/mbedtls-2.6.1/library/ssl_tls.c#L7465 */
    if (mbedtls_ssl_config_defaults(
            &socket->config, MBEDTLS_SSL_IS_SERVER,
            transport_for_socket_type(socket->backend_type),
            MBEDTLS_SSL_PRESET_DEFAULT)) {
        LOG(ERROR, "mbedtls_ssl_config_defaults() failed");
        return -1;
    }

#ifdef WITH_MBEDTLS_LOGS
    // most verbose logs available
    mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_dbg(&socket->config, debug_mbedtls, NULL);
#endif // WITH_MBEDTLS_LOGS

    if (set_min_ssl_version(&socket->config, configuration->version)) {
        LOG(ERROR, "Could not set minimum SSL version");
        return -1;
    }

    mbedtls_ssl_conf_rng(&socket->config,
                         mbedtls_ctr_drbg_random, &AVS_SSL_GLOBAL.rng);

    switch (socket->security_mode) {
    case AVS_NET_SECURITY_PSK:
        if (initialize_psk_security(socket)) {
            return -1;
        }
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        initialize_cert_security(socket);
        break;
    default:
        assert(0 && "invalid enum value");
        return -1;
    }

    const avs_net_dtls_handshake_timeouts_t *dtls_handshake_timeouts =
            configuration->dtls_handshake_timeouts
                    ? configuration->dtls_handshake_timeouts
                    : &DEFAULT_DTLS_HANDSHAKE_TIMEOUTS;
    int64_t min_ms, max_ms;
    if (avs_time_duration_to_scalar(&min_ms, AVS_TIME_MS,
                                    dtls_handshake_timeouts->min)
            || avs_time_duration_to_scalar(&max_ms, AVS_TIME_MS,
                                           dtls_handshake_timeouts->max)
            || min_ms < 0 || min_ms > UINT32_MAX
            || max_ms < 0 || max_ms > UINT32_MAX) {
        LOG(ERROR, "Invalid DTLS handshake timeouts");
        return -1;
    }
    mbedtls_ssl_conf_handshake_timeout(&socket->config,
                                       (uint32_t) min_ms, (uint32_t) max_ms);

    if (configuration->additional_configuration_clb
            && configuration->additional_configuration_clb(&socket->config)) {
        LOG(ERROR, "Error while setting additional SSL configuration");
        return -1;
    }

    return 0;
}

static int update_ssl_endpoint_config(ssl_socket_t *socket) {
    avs_net_socket_opt_value_t state_opt;
    if (avs_net_socket_get_opt((avs_net_abstract_socket_t *) socket,
                               AVS_NET_SOCKET_OPT_STATE, &state_opt)) {
        LOG(ERROR, "initialize_ssl_config: could not get socket state");
        return -1;
    }
    if (state_opt.state == AVS_NET_SOCKET_STATE_CONNECTED) {
        mbedtls_ssl_conf_endpoint(&socket->config, MBEDTLS_SSL_IS_CLIENT);
#ifdef MBEDTLS_SSL_SESSION_TICKETS
        mbedtls_ssl_conf_session_tickets(&socket->config,
                                         MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
#endif // MBEDTLS_SSL_SESSION_TICKETS
    } else if (state_opt.state == AVS_NET_SOCKET_STATE_ACCEPTED) {
        mbedtls_ssl_conf_endpoint(&socket->config, MBEDTLS_SSL_IS_SERVER);
#ifdef MBEDTLS_SSL_SESSION_TICKETS
        mbedtls_ssl_conf_session_tickets(&socket->config,
                                         MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif // MBEDTLS_SSL_SESSION_TICKETS
    } else {
        socket->error_code = EINVAL;
        LOG(ERROR, "initialize_ssl_config: invalid socket state");
        return -1;
    }

    return 0;
}

static bool sessions_equal(const mbedtls_ssl_session *left,
                           const mbedtls_ssl_session *right) {
    if (!left && !right) {
        return true;
    }
    return left && right
            && left->ciphersuite == right->ciphersuite
            && left->compression == right->compression
#ifdef MBEDTLS_HAVE_TIME
            && left->start == right->start
#endif // MBEDTLS_HAVE_TIME
            && left->id_len == right->id_len
            && memcmp(left->id, right->id, left->id_len) == 0;
}

static int start_ssl(ssl_socket_t *socket, const char *host) {
    int result;
    if (update_ssl_endpoint_config(socket)) {
        LOG(ERROR, "could not initialize ssl context");
        return -1;
    }

    assert(!socket->flags.context_valid);

    mbedtls_ssl_session tmp_session;
    bool restore_session = socket->flags.stored_session_valid;
    if (restore_session) {
        tmp_session = *get_stored_session(socket);
        socket->flags.stored_session_valid = false;
    }

    mbedtls_ssl_init(&socket->state.context);
    socket->flags.context_valid = true;

    mbedtls_ssl_set_bio(get_context(socket), socket,
                        avs_bio_send, NULL, avs_bio_recv);
    mbedtls_ssl_set_timer_cb(get_context(socket), &socket->timer,
                             mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);
    if ((result = mbedtls_ssl_setup(get_context(socket), &socket->config))) {
        LOG(ERROR, "mbedtls_ssl_setup() failed: %d", result);
        socket->error_code = ENOMEM;
        goto finish;
    }

    if ((result = mbedtls_ssl_set_hostname(get_context(socket), host))) {
        LOG(ERROR, "mbedtls_ssl_set_hostname() failed: %d", result);
        socket->error_code =
                (result == MBEDTLS_ERR_SSL_ALLOC_FAILED ? ENOMEM : EINVAL);
        goto finish;
    }

    if (restore_session
            && socket->config.endpoint == MBEDTLS_SSL_IS_CLIENT
            && (result = mbedtls_ssl_set_session(get_context(socket),
                                                 &tmp_session))) {
        LOG(WARNING,
            "mbedtls_ssl_set_session() failed: %d; performing full handshake",
            result);
    }

    do {
        result = mbedtls_ssl_handshake(get_context(socket));
    } while (result == MBEDTLS_ERR_SSL_WANT_READ
                || result == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (result == 0) {
        if ((socket->flags.session_restored =
                (restore_session && sessions_equal(get_context(socket)->session,
                                                   &tmp_session)))) {
            LOG(TRACE, "handshake success: session restored");
        } else {
            LOG(TRACE, "handshake success: new session started");
        }
    } else {
        LOG(ERROR, "handshake failed: %d", result);
    }

    if (!result
            && !socket->flags.session_restored
            && is_verification_enabled(socket)) {
        uint32_t verify_result =
                mbedtls_ssl_get_verify_result(get_context(socket));
        if (verify_result) {
            LOG(ERROR, "server certificate verification failure: %" PRIu32,
                verify_result);
            result = -1;
        }
    }
finish:
    if (restore_session) {
        mbedtls_ssl_session_free(&tmp_session);
    }
    if (result) {
        if (!socket->error_code) {
            socket->error_code = EPROTO;
        }
        return -1;
    } else {
        socket->error_code = 0;
        return 0;
    }
}

static void update_send_or_recv_error_code(ssl_socket_t *socket,
                                           int mbedtls_result) {
    if (!socket->error_code
            && (mbedtls_result == MBEDTLS_ERR_NET_RECV_FAILED
                    || mbedtls_result == MBEDTLS_ERR_NET_SEND_FAILED)) {
        socket->error_code = avs_net_socket_errno(socket->backend_socket);
    }
    if (!socket->error_code) {
        socket->error_code = errno;
    }
    if (!socket->error_code) {
        socket->error_code = EPROTO;
    }
}

static int send_ssl(avs_net_abstract_socket_t *socket_,
                    const void *buffer,
                    size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    size_t bytes_sent = 0;
    int result;
    LOG(TRACE, "send_ssl(socket=%p, buffer=%p, buffer_length=%lu)",
        (void *) socket, buffer, (unsigned long) buffer_length);

    while (bytes_sent < buffer_length) {
        do {
            errno = 0;
            result = mbedtls_ssl_write(
                    get_context(socket),
                    ((const unsigned char *) buffer) + bytes_sent,
                    (size_t) (buffer_length - bytes_sent));
        } while (result == MBEDTLS_ERR_SSL_WANT_WRITE
                    || result == MBEDTLS_ERR_SSL_WANT_READ);

        if (result <= 0) {
            LOG(DEBUG, "ssl_write result %d", result);
            break;
        } else {
            bytes_sent += (size_t) result;
        }
    }

    if (bytes_sent < buffer_length) {
        LOG(ERROR, "send failed (%zu/%zu): %d",
            bytes_sent, buffer_length, result);
        update_send_or_recv_error_code(socket, result);
        return -1;
    }
    socket->error_code = 0;
    return 0;
}

static int receive_ssl(avs_net_abstract_socket_t *socket_,
                       size_t *out_bytes_received,
                       void *buffer,
                       size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result = -1;

    LOG(TRACE, "receive_ssl(socket=%p, buffer=%p, buffer_length=%lu)",
        (void *) socket, buffer, (unsigned long) buffer_length);

    do {
        errno = 0;
        result = mbedtls_ssl_read(get_context(socket),
                                  (unsigned char *) buffer, buffer_length);
    } while (result == MBEDTLS_ERR_SSL_WANT_READ
                || result == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (result < 0) {
        *out_bytes_received = 0;
        if (result != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            LOG(ERROR, "receive failed: %d", result);
            update_send_or_recv_error_code(socket, result);
            return -1;
        }
    } else {
        *out_bytes_received = (size_t) result;
    }
    socket->error_code = 0;
    return 0;
}

static void cleanup_security_cert(ssl_socket_certs_t *certs) {
    if (certs->ca_cert) {
        mbedtls_x509_crt_free(certs->ca_cert);
        free(certs->ca_cert);
    }
    if (certs->client_cert) {
        mbedtls_x509_crt_free(certs->client_cert);
        free(certs->client_cert);
    }
    if (certs->pk_key) {
        mbedtls_pk_free(certs->pk_key);
        free(certs->pk_key);
    }
}

static void cleanup_security_psk(ssl_socket_psk_t *psk) {
    free(psk->ciphersuites);
    psk->ciphersuites = NULL;
    _avs_net_psk_cleanup(&psk->value);
}

static int cleanup_ssl(avs_net_abstract_socket_t **socket_) {
    ssl_socket_t **socket = (ssl_socket_t **) socket_;
    LOG(TRACE, "cleanup_ssl(*socket=%p)", (void *) *socket);

    close_ssl(*socket_);
    avs_net_socket_cleanup(&(*socket)->backend_socket);

    if ((*socket)->flags.stored_session_valid) {
        mbedtls_ssl_session_free(get_stored_session(*socket));
    }

    switch ((*socket)->security_mode) {
    case AVS_NET_SECURITY_PSK:
        cleanup_security_psk(&(*socket)->security.psk);
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        cleanup_security_cert(&(*socket)->security.cert);
        break;
    }

    /* Detach the uncopied PSK values */
    (*socket)->config.psk = NULL;
    (*socket)->config.psk_len = 0;
    (*socket)->config.psk_identity = NULL;
    (*socket)->config.psk_identity_len = 0;
    mbedtls_ssl_config_free(&(*socket)->config);

    free(*socket);
    *socket = NULL;
    return 0;
}

#define CREATE_OR_FAIL(type, ptr) \
do { \
    free(*ptr); \
    *ptr = (type *) calloc(1, sizeof(**ptr)); \
    if (!*ptr) {\
        LOG(ERROR, "memory allocation error"); \
        return -1; \
    } \
} while (0)

static int
load_ca_certs_from_paths(mbedtls_x509_crt **out,
                         const avs_net_certificate_info_t *cert_info) {
    const char *ca_cert_path = cert_info->trusted_certs.impl.data.paths.cert_path;
    const char *ca_cert_file = cert_info->trusted_certs.impl.data.paths.cert_file;
    if (!ca_cert_path && !ca_cert_file) {
        LOG(ERROR, "CA cert path and CA cert file not provided");
        return -1;
    }
    if (cert_info->trusted_certs.impl.format != AVS_NET_DATA_FORMAT_DER
        && cert_info->trusted_certs.impl.format != AVS_NET_DATA_FORMAT_PEM) {
        LOG(ERROR, "unsupported CA certs format");
        return -1;
    }
    CREATE_OR_FAIL(mbedtls_x509_crt, out);
    mbedtls_x509_crt_init(*out);
    int result;

    if (ca_cert_path
           && (result = mbedtls_x509_crt_parse_path(*out, ca_cert_path))) {
        LOG(ERROR, "failed to parse %d certs in path <%s>", result,
            ca_cert_path);
        return result;
    }
    if (ca_cert_file
           && (result = mbedtls_x509_crt_parse_file(*out, ca_cert_file))) {
        LOG(ERROR, "failed to parse %d certs in file <%s>", result,
            ca_cert_file);
        return result;
    }
    return 0;
}

static int load_ca_certs_from_memory(mbedtls_x509_crt **out,
                                     const avs_net_trusted_cert_source_t *cert_info) {
    const avs_net_ssl_raw_data_t *ca_cert = &cert_info->impl.data.cert;
    if (cert_info->impl.format != AVS_NET_DATA_FORMAT_DER) {
        LOG(ERROR, "invalid CA certs format");
        return -1;
    }
    if (!ca_cert->data || !ca_cert->size) {
        LOG(ERROR, "invalid DER CA certificate provided");
        return -1;
    }
    CREATE_OR_FAIL(mbedtls_x509_crt, out);
    mbedtls_x509_crt_init(*out);
    int result = mbedtls_x509_crt_parse_der(
            *out, (const unsigned char *) ca_cert->data, ca_cert->size);
    if (result) {
        LOG(ERROR, "failed to parse DER certificate: %d", result);
    }
    return result;
}

static int load_client_key_from_ec(ssl_socket_certs_t *certs,
                                   const avs_net_ssl_raw_ec_t *key) {
    if (!key->private_key || !key->private_key_size) {
        LOG(ERROR, "EC private key not provided");
        return -1;
    }
    if (!key->curve_name) {
        LOG(ERROR, "EC curve name not provided");
        return -1;
    }
    mbedtls_ecp_keypair *private_ec, *cert_ec;
    const mbedtls_ecp_curve_info *curve_info;

    if (!certs->client_cert
            || mbedtls_pk_get_type(&certs->client_cert->pk)
                    != MBEDTLS_PK_ECKEY) {
        LOG(ERROR, "invalid client certificate");
        return -1;
    }
    cert_ec = mbedtls_pk_ec(certs->client_cert->pk);

    if (mbedtls_pk_setup(certs->pk_key,
                         mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) {
        LOG(ERROR, "could not create pk_key");
        return -1;
    }
    private_ec = mbedtls_pk_ec(*certs->pk_key);

    if (!(curve_info = mbedtls_ecp_curve_info_from_name(key->curve_name))
            || mbedtls_ecp_group_load(&private_ec->grp, curve_info->grp_id)
            || mbedtls_mpi_read_binary(&private_ec->d,
                                       (const unsigned char *) key->private_key,
                                       key->private_key_size)
            || mbedtls_ecp_copy(&private_ec->Q, &cert_ec->Q)) {
        LOG(ERROR, "error while initializing private key; curve name: %s",
            key->curve_name);
        return -1;
    }

    return 0;
}

static int load_client_key_from_pkcs8(ssl_socket_certs_t *certs,
                                      const void *data,
                                      size_t size,
                                      const char *password) {
    size_t password_len = password ? strlen(password) : 0;
    return mbedtls_pk_parse_key(certs->pk_key,
                                (const unsigned char *) data, size,
                                (const unsigned char *) password, password_len);
}

static int load_client_key_from_data(ssl_socket_certs_t *certs,
                                     const avs_net_private_key_t *key) {
    switch (key->impl.format) {
    case AVS_NET_DATA_FORMAT_EC:
        return load_client_key_from_ec(certs, &key->impl.data.ec);
    case AVS_NET_DATA_FORMAT_PKCS8:
        return load_client_key_from_pkcs8(certs, key->impl.data.pkcs8.data,
                                          key->impl.data.pkcs8.size,
                                          key->impl.data.pkcs8.password);
    default:
        LOG(ERROR, "unsupported in memory private key format");
        return -1;
    }
}

static int load_client_key_from_file(ssl_socket_certs_t *certs,
                                     const avs_net_private_key_t *key) {
    if (!key->impl.data.file.path) {
        LOG(ERROR, "private key not specified");
        return -1;
    }

    switch (key->impl.format) {
    case AVS_NET_DATA_FORMAT_PEM:
    case AVS_NET_DATA_FORMAT_DER:
        return mbedtls_pk_parse_keyfile(certs->pk_key, key->impl.data.file.path,
                                        key->impl.data.file.password);
    default:
        LOG(ERROR, "unsupported client key file format");
        return -1;
    }
}

static int load_client_private_key(ssl_socket_certs_t *certs,
                                   const avs_net_private_key_t *key) {
    CREATE_OR_FAIL(mbedtls_pk_context, &certs->pk_key);
    mbedtls_pk_init(certs->pk_key);

    switch (key->impl.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        return load_client_key_from_file(certs, key);
    case AVS_NET_DATA_SOURCE_BUFFER:
        return load_client_key_from_data(certs, key);
    default:
        assert(0 && "invalid enum value");
        return -1;
    }
}

static int load_client_cert_from_file(ssl_socket_certs_t *certs,
                                      const avs_net_client_cert_t *cert) {
    switch (cert->impl.format) {
    case AVS_NET_DATA_FORMAT_PEM:
    case AVS_NET_DATA_FORMAT_DER:
        return mbedtls_x509_crt_parse_file(certs->client_cert,
                                           cert->impl.data.file.path);
    default:
        LOG(ERROR, "unsupported client cert file format");
        return -1;
    }
}

static int load_client_cert_from_data(ssl_socket_certs_t *certs,
                                      const avs_net_client_cert_t *cert) {
    switch (cert->impl.format) {
    case AVS_NET_DATA_FORMAT_DER:
        return mbedtls_x509_crt_parse_der(
                certs->client_cert,
                (const unsigned char *) cert->impl.data.cert.data,
                cert->impl.data.cert.size);
    default:
        LOG(ERROR, "unsupported client cert data format");
        return -1;
    }
}

static int load_client_cert(ssl_socket_certs_t *certs,
                            const avs_net_client_cert_t *cert,
                            const avs_net_private_key_t *key) {
    int failed = 0;

    if (is_client_cert_empty(cert)) {
        LOG(TRACE, "client certificate not specified");
        return 0;
    }

    CREATE_OR_FAIL(mbedtls_x509_crt, &certs->client_cert);
    mbedtls_x509_crt_init(certs->client_cert);

    switch (cert->impl.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        failed = load_client_cert_from_file(certs, cert);
        if (failed) {
            LOG(WARNING, "failed to parse %d certs in file <%s>",
                failed, cert->impl.data.file.path);
        }
        break;
    case AVS_NET_DATA_SOURCE_BUFFER:
        failed = load_client_cert_from_data(certs, cert);
        if (failed) {
            LOG(WARNING, "failed to parse DER certificate: %d", failed);
        }
        break;
    default:
        assert(0 && "invalid enum value");
        return -1;
    }

    if (failed) {
        return failed;
    }

    if (load_client_private_key(certs, key)) {
        LOG(ERROR, "Error loading client private key");
        return -1;
    }

    return 0;
}

static int configure_ssl_certs(ssl_socket_certs_t *certs,
                               const avs_net_certificate_info_t *cert_info) {
    LOG(TRACE, "configure_ssl_certs");

    if (cert_info->server_cert_validation) {
        switch (cert_info->trusted_certs.impl.source) {
        case AVS_NET_DATA_SOURCE_PATHS:
            if (load_ca_certs_from_paths(&certs->ca_cert, cert_info)) {
                return -1;
            }
            break;
        case AVS_NET_DATA_SOURCE_BUFFER:
            if (load_ca_certs_from_memory(&certs->ca_cert,
                                          &cert_info->trusted_certs)) {
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

    if (load_client_cert(certs,
                         &cert_info->client_cert,
                         &cert_info->client_key)) {
        LOG(ERROR, "error loading client certificate");
        return -1;
    }

    return 0;
}

static int configure_ssl_psk(ssl_socket_t *socket,
                             const avs_net_psk_t *psk) {
    LOG(TRACE, "configure_ssl_psk");
    return _avs_net_psk_copy(&socket->security.psk.value, psk);
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 avs_net_socket_type_t backend_type,
                                 const avs_net_ssl_configuration_t *configuration) {
    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;

    socket->backend_type = backend_type;
    socket->backend_configuration = configuration->backend_configuration;
    socket->flags.use_session_resumption =
            configuration->use_session_resumption;

    socket->security_mode = configuration->security.mode;
    switch (configuration->security.mode) {
    case AVS_NET_SECURITY_PSK:
        if (configure_ssl_psk(socket, &configuration->security.data.psk)) {
            return -1;
        }
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        if (configure_ssl_certs(&socket->security.cert,
                                &configuration->security.data.cert)) {
            return -1;
        }
        break;
    default:
        assert(0 && "invalid enum value");
        return -1;
    }

    if (configure_ssl(socket, configuration)) {
        return -1;
    }

    return 0;
}
