/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_NET) && defined(AVS_COMMONS_WITH_MBEDTLS)

// this uses some symbols such as "printf" - include it before poisoning them
#    include <mbedtls/platform.h>

#    include <avs_commons_poison.h>

#    include <assert.h>
#    include <errno.h>
#    include <inttypes.h>
#    include <string.h>

#    if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#        define inline
#    endif

#    include <mbedtls/ctr_drbg.h>
#    include <mbedtls/entropy.h>
#    include <mbedtls/platform.h>
#    include <mbedtls/version.h>
#    if MBEDTLS_VERSION_NUMBER >= 0x02040000 // mbed TLS 2.4 deprecated net.h
#        include <mbedtls/net_sockets.h>
#    else // support mbed TLS <=2.3
#        include <mbedtls/net.h>
#    endif
#    include <mbedtls/ssl.h>
#    include <mbedtls/timing.h>

#    ifdef AVS_COMMONS_NET_WITH_MBEDTLS_LOGS
#        ifndef AVS_COMMONS_WITH_INTERNAL_LOGS
#            error "AVS_COMMONS_NET_WITH_MBEDTLS_LOGS requires AVS_COMMONS_WITH_INTERNAL_LOGS to be enabled"
#        endif // AVS_COMMONS_WITH_INTERNAL_LOGS

#        include <mbedtls/debug.h>
#    endif // AVS_COMMONS_NET_WITH_MBEDTLS_LOGS

#    include <avsystem/commons/avs_errno_map.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_prng.h>
#    include <avsystem/commons/avs_utils.h>

#    include "../avs_net_global.h"
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#        include "crypto/mbedtls/avs_mbedtls_data_loader.h"
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#    include "avs_mbedtls_persistence.h"

#    if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) && defined(MBEDTLS_SHA256_C) \
            && defined(MBEDTLS_SHA512_C)
#        include <mbedtls/sha256.h>
#        include <mbedtls/sha512.h>
#        define WITH_DANE_SUPPORT
#        define dane_tlsa_array_field security.cert.dane_tlsa
#    endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
           // defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_SHA512_C)

#    include "../avs_net_impl.h"

VISIBILITY_SOURCE_BEGIN

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#        ifdef WITH_DANE_SUPPORT
typedef struct {
    int last_known_index;

    // bitmask indexed by avs_net_socket_dane_certificate_usage_t
    // i.e., (match_mask & (1 << 0)) - PKIX-TA matched
    //       (match_mask & (1 << 1)) - PKIX-EE matched
    //       (match_mask & (1 << 2)) - DANE-TA matched
    //       (match_mask & (1 << 3)) - DANE-EE matched
    uint8_t match_mask;

    uint32_t verify_result_flags;

    int verify_result;
} dane_verify_state_t;

#            define DANE_TA_OR_EE_MATCH_MASK                       \
                ((1 << AVS_NET_SOCKET_DANE_TRUST_ANCHOR_ASSERTION) \
                 | (1 << AVS_NET_SOCKET_DANE_DOMAIN_ISSUED_CERTIFICATE))

#            define DANE_FULL_MATCH_MASK                    \
                (DANE_TA_OR_EE_MATCH_MASK                   \
                 | (1 << AVS_NET_SOCKET_DANE_CA_CONSTRAINT) \
                 | (1 << AVS_NET_SOCKET_DANE_SERVICE_CERTIFICATE_CONSTRAINT))
#        endif // WITH_DANE_SUPPORT

typedef struct {
    mbedtls_x509_crt *ca_cert;
    mbedtls_x509_crl *ca_crl;
    mbedtls_x509_crt *client_cert;
    mbedtls_pk_context *client_key;
#        ifdef WITH_DANE_SUPPORT
    // dane_ta_certs the original last element of ca_cert chain;
    // if NULL, it means that DANE is disabled
    mbedtls_x509_crt *dane_ta_certs;
    avs_net_socket_dane_tlsa_array_t dane_tlsa;
    dane_verify_state_t dane_verify_state;
#        endif // WITH_DANE_SUPPORT
} ssl_socket_certs_t;
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI

typedef struct {
    const avs_net_socket_v_table_t *const operations;
    struct {
        bool context_valid : 1;
        bool session_restored : 1;
    } flags;
    mbedtls_ssl_context context;
    mbedtls_ssl_config config;
#    ifdef AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
    void *session_resumption_buffer;
    size_t session_resumption_buffer_size;
#    endif // AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
    avs_net_security_mode_t security_mode;
    union {
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
        ssl_socket_certs_t cert;
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#    ifdef AVS_COMMONS_NET_WITH_PSK
        avs_net_owned_psk_t psk;
#    endif // AVS_COMMONS_NET_WITH_PSK
    } security;
    mbedtls_timing_delay_context timer;
    avs_net_socket_type_t backend_type;
    avs_net_socket_t *backend_socket;
    avs_error_t bio_error;
    avs_net_socket_configuration_t backend_configuration;
    /// Subset of @ref avs_net_ssl_configuration_t#tls_ciphersuites appropriate
    /// for security mode, 0-terminated array
    int *effective_ciphersuites;
    /// Non empty, when custom server hostname shall be used.
    char server_name_indication[256];
    bool use_connection_id;
} ssl_socket_t;

static bool is_ssl_started(ssl_socket_t *socket) {
    return socket->flags.context_valid;
}

static bool is_session_resumed(ssl_socket_t *socket) {
    return socket->flags.session_restored;
}

static mbedtls_ssl_context *get_context(ssl_socket_t *socket) {
    assert(socket->flags.context_valid);
    return &socket->context;
}

#    ifdef AVS_COMMONS_NET_WITH_MBEDTLS_LOGS
static void debug_mbedtls(
        void *ctx, int level, const char *file, int line, const char *str) {
    (void) ctx;
    (void) level;
    const size_t len = strlen(str);
    const char *msg = str;
    char msgbuf[len + 1];
    if (len > 0 && str[len - 1] == '\n') {
        memset(msgbuf, 0, len);
        memcpy(msgbuf, str, len - 1);
        msg = msgbuf;
    }
    avs_log_internal_l__(AVS_LOG_TRACE, "mbedtls", file, (unsigned) line, "%s",
                         msg);
}
#    endif // AVS_COMMONS_NET_WITH_MBEDTLS_LOGS

#    define NET_SSL_COMMON_INTERNALS
#    include "../avs_ssl_common.h"

static avs_error_t return_alert_if_any(ssl_socket_t *socket) {
    mbedtls_ssl_context *context = get_context(socket);
    if (context->in_msgtype == AVS_TLS_MESSAGE_TYPE_ALERT) {
        LOG(DEBUG, _("alert_level = ") "%u" _(", alert_description = ") "%u",
            context->in_msg[0], context->in_msg[1]);
        return avs_net_ssl_alert(context->in_msg[0], context->in_msg[1]);
    }
    return AVS_OK;
}

void _avs_net_cleanup_global_ssl_state(void) {
    // do nothing
}

avs_error_t _avs_net_initialize_global_ssl_state(void) {
    // do nothing
    return AVS_OK;
}

static int
avs_bio_recv(void *ctx, unsigned char *buf, size_t len, uint32_t timeout_ms) {
    ssl_socket_t *socket = (ssl_socket_t *) ctx;
    avs_net_socket_opt_value_t orig_timeout;
    avs_net_socket_opt_value_t new_timeout;
    size_t read_bytes;
    int result;
    if (avs_is_err((socket->bio_error = avs_net_socket_get_opt(
                            socket->backend_socket,
                            AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                            &orig_timeout)))) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    new_timeout = orig_timeout;
    if (timeout_ms) {
        new_timeout.recv_timeout =
                avs_time_duration_from_scalar(timeout_ms, AVS_TIME_MS);
    }
    avs_net_socket_set_opt(socket->backend_socket,
                           AVS_NET_SOCKET_OPT_RECV_TIMEOUT, new_timeout);
    if (avs_is_err((socket->bio_error = avs_net_socket_receive(
                            socket->backend_socket, &read_bytes, buf, len)))) {
        if (socket->bio_error.category == AVS_ERRNO_CATEGORY
                && socket->bio_error.code == AVS_ETIMEDOUT) {
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
    if (avs_is_err((socket->bio_error = avs_net_socket_send(
                            socket->backend_socket, buf, len)))) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    } else {
        return (int) len;
    }
}

static avs_error_t get_dtls_overhead(ssl_socket_t *socket,
                                     int *out_header,
                                     int *out_padding_size) {
    if (!is_ssl_started(socket)) {
        return avs_errno(AVS_EBADF);
    }

    const mbedtls_ssl_ciphersuite_t *ciphersuite =
            mbedtls_ssl_ciphersuite_from_string(
                    mbedtls_ssl_get_ciphersuite(get_context(socket)));

    int result = mbedtls_ssl_get_record_expansion(get_context(socket));
    if (result == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE
            || result == MBEDTLS_ERR_SSL_INTERNAL_ERROR) {
        /* This is either a result of compression mode or some internal
         * error, and in both cases we can't predict the size. */
        return avs_errno(AVS_EBADF);
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
    return AVS_OK;
}

static void close_ssl_raw(ssl_socket_t *socket) {
    if (socket->backend_socket) {
        avs_net_socket_close(socket->backend_socket);
    }

    if (socket->flags.context_valid) {
        mbedtls_ssl_free(get_context(socket));
        socket->flags.context_valid = false;
    }
}

static int set_min_ssl_version(mbedtls_ssl_config *config,
                               avs_net_ssl_version_t version) {
    switch (version) {
    case AVS_NET_SSL_VERSION_DEFAULT:
    case AVS_NET_SSL_VERSION_SSLv2_OR_3:
    case AVS_NET_SSL_VERSION_SSLv3:
        mbedtls_ssl_conf_min_version(config, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_0);
        return 0;
    case AVS_NET_SSL_VERSION_TLSv1:
        mbedtls_ssl_conf_min_version(config, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_1);
        return 0;
    case AVS_NET_SSL_VERSION_TLSv1_1:
        mbedtls_ssl_conf_min_version(config, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_2);
        return 0;
    case AVS_NET_SSL_VERSION_TLSv1_2:
        mbedtls_ssl_conf_min_version(config, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_3);
        return 0;
    default:
        LOG(ERROR, _("Unsupported SSL version"));
        return -1;
    }
}

#    if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) \
            || defined(AVS_COMMONS_NET_WITH_PSK)
static bool
contains_cipher(const avs_net_socket_tls_ciphersuites_t *enabled_ciphers,
                int cipher) {
    if (!enabled_ciphers->ids) {
        return true;
    } else {
        for (size_t i = 0; i < enabled_ciphers->num_ids; ++i) {
            if (enabled_ciphers->ids[i] == (uint32_t) cipher) {
                return true;
            }
        }
        return false;
    }
}
#    endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) ||
           // defined(AVS_COMMONS_NET_WITH_PSK)

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
static int *init_cert_ciphersuites(
        const avs_net_socket_tls_ciphersuites_t *enabled_ciphers) {
    const int *all_ciphers = mbedtls_ssl_list_ciphersuites();

    size_t ciphers_count = 0;
    for (const int *cipher = all_ciphers; cipher && *cipher; ++cipher) {
        if (contains_cipher(enabled_ciphers, *cipher)) {
            ++ciphers_count;
        }
    }

    int *ciphers = (int *) avs_calloc(ciphers_count + 1, sizeof(int));
    if (!ciphers) {
        LOG(ERROR, _("Out of memory"));
        return NULL;
    }

    int *cipher_it = ciphers;
    for (const int *cipher = all_ciphers; cipher && *cipher; ++cipher) {
        if (contains_cipher(enabled_ciphers, *cipher)) {
            *cipher_it++ = *cipher;
        }
    }

    return ciphers;
}

#        ifdef WITH_DANE_SUPPORT

#            if MBEDTLS_VERSION_NUMBER < 0x02070000
// the _ret variants were introduced in mbed TLS 2.7.0,
// emulate them on older versions

static inline int mbedtls_sha256_ret(const unsigned char *input,
                                     size_t ilen,
                                     unsigned char output[32],
                                     int is224) {
    mbedtls_sha256(input, ilen, output, is224);
    return 0;
}

static inline int mbedtls_sha512_ret(const unsigned char *input,
                                     size_t ilen,
                                     unsigned char output[64],
                                     int is384) {
    mbedtls_sha512(input, ilen, output, is384);
    return 0;
}
#            endif // MBEDTLS_VERSION_NUMBER

static bool dane_match_buffer(const unsigned char *buf,
                              size_t buf_len,
                              const avs_net_socket_dane_tlsa_record_t *entry) {
    switch (entry->matching_type) {
    case AVS_NET_SOCKET_DANE_MATCH_FULL:
        return entry->association_data_size == buf_len
               && memcmp(entry->association_data, buf, buf_len) == 0;
    case AVS_NET_SOCKET_DANE_MATCH_SHA256: {
        unsigned char sha[32];
        if (entry->association_data_size != sizeof(sha)) {
            return false;
        }
        return !mbedtls_sha256_ret(buf, buf_len, sha, 0)
               && memcmp(entry->association_data, sha, sizeof(sha)) == 0;
    }
    case AVS_NET_SOCKET_DANE_MATCH_SHA512: {
        unsigned char sha[64];
        if (entry->association_data_size != sizeof(sha)) {
            return false;
        }
        return !mbedtls_sha512_ret(buf, buf_len, sha, 0)
               && memcmp(entry->association_data, sha, sizeof(sha)) == 0;
    }
    }
    AVS_UNREACHABLE("Invalid matching type");
    return false;
}

static bool dane_match(mbedtls_x509_crt *crt,
                       const avs_net_socket_dane_tlsa_record_t *entry) {
    switch (entry->selector) {
    case AVS_NET_SOCKET_DANE_CERTIFICATE:
        return dane_match_buffer(crt->raw.p, crt->raw.len, entry);
    case AVS_NET_SOCKET_DANE_PUBLIC_KEY: {
        unsigned char *buf = (unsigned char *) avs_malloc(crt->raw.len);
        if (!buf) {
            LOG(ERROR, _("Out of memory"));
            return false;
        }
        // Note: mbedtls_pk_write_pubkey_der() writes data at the end of buffer
        int length = mbedtls_pk_write_pubkey_der(&crt->pk, buf, crt->raw.len);
        bool result =
                (length >= 0
                 && dane_match_buffer(&buf[crt->raw.len - (size_t) length],
                                      (size_t) length, entry));
        avs_free(buf);
        return result;
    }
    }
    AVS_UNREACHABLE("Invalid selector");
    return false;
}

static bool has_dane_ta_or_ee_entries(ssl_socket_t *socket) {
    for (size_t i = 0; i < socket->security.cert.dane_tlsa.array_element_count;
         ++i) {
        const avs_net_socket_dane_tlsa_record_t *const entry =
                &socket->security.cert.dane_tlsa.array_ptr[i];
        if (entry->certificate_usage
                        == AVS_NET_SOCKET_DANE_TRUST_ANCHOR_ASSERTION
                || entry->certificate_usage
                               == AVS_NET_SOCKET_DANE_DOMAIN_ISSUED_CERTIFICATE) {
            return true;
        }
    }
    return false;
}

static void reset_dane_verify_state(ssl_socket_t *socket) {
    socket->security.cert.dane_verify_state.match_mask = 0;
    socket->security.cert.dane_verify_state.verify_result_flags = 0;
    socket->security.cert.dane_verify_state.verify_result = 0;
}

static void update_dane_verify_state(ssl_socket_t *socket,
                                     mbedtls_x509_crt *crt,
                                     bool is_ee,
                                     uint32_t verify_result_flags) {
    socket->security.cert.dane_verify_state.verify_result_flags |=
            verify_result_flags;

    for (size_t i = 0; i < socket->security.cert.dane_tlsa.array_element_count;
         ++i) {
        const avs_net_socket_dane_tlsa_record_t *const entry =
                &socket->security.cert.dane_tlsa.array_ptr[i];
        if (socket->security.cert.dane_verify_state.match_mask
                & (1 << entry->certificate_usage)) {
            // Certificate usage already satisfied, no need to check again
            continue;
        }
        if ((entry->certificate_usage
                     == AVS_NET_SOCKET_DANE_SERVICE_CERTIFICATE_CONSTRAINT
             || entry->certificate_usage
                        == AVS_NET_SOCKET_DANE_DOMAIN_ISSUED_CERTIFICATE)
                != is_ee) {
            // TA/EE mismatch
            continue;
        }
        if (dane_match(crt, entry)) {
            socket->security.cert.dane_verify_state.match_mask |=
                    (uint8_t) (1 << entry->certificate_usage);
        }
    }
}

static uint32_t perform_cert_verification(ssl_socket_t *socket) {
    // If the only problem with the certificate is that it failed PKIX
    // verification, but we are using DANE and have matched DANE-TA or
    // DANE-EE entry, it's a success
    if (socket->security.cert.dane_verify_state.verify_result_flags
                    == MBEDTLS_X509_BADCERT_NOT_TRUSTED
            && (socket->security.cert.dane_verify_state.match_mask
                & DANE_TA_OR_EE_MATCH_MASK)) {
        return 0;
    }

    uint8_t dane_valid_matches = (socket->security.cert.ca_cert
                                  == socket->security.cert.dane_ta_certs)
                                         ? DANE_TA_OR_EE_MATCH_MASK
                                         : DANE_FULL_MATCH_MASK;
    // If verification succeeded,
    // check if DANE verification succeeded as well
    if (!socket->security.cert.dane_verify_state.verify_result_flags
            && socket->security.cert.dane_tlsa.array_element_count > 0
            && !(socket->security.cert.dane_verify_state.match_mask
                 & dane_valid_matches)) {
        LOG(ERROR, _("DANE certificate verification failed"));
        return MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    }

    return socket->security.cert.dane_verify_state.verify_result_flags;
}

static int verify_cert_cb(void *socket_,
                          mbedtls_x509_crt *crt,
                          int index,
                          uint32_t *verify_result_flags) {
    // This callback is called for each certificate in the chain
    // Starting for the topmost (root) certificate, with highest index
    // And then iterates down to index 0 (the actual peer certificate)
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    assert(socket->security_mode == AVS_NET_SECURITY_CERTIFICATE);
    assert(socket->security.cert.dane_ta_certs);

    if (socket->security.cert.ca_cert == socket->security.cert.dane_ta_certs
            && !has_dane_ta_or_ee_entries(socket)) {
        // No global trust store (opportunistic DANE) and no DANE-TA or DANE-EE
        // entries; this is unusable, so fall back to no verification
        return 0;
    }

    if (index != socket->security.cert.dane_verify_state.last_known_index - 1) {
        // First entry (root certificate)
        reset_dane_verify_state(socket);
    }
    socket->security.cert.dane_verify_state.last_known_index = index;
    update_dane_verify_state(socket, crt, /* is_ee = */ index == 0,
                             *verify_result_flags);

    if (index == 0) {
        // End of the chain, perform actual verification
        uint32_t verify_result = perform_cert_verification(socket);
        *verify_result_flags |= verify_result;

        // We are configured to MBEDTLS_SSL_VERIFY_OPTIONAL, so verification
        // flags would normally be ignored. Let's replicate the logic of
        // MBEDTLS_SSL_VERIFY_REQUIRED instead.
        if (verify_result) {
            LOG(ERROR,
                _("server certificate verification failure: ") "%" PRIu32,
                verify_result);
            socket->security.cert.dane_verify_state.verify_result =
                    MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            if (verify_result == MBEDTLS_X509_BADCERT_MISSING) {
                return MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE;
            } else {
                return MBEDTLS_ERR_X509_FATAL_ERROR;
            }
        }
    }

    return 0;
}

static int wrap_handshake_result(ssl_socket_t *socket, int result) {
    if (result >= 0 && socket->security_mode == AVS_NET_SECURITY_CERTIFICATE
            && socket->security.cert.dane_ta_certs
            && socket->security.cert.dane_verify_state.verify_result) {
        return socket->security.cert.dane_verify_state.verify_result;
    }
    return result;
}
#        else  // WITH_DANE_SUPPORT
static int wrap_handshake_result(ssl_socket_t *socket, int result) {
    (void) socket;
    return result;
}
#        endif // WITH_DANE_SUPPORT

static avs_error_t initialize_cert_security(
        ssl_socket_t *socket,
        const avs_net_socket_tls_ciphersuites_t *tls_ciphersuites) {
    avs_free(socket->effective_ciphersuites);
    if (!(socket->effective_ciphersuites =
                  init_cert_ciphersuites(tls_ciphersuites))) {
        return avs_errno(AVS_ENOMEM);
    }

    if (socket->security.cert.ca_cert || socket->security.cert.ca_crl) {
#        ifdef WITH_DANE_SUPPORT
        if (socket->security.cert.dane_ta_certs) {
            // NOTE: When verify_cert_cb() fails, the whole verification routine
            // fails as well, so this is effectively equivalent to modified
            // MBEDTLS_SSL_VERIFY_REQUIRED.
            mbedtls_ssl_conf_authmode(&socket->config,
                                      MBEDTLS_SSL_VERIFY_OPTIONAL);
            mbedtls_ssl_conf_verify(&socket->config, verify_cert_cb, socket);
        } else
#        endif // WITH_DANE_SUPPORT
        {
            mbedtls_ssl_conf_authmode(&socket->config,
                                      MBEDTLS_SSL_VERIFY_REQUIRED);
        }
        mbedtls_ssl_conf_ca_chain(&socket->config,
                                  socket->security.cert.ca_cert,
                                  socket->security.cert.ca_crl);
    } else {
        mbedtls_ssl_conf_authmode(&socket->config, MBEDTLS_SSL_VERIFY_NONE);
    }

    if (socket->security.cert.client_cert && socket->security.cert.client_key) {
        mbedtls_ssl_conf_own_cert(&socket->config,
                                  socket->security.cert.client_cert,
                                  socket->security.cert.client_key);
    }

    mbedtls_ssl_conf_ciphersuites(&socket->config,
                                  socket->effective_ciphersuites);
    return AVS_OK;
}

static avs_error_t update_cert_configuration(ssl_socket_t *socket) {
    if (socket->security_mode != AVS_NET_SECURITY_CERTIFICATE) {
        return AVS_OK;
    }

#        ifdef WITH_DANE_SUPPORT
    if (socket->security.cert.dane_ta_certs) {
        // 2 0 0 (DANE-TA / Entire certificate / Entire information) data
        // shall be included as part of the trust store

        // First, remove any previous entries
        mbedtls_x509_crt_free(socket->security.cert.dane_ta_certs);
        mbedtls_x509_crt_init(socket->security.cert.dane_ta_certs);
        // And now, add the relevant entries
        for (size_t i = 0;
             i < socket->security.cert.dane_tlsa.array_element_count;
             ++i) {
            const avs_net_socket_dane_tlsa_record_t *const entry =
                    &socket->security.cert.dane_tlsa.array_ptr[i];
            if (entry->certificate_usage
                            == AVS_NET_SOCKET_DANE_TRUST_ANCHOR_ASSERTION
                    && entry->selector == AVS_NET_SOCKET_DANE_CERTIFICATE
                    && entry->matching_type == AVS_NET_SOCKET_DANE_MATCH_FULL
                    && mbedtls_x509_crt_parse_der(
                               socket->security.cert.dane_ta_certs,
                               (const unsigned char *) entry->association_data,
                               entry->association_data_size)) {
                return avs_errno(AVS_EPROTO);
            }
        }
    }
#        endif // WITH_DANE_SUPPORT

    mbedtls_ssl_conf_ca_chain(&socket->config,
                              socket->security.cert.ca_cert,
                              socket->security.cert.ca_crl);
    return AVS_OK;
}
#    else // AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#        define initialize_cert_security(...) avs_errno(AVS_ENOTSUP)
#        define update_cert_configuration(...) AVS_OK
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI

#    ifdef AVS_COMMONS_NET_WITH_PSK
static int *init_psk_ciphersuites(
        const avs_net_socket_tls_ciphersuites_t *enabled_ciphers) {
    const int *all_ciphers = mbedtls_ssl_list_ciphersuites();

    size_t ciphers_count = 0;
    for (const int *cipher = all_ciphers; cipher && *cipher; ++cipher) {
        const mbedtls_ssl_ciphersuite_t *info =
                mbedtls_ssl_ciphersuite_from_id(*cipher);
        if (mbedtls_ssl_ciphersuite_uses_psk(info)
                && contains_cipher(enabled_ciphers, *cipher)) {
            ++ciphers_count;
        }
    }

    int *psk_ciphers = (int *) avs_calloc(ciphers_count + 1, sizeof(int));
    if (!psk_ciphers) {
        LOG(ERROR, _("Out of memory"));
        return NULL;
    }

    int *psk_cipher_it = psk_ciphers;
    for (const int *cipher = all_ciphers; cipher && *cipher; ++cipher) {
        const mbedtls_ssl_ciphersuite_t *info =
                mbedtls_ssl_ciphersuite_from_id(*cipher);
        if (mbedtls_ssl_ciphersuite_uses_psk(info)
                && contains_cipher(enabled_ciphers, *cipher)) {
            *psk_cipher_it++ = *cipher;
        }
    }

    return psk_ciphers;
}

static avs_error_t initialize_psk_security(
        ssl_socket_t *socket,
        const avs_net_socket_tls_ciphersuites_t *tls_ciphersuites) {
    avs_free(socket->effective_ciphersuites);
    if (!(socket->effective_ciphersuites =
                  init_psk_ciphersuites(tls_ciphersuites))) {
        return avs_errno(AVS_ENOMEM);
    }

    /* mbedtls_ssl_conf_psk() makes copies of the buffers */
    /* We set the values directly instead, to avoid that. */
    socket->config.psk = (unsigned char *) socket->security.psk.psk;
    socket->config.psk_len = socket->security.psk.psk_size;
    socket->config.psk_identity =
            (unsigned char *) socket->security.psk.identity;
    socket->config.psk_identity_len = socket->security.psk.identity_size;

    mbedtls_ssl_conf_ciphersuites(&socket->config,
                                  socket->effective_ciphersuites);
    return AVS_OK;
}
#    else // AVS_COMMONS_NET_WITH_PSK
#        define initialize_psk_security(...) \
            (LOG(ERROR, _("PSK support disabled")), avs_errno(AVS_ENOTSUP))
#    endif // AVS_COMMONS_NET_WITH_PSK

static int transport_for_socket_type(avs_net_socket_type_t backend_type) {
    switch (backend_type) {
    case AVS_NET_TCP_SOCKET:
    case AVS_NET_SSL_SOCKET:
        return MBEDTLS_SSL_TRANSPORT_STREAM;
    case AVS_NET_UDP_SOCKET:
    case AVS_NET_DTLS_SOCKET:
        return MBEDTLS_SSL_TRANSPORT_DATAGRAM;
    default:
        AVS_UNREACHABLE("invalid enum value");
        return -1;
    }
}

static int
rng_function(void *ctx, unsigned char *out_buf, size_t out_buf_size) {
    return avs_crypto_prng_bytes((avs_crypto_prng_ctx_t *) ctx, out_buf,
                                 out_buf_size);
}

static avs_error_t
configure_ssl(ssl_socket_t *socket,
              const avs_net_ssl_configuration_t *configuration) {
    mbedtls_ssl_config_init(&socket->config);
    /* HACK: The config is always initialized with MBEDTLS_SSL_IS_SERVER even
     * though it may be later reused in a client context. This is because the
     * default server-side config initializes pretty much everything that the
     * default client-side config does (aside from endpoint, authmode and
     * session_tickets, which are just flags that are trivial to set manually),
     * and more. So it's safer to initialize it with server-side defaults and
     * then repurpose as a client-side config rather than vice versa. Details:
     * https://github.com/ARMmbed/mbedtls/blob/mbedtls-2.6.1/library/ssl_tls.c#L7465
     */
    if (mbedtls_ssl_config_defaults(&socket->config, MBEDTLS_SSL_IS_SERVER,
                                    transport_for_socket_type(
                                            socket->backend_type),
                                    MBEDTLS_SSL_PRESET_DEFAULT)) {
        LOG(ERROR, _("mbedtls_ssl_config_defaults() failed"));
        return avs_errno(AVS_ENOTSUP);
    }

#    ifdef AVS_COMMONS_NET_WITH_MBEDTLS_LOGS
    // most verbose logs available
    mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_dbg(&socket->config, debug_mbedtls, NULL);
#    endif // AVS_COMMONS_NET_WITH_MBEDTLS_LOGS

    if (set_min_ssl_version(&socket->config, configuration->version)) {
        LOG(ERROR, _("Could not set minimum SSL version"));
        return avs_errno(AVS_ENOTSUP);
    }

    mbedtls_ssl_conf_rng(&socket->config, rng_function,
                         configuration->prng_ctx);

    const avs_net_dtls_handshake_timeouts_t *dtls_handshake_timeouts =
            configuration->dtls_handshake_timeouts
                    ? configuration->dtls_handshake_timeouts
                    : &DEFAULT_DTLS_HANDSHAKE_TIMEOUTS;
    int64_t min_ms, max_ms;
    if (avs_time_duration_to_scalar(&min_ms, AVS_TIME_MS,
                                    dtls_handshake_timeouts->min)
            || avs_time_duration_to_scalar(&max_ms, AVS_TIME_MS,
                                           dtls_handshake_timeouts->max)
            || min_ms < 0 || min_ms > UINT32_MAX || max_ms < 0
            || max_ms > UINT32_MAX) {
        LOG(ERROR, _("Invalid DTLS handshake timeouts"));
        return avs_errno(AVS_EINVAL);
    }
    mbedtls_ssl_conf_handshake_timeout(&socket->config, (uint32_t) min_ms,
                                       (uint32_t) max_ms);

    if (configuration->session_resumption_buffer_size > 0) {
        assert(configuration->session_resumption_buffer);
#    ifdef AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
        socket->session_resumption_buffer =
                configuration->session_resumption_buffer;
        socket->session_resumption_buffer_size =
                configuration->session_resumption_buffer_size;
#    endif // AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
    }

    if (configuration->server_name_indication) {
        size_t len = strlen(configuration->server_name_indication);
        if (len >= sizeof(socket->server_name_indication)) {
            LOG(ERROR,
                _("SNI is too long (maximum allowed size is ") "%u" _(")"),
                (unsigned) sizeof(socket->server_name_indication) - 1);
            return avs_errno(AVS_ERANGE);
        }
        memcpy(socket->server_name_indication,
               configuration->server_name_indication, len + 1);
    }
    socket->use_connection_id = configuration->use_connection_id;

#    if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if (socket->use_connection_id
            && transport_for_socket_type(socket->backend_type)
                           == MBEDTLS_SSL_TRANSPORT_DATAGRAM
            && mbedtls_ssl_conf_cid(&socket->config, 0,
                                    MBEDTLS_SSL_UNEXPECTED_CID_IGNORE)) {
        LOG(ERROR, _("cannot configure CID"));
        return avs_errno(AVS_ENOTSUP);
    }
#    endif // MBEDTLS_SSL_DTLS_CONNECTION_ID

    avs_error_t err;
    switch (socket->security_mode) {
    case AVS_NET_SECURITY_PSK:
        err = initialize_psk_security(socket, &configuration->ciphersuites);
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        err = initialize_cert_security(socket, &configuration->ciphersuites);
        break;
    default:
        AVS_UNREACHABLE("invalid enum value");
        err = avs_errno(AVS_EBADF);
    }
    if (avs_is_err(err)) {
        return err;
    }

    if (configuration->additional_configuration_clb
            && configuration->additional_configuration_clb(&socket->config)) {
        LOG(ERROR, _("Error while setting additional SSL configuration"));
        return avs_errno(AVS_EPIPE);
    }

    return AVS_OK;
}

static avs_error_t update_ssl_endpoint_config(ssl_socket_t *socket) {
    avs_net_socket_opt_value_t state_opt;
    avs_error_t err =
            avs_net_socket_get_opt((avs_net_socket_t *) socket,
                                   AVS_NET_SOCKET_OPT_STATE, &state_opt);
    if (avs_is_err(err)) {
        LOG(ERROR, _("initialize_ssl_config: could not get socket state"));
        return err;
    }
    if (state_opt.state == AVS_NET_SOCKET_STATE_CONNECTED) {
        mbedtls_ssl_conf_endpoint(&socket->config, MBEDTLS_SSL_IS_CLIENT);
#    ifdef MBEDTLS_SSL_SESSION_TICKETS
        mbedtls_ssl_conf_session_tickets(&socket->config,
                                         MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
#    endif // MBEDTLS_SSL_SESSION_TICKETS
    } else if (state_opt.state == AVS_NET_SOCKET_STATE_ACCEPTED) {
        mbedtls_ssl_conf_endpoint(&socket->config, MBEDTLS_SSL_IS_SERVER);
#    ifdef MBEDTLS_SSL_SESSION_TICKETS
        mbedtls_ssl_conf_session_tickets(&socket->config,
                                         MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#    endif // MBEDTLS_SSL_SESSION_TICKETS
    } else {
        LOG(ERROR, _("initialize_ssl_config: invalid socket state"));
        return avs_errno(AVS_EINVAL);
    }

    return AVS_OK;
}

#    ifdef AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
static bool sessions_equal(const mbedtls_ssl_session *left,
                           const mbedtls_ssl_session *right) {
    if (!left && !right) {
        return true;
    }
    return left && right && left->ciphersuite == right->ciphersuite
           && left->compression == right->compression
#        ifdef MBEDTLS_HAVE_TIME
           && left->start == right->start
#        endif // MBEDTLS_HAVE_TIME
           && left->id_len == right->id_len
           && memcmp(left->id, right->id, left->id_len) == 0;
}
#    else // AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
#        define sessions_equal(left, right) false
#    endif // AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE

static avs_error_t start_ssl(ssl_socket_t *socket, const char *host) {
    int result;
    avs_error_t err;
    if (avs_is_err((err = update_ssl_endpoint_config(socket)))) {
        LOG(ERROR, _("could not initialize ssl context"));
        return err;
    }
    assert(!socket->flags.context_valid);

    bool restore_session = false;
#    ifdef AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
    mbedtls_ssl_session restored_session;
    mbedtls_ssl_session_init(&restored_session);
#    endif // AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE

    mbedtls_ssl_init(&socket->context);
    socket->flags.context_valid = true;

    mbedtls_ssl_set_bio(get_context(socket), socket, avs_bio_send, NULL,
                        avs_bio_recv);
    mbedtls_ssl_set_timer_cb(get_context(socket), &socket->timer,
                             mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);
    if (avs_is_err((err = update_cert_configuration(socket)))) {
        goto finish;
    }
    if ((result = mbedtls_ssl_setup(get_context(socket), &socket->config))) {
        LOG(ERROR, _("mbedtls_ssl_setup() failed: ") "%d", result);
        err = avs_errno(AVS_ENOMEM);
        goto finish;
    }
#    if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    // This may seem a bit odd, but the CID draft says:
    //
    // > 3.  The "connection_id" Extension
    // > [...]
    // > A zero-length CID value indicates that the client is prepared to send
    // > with a CID but does not wish the server to use one when sending.
    // > [...]
    // > A server willing to use CIDs will respond with a "connection_id"
    // > extension in the ServerHello, containing the CID it wishes the client
    // > to use when sending messages towards it.
    if (socket->use_connection_id
            && transport_for_socket_type(socket->backend_type)
                           == MBEDTLS_SSL_TRANSPORT_DATAGRAM
            && mbedtls_ssl_set_cid(get_context(socket), MBEDTLS_SSL_CID_ENABLED,
                                   NULL, 0)) {
        LOG(ERROR, _("cannot initialize CID to an empty value"));
        err = avs_errno(AVS_EIO);
        goto finish;
    }
#    endif // MBEDTLS_SSL_DTLS_CONNECTION_ID

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
    if ((result = mbedtls_ssl_set_hostname(
                 get_context(socket),
                 socket->server_name_indication[0]
                         ? socket->server_name_indication
                         : host))) {
        LOG(ERROR, _("mbedtls_ssl_set_hostname() failed: ") "%d", result);
        err = avs_errno(result == MBEDTLS_ERR_SSL_ALLOC_FAILED ? AVS_ENOMEM
                                                               : AVS_EINVAL);
        goto finish;
    }
#    else
    (void) host;
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI

#    ifdef AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
    if (socket->session_resumption_buffer
            && socket->config.endpoint == MBEDTLS_SSL_IS_CLIENT) {
        if (avs_is_err(_avs_net_mbedtls_session_restore(
                    &restored_session, socket->session_resumption_buffer,
                    socket->session_resumption_buffer_size))) {
            LOG(WARNING,
                _("Could not restore session; performing full handshake"));
        } else if ((result = mbedtls_ssl_set_session(get_context(socket),
                                                     &restored_session))) {
            LOG(WARNING,
                _("mbedtls_ssl_set_session() failed: ") "%d" _(
                        "; performing full ") _("handshake"),
                result);
        } else {
            restore_session = true;
        }
    }
#    endif // AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE

    socket->bio_error = AVS_OK;
    do {
        result = mbedtls_ssl_handshake(get_context(socket));
    } while (result == MBEDTLS_ERR_SSL_WANT_READ
             || result == MBEDTLS_ERR_SSL_WANT_WRITE);
    result = wrap_handshake_result(socket, result);

    if (result == 0) {
#    if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        if (socket->use_connection_id) {
            unsigned char peer_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX];
            size_t peer_cid_len = 0;
            int enabled = 0;
            (void) mbedtls_ssl_get_peer_cid(get_context(socket), &enabled,
                                            peer_cid, &peer_cid_len);
            if (enabled) {
                char peer_cid_hex[2 * sizeof(peer_cid) + 1] = "";
                (void) avs_hexlify(peer_cid_hex, sizeof(peer_cid_hex), peer_cid,
                                   peer_cid_len);
                LOG(DEBUG, _("negotiated CID = ") "%s", peer_cid_hex);
            }
        }
#    endif // MBEDTLS_SSL_DTLS_CONNECTION_ID
#    ifdef AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
        if (socket->session_resumption_buffer
                && socket->config.endpoint == MBEDTLS_SSL_IS_CLIENT) {
            // We rely on session renegotation being disabled in
            // configuration.
            _avs_net_mbedtls_session_save(
                    get_context(socket)->session,
                    socket->session_resumption_buffer,
                    socket->session_resumption_buffer_size);
        }
#    endif // AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
        if ((socket->flags.session_restored =
                     (restore_session
                      && sessions_equal(get_context(socket)->session,
                                        &restored_session)))) {
            LOG(TRACE, _("handshake success: session restored"));
        } else {
            LOG(TRACE, _("handshake success: new session started"));
        }
    } else {
        if (avs_is_ok((err = return_alert_if_any(socket)))) {
            if (avs_is_err(socket->bio_error)) {
                err = socket->bio_error;
            } else {
                err = avs_errno(AVS_EPROTO);
            }
        }
        LOG(ERROR, _("handshake failed: ") "%d", result);
    }

finish:
#    ifdef AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
    mbedtls_ssl_session_free(&restored_session);
#    endif // AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE
    if (avs_is_err(err)) {
        mbedtls_ssl_free(get_context(socket));
        socket->flags.context_valid = false;
        return err;
    } else {
        return AVS_OK;
    }
}

static avs_error_t
send_ssl(avs_net_socket_t *socket_, const void *buffer, size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    size_t bytes_sent = 0;
    int result = 0;
    avs_error_t err = AVS_OK;
    LOG(TRACE,
        _("send_ssl(socket=") "%p" _(", buffer=") "%p" _(
                ", buffer_length=") "%lu" _(")"),
        (void *) socket, buffer, (unsigned long) buffer_length);

    while (bytes_sent < buffer_length) {
        do {
            socket->bio_error = AVS_OK;
            errno = 0;
            result = mbedtls_ssl_write(get_context(socket),
                                       ((const unsigned char *) buffer)
                                               + bytes_sent,
                                       (size_t) (buffer_length - bytes_sent));
        } while (result == MBEDTLS_ERR_SSL_WANT_WRITE
                 || result == MBEDTLS_ERR_SSL_WANT_READ);
        result = wrap_handshake_result(socket, result);
        if (result <= 0) {
            break;
        }

        bytes_sent += (size_t) result;
    }

    if (result < 0) {
        if (avs_is_err(socket->bio_error)) {
            err = socket->bio_error;
        } else if (avs_is_ok((err = avs_errno(avs_map_errno(errno))))) {
            err = avs_errno(AVS_EPROTO);
        }
    }
    LOG(DEBUG, _("ssl_write result ") "%d", result);

    if (bytes_sent < buffer_length) {
        LOG(ERROR, _("send failed (") "%lu" _("/") "%lu" _("): ") "%d",
            (unsigned long) bytes_sent, (unsigned long) buffer_length, result);
        assert(avs_is_err(err));
        return err;
    }
    return AVS_OK;
}

static avs_error_t receive_ssl(avs_net_socket_t *socket_,
                               size_t *out_bytes_received,
                               void *buffer,
                               size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int result = 0;

    LOG(TRACE,
        _("receive_ssl(socket=") "%p" _(", buffer=") "%p" _(
                ", buffer_length=") "%lu" _(")"),
        (void *) socket, buffer, (unsigned long) buffer_length);

    if (buffer_length > 0
            && transport_for_socket_type(socket->backend_type)
                           == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        // mbed TLS treats datagram connections as if they are stream-based :(
        size_t unread_bytes_from_previous_datagram =
                mbedtls_ssl_get_bytes_avail(get_context(socket));
        while (unread_bytes_from_previous_datagram > 0) {
            if ((result = mbedtls_ssl_read(
                         get_context(socket), (unsigned char *) buffer,
                         AVS_MIN(buffer_length,
                                 unread_bytes_from_previous_datagram)))
                    < 0) {
                break;
            }
            assert((size_t) result <= unread_bytes_from_previous_datagram);
            unread_bytes_from_previous_datagram -= (size_t) result;
        }
    }

    if (result >= 0) {
        do {
            socket->bio_error = AVS_OK;
            errno = 0;
            result = mbedtls_ssl_read(get_context(socket),
                                      (unsigned char *) buffer,
                                      buffer_length);
        } while (result == MBEDTLS_ERR_SSL_WANT_READ
                 || result == MBEDTLS_ERR_SSL_WANT_WRITE);
    }
    result = wrap_handshake_result(socket, result);

    if (result < 0) {
        *out_bytes_received = 0;
        if (result == MBEDTLS_ERR_SSL_TIMEOUT) {
            LOG(TRACE, _("receive_ssl: timed out"));
            return avs_errno(AVS_ETIMEDOUT);
        } else if (result != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            avs_error_t err = return_alert_if_any(socket);
            if (avs_is_ok(err)) {
                if (avs_is_err(socket->bio_error)) {
                    err = socket->bio_error;
                } else if (avs_is_ok((err = avs_errno(avs_map_errno(errno))))) {
                    err = avs_errno(AVS_EPROTO);
                }
            }
            LOG(ERROR, _("receive failed: ") "%d", result);
            return err;
        }
    } else {
        *out_bytes_received = (size_t) result;
        if (transport_for_socket_type(socket->backend_type)
                        == MBEDTLS_SSL_TRANSPORT_DATAGRAM
                && mbedtls_ssl_get_bytes_avail(get_context(socket)) > 0) {
            LOG(WARNING, _("receive_ssl: message truncated"));
            return avs_errno(AVS_EMSGSIZE);
        }
    }
    return AVS_OK;
}

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
static void cleanup_security_cert(ssl_socket_certs_t *certs) {
    _avs_crypto_mbedtls_x509_crt_cleanup(&certs->ca_cert);
    _avs_crypto_mbedtls_x509_crl_cleanup(&certs->ca_crl);
    _avs_crypto_mbedtls_x509_crt_cleanup(&certs->client_cert);
    _avs_crypto_mbedtls_pk_context_cleanup(&certs->client_key);
#        ifdef WITH_DANE_SUPPORT
    // NOTE: Not freeing dane_ta_certs, as it is supposed to be on the
    // ca_cert chain, so has been freed together with ca_cert
    avs_free((void *) (intptr_t) (const void *) certs->dane_tlsa.array_ptr);
#        endif // WITH_DANE_SUPPORT
}
#    else // AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#        define cleanup_security_cert(...) (void) 0
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI

#    ifdef AVS_COMMONS_NET_WITH_PSK
#        define cleanup_security_psk _avs_net_psk_cleanup
#    else // AVS_COMMONS_NET_WITH_PSK
#        define cleanup_security_psk(...) (void) 0
#    endif // AVS_COMMONS_NET_WITH_PSK

static avs_error_t cleanup_ssl(avs_net_socket_t **socket_) {
    ssl_socket_t **socket = (ssl_socket_t **) socket_;
    LOG(TRACE, _("cleanup_ssl(*socket=") "%p" _(")"), (void *) *socket);

    avs_error_t err = close_ssl(*socket_);
    add_err(&err, avs_net_socket_cleanup(&(*socket)->backend_socket));

    switch ((*socket)->security_mode) {
    case AVS_NET_SECURITY_PSK:
        cleanup_security_psk(&(*socket)->security.psk);
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        cleanup_security_cert(&(*socket)->security.cert);
        break;
    }
    avs_free((*socket)->effective_ciphersuites);

#    ifdef AVS_COMMONS_NET_WITH_PSK
    /* Detach the uncopied PSK values */
    (*socket)->config.psk = NULL;
    (*socket)->config.psk_len = 0;
    (*socket)->config.psk_identity = NULL;
    (*socket)->config.psk_identity_len = 0;
#    endif // AVS_COMMONS_NET_WITH_PSK
    mbedtls_ssl_config_free(&(*socket)->config);

    avs_free(*socket);
    *socket = NULL;
    return AVS_OK;
}

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
static int rebuild_client_cert_chain_verify_cb(void *last_configured_cert_,
                                               mbedtls_x509_crt *crt,
                                               int index,
                                               uint32_t *verify_result_flags) {
    // This callback is called for each certificate in the chain
    // Starting for the topmost (root) certificate, with highest index
    // And then iterates down to index 0 (the actual peer certificate)

    // We (ab)use it to rebuild the client certificate chain

    (void) verify_result_flags;
    mbedtls_x509_crt *last_configured_cert =
            (mbedtls_x509_crt *) last_configured_cert_;
    if (index == 0) {
        assert(crt == last_configured_cert
               || (crt->raw.len == last_configured_cert->raw.len
                   && memcmp(crt->raw.p, last_configured_cert->raw.p,
                             crt->raw.len)
                              == 0));
        return 0;
    }

    // Copy the certificate
    mbedtls_x509_crt *crt_copy =
            (mbedtls_x509_crt *) mbedtls_calloc(1, sizeof(*crt_copy));
    if (!crt_copy) {
        LOG(ERROR, _("Out of memory"));
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    mbedtls_x509_crt_init(crt_copy);
    int result = mbedtls_x509_crt_parse_der(crt_copy, crt->raw.p, crt->raw.len);
    if (result) {
        mbedtls_x509_crt_free(crt_copy);
        mbedtls_free(crt_copy);
        return result;
    }
    assert(crt_copy->version != 0);
    assert(!crt_copy->next);

    // Insert it after the last configured one
    crt_copy->next = last_configured_cert->next;
    last_configured_cert->next = crt_copy;

    return 0;
}

static bool cert_makes_cycle_in_chain(const mbedtls_x509_crt *first_cert,
                                      const mbedtls_x509_crt *checked_cert) {
    const mbedtls_x509_crt *cert = first_cert;
    while (cert && cert->version != 0) {
        if (cert == checked_cert) {
            return false;
        }
        if (cert->raw.len == checked_cert->raw.len
                && memcmp(cert->raw.p, checked_cert->raw.p, cert->raw.len)
                               == 0) {
            return true;
        }
        cert = cert->next;
    }
    AVS_UNREACHABLE("checked_cert pointer not found in chain");
    return false;
}

static avs_error_t rebuild_client_cert_chain(mbedtls_x509_crt *trust_store,
                                             mbedtls_x509_crt *first_cert) {
    assert(trust_store);
    assert(first_cert);
    assert(first_cert->version != 0);
    mbedtls_x509_crt *last_cert = first_cert;
    while (last_cert->version != 0 && last_cert->next) {
        last_cert = last_cert->next;
    }
    // Mbed TLS' cert verification stops at the first cert found in trust store,
    // so we repeat the procedure until no new certs are added
    while (true) {
        int result = mbedtls_x509_crt_verify(
                last_cert, trust_store, NULL, NULL, &(uint32_t) { 0 },
                rebuild_client_cert_chain_verify_cb, last_cert);
        if (result == MBEDTLS_ERR_X509_ALLOC_FAILED) {
            return avs_errno(AVS_ENOMEM);
        } else if (result) {
            return avs_errno(AVS_EPROTO);
        } else if (last_cert->version == 0 || !last_cert->next) {
            // No new certificates added - stop here
            return AVS_OK;
        }
        // New certificates added - check for cycles
        // and update the last_cert pointer
        while (last_cert->version != 0 && last_cert->next) {
            if (last_cert->next->version != 0
                    && cert_makes_cycle_in_chain(first_cert, last_cert->next)) {
                // Cycle found - let's remove it and finish
                _avs_crypto_mbedtls_x509_crt_cleanup(&last_cert->next);
                return AVS_OK;
            }
            last_cert = last_cert->next;
        }
    }
}

static avs_error_t
configure_ssl_certs(ssl_socket_certs_t *certs,
                    const avs_net_certificate_info_t *cert_info) {
    LOG(TRACE, _("configure_ssl_certs"));

    avs_error_t err = AVS_OK;

    mbedtls_x509_crt *ca_certs = NULL;
    if ((cert_info->server_cert_validation
         || cert_info->rebuild_client_cert_chain)
            && avs_is_err((err = _avs_crypto_mbedtls_load_certs(
                                   &ca_certs, &cert_info->trusted_certs)))) {
        LOG(ERROR, _("could not load CA chain"));
    }

    if (avs_is_ok(err)) {
        if (cert_info->client_cert.desc.source
                != AVS_CRYPTO_DATA_SOURCE_EMPTY) {
            if (avs_is_err((err = _avs_crypto_mbedtls_load_certs(
                                    &certs->client_cert,
                                    &cert_info->client_cert)))) {
                LOG(ERROR, _("could not load client certificate"));
            } else if (cert_info->rebuild_client_cert_chain && ca_certs
                       && certs->client_cert && certs->client_cert->version != 0
                       && avs_is_err((err = rebuild_client_cert_chain(
                                              ca_certs, certs->client_cert)))) {
                LOG(ERROR, _("could not rebuild client certificate chain"));
            }
            if (avs_is_ok(err)
                    && avs_is_err((err = _avs_crypto_mbedtls_load_private_key(
                                           &certs->client_key,
                                           &cert_info->client_key)))) {
                LOG(ERROR, _("could not load client private key"));
            }
        } else {
            LOG(TRACE, _("client certificate not specified"));
        }
    }

    if (avs_is_ok(err)) {
        if (cert_info->server_cert_validation) {
            assert(!certs->ca_cert);
            certs->ca_cert = ca_certs;
            ca_certs = NULL;
            if (avs_is_err((err = _avs_crypto_mbedtls_load_crls(
                                    &certs->ca_crl,
                                    &cert_info->cert_revocation_lists)))) {
                LOG(ERROR, _("could not load CRLs"));
            }
        } else {
            LOG(DEBUG, _("Server authentication disabled"));
        }
    }

    _avs_crypto_mbedtls_x509_crt_cleanup(&ca_certs);

    if (cert_info->dane) {
#        ifdef WITH_DANE_SUPPORT
        mbedtls_x509_crt **insert_ptr = &certs->ca_cert;
        while (*insert_ptr) {
            insert_ptr = &(*insert_ptr)->next;
        }
        if (!(*insert_ptr = (mbedtls_x509_crt *) mbedtls_calloc(
                      1, sizeof(**insert_ptr)))) {
            LOG(ERROR, _("Out of memory"));
            err = avs_errno(AVS_ENOMEM);
        } else {
            mbedtls_x509_crt_init(*insert_ptr);
            certs->dane_ta_certs = *insert_ptr;
        }
#        else  // WITH_DANE_SUPPORT
        LOG(ERROR, _("DANE not supported"));
        err = avs_errno(AVS_ENOTSUP);
#        endif // WITH_DANE_SUPPORT
    }

    return err;
}

#    else // AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#        define configure_ssl_certs(...) \
            (LOG(ERROR, _("X.509 support disabled")), avs_errno(AVS_ENOTSUP))
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI

#    ifdef AVS_COMMONS_NET_WITH_PSK
static avs_error_t configure_ssl_psk(ssl_socket_t *socket,
                                     const avs_net_psk_info_t *psk) {
    LOG(TRACE, _("configure_ssl_psk"));
    return _avs_net_psk_copy(&socket->security.psk, psk);
}
#    else // AVS_COMMONS_NET_WITH_PSK
#        define configure_ssl_psk(...) \
            (LOG(ERROR, _("PSK support disabled")), avs_errno(AVS_ENOTSUP))
#    endif // AVS_COMMONS_NET_WITH_PSK

static avs_error_t
initialize_ssl_socket(ssl_socket_t *socket,
                      avs_net_socket_type_t backend_type,
                      const avs_net_ssl_configuration_t *configuration) {
    avs_error_t err;
    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;

    socket->backend_type = backend_type;
    socket->backend_configuration = configuration->backend_configuration;

    socket->security_mode = configuration->security.mode;
    switch (configuration->security.mode) {
    case AVS_NET_SECURITY_PSK:
        err = configure_ssl_psk(socket, &configuration->security.data.psk);
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        err = configure_ssl_certs(&socket->security.cert,
                                  &configuration->security.data.cert);
        break;
    default:
        AVS_UNREACHABLE("invalid enum value");
        err = avs_errno(AVS_EINVAL);
    }

    return avs_is_ok(err) ? configure_ssl(socket, configuration) : err;
}

#endif // defined(AVS_COMMONS_WITH_AVS_NET) && defined(AVS_COMMONS_WITH_MBEDTLS)
