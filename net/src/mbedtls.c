/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014-2017 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

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

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

typedef struct {
    mbedtls_x509_crt *ca_cert;
    mbedtls_x509_crt *client_cert;
    mbedtls_pk_context *pk_key;
} ssl_socket_certs_t;

typedef struct {
    avs_net_psk_t value;
    int *ciphersuites;
} ssl_socket_psk_t;

typedef struct {
    const avs_net_socket_v_table_t * const operations;
    mbedtls_ssl_context context;
    mbedtls_ssl_config config;
    avs_net_security_mode_t security_mode;
    union {
        ssl_socket_certs_t cert;
        ssl_socket_psk_t psk;
    } security;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
    mbedtls_timing_delay_context timer;
    avs_net_socket_type_t backend_type;
    avs_net_abstract_socket_t *backend_socket;
    int error_code;
    avs_net_ssl_version_t version;
    avs_ssl_additional_configuration_clb_t *additional_configuration_clb;
    avs_net_socket_configuration_t backend_configuration;
} ssl_socket_t;

static int is_ssl_started(ssl_socket_t *socket) {
    return socket->context.conf != NULL;
}

#define NET_SSL_COMMON_INTERNALS
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
    remote_hostname_ssl,
    remote_port_ssl,
    local_port_ssl,
    get_opt_ssl,
    set_opt_ssl,
    errno_ssl
};

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
        new_timeout.recv_timeout = (avs_net_timeout_t) timeout_ms;
    }
    avs_net_socket_set_opt(socket->backend_socket,
                           AVS_NET_SOCKET_OPT_RECV_TIMEOUT, new_timeout);
    if (avs_net_socket_receive(socket->backend_socket, &read_bytes, buf, len)) {
        result = MBEDTLS_ERR_NET_RECV_FAILED;
        socket->error_code = avs_net_socket_errno(socket->backend_socket);
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
    const mbedtls_ssl_ciphersuite_t *ciphersuite =
            mbedtls_ssl_ciphersuite_from_string(
                    mbedtls_ssl_get_ciphersuite(&socket->context));
    *out_header = 13; /* base DTLS header size */
    *out_padding_size = 0;
    if (ciphersuite) {
        const mbedtls_cipher_info_t *cipher =
                mbedtls_cipher_info_from_type(ciphersuite->cipher);
        const mbedtls_md_info_t *mac =
                mbedtls_md_info_from_type(ciphersuite->mac);
        if (cipher) {
            if (cipher->mode == MBEDTLS_MODE_CBC) {
                *out_padding_size = (int) cipher->block_size; /* padding */
                *out_header += (int) cipher->iv_size; /* explicit IV */
            } else if (cipher->mode == MBEDTLS_MODE_GCM
                    || cipher->mode == MBEDTLS_MODE_CCM) {
                *out_header += 8; /* explicit IV length for GCM and CCM */
            }
        }
        if (mac && !(cipher && (cipher->mode == MBEDTLS_MODE_GCM
                                        || cipher->mode == MBEDTLS_MODE_CCM))) {
            *out_header += (int) mbedtls_md_get_size(mac);
        }
    }
    /* ignoring the compression for now */
    /* mbed TLS does not declare any overhead constants */
    return 0;
}

static void close_ssl_raw(ssl_socket_t *socket) {
    if (socket->backend_socket) {
        avs_net_socket_close(socket->backend_socket);
    }
    mbedtls_ssl_free(&socket->context);
    memset(&socket->context, 0, sizeof(socket->context));

    /* Detach the uncopied PSK values */
    socket->config.psk = NULL;
    socket->config.psk_len = 0;
    socket->config.psk_identity = NULL;
    socket->config.psk_identity_len = 0;
    mbedtls_ssl_config_free(&socket->config);
    memset(&socket->config, 0, sizeof(socket->config));

    mbedtls_ctr_drbg_free(&socket->rng);
    memset(&socket->rng, 0, sizeof(socket->rng));

    mbedtls_entropy_free(&socket->entropy);
    memset(&socket->entropy, 0, sizeof(socket->entropy));
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

static int initialize_ssl_config(ssl_socket_t *socket) {
    avs_net_socket_opt_value_t state_opt;
    int endpoint;
    if (avs_net_socket_get_opt((avs_net_abstract_socket_t *) socket,
                               AVS_NET_SOCKET_OPT_STATE, &state_opt)) {
        LOG(ERROR, "initialize_ssl_config: could not get socket state");
        return -1;
    }
    if (state_opt.state == AVS_NET_SOCKET_STATE_CONNECTED) {
        endpoint = MBEDTLS_SSL_IS_CLIENT;
    } else if (state_opt.state == AVS_NET_SOCKET_STATE_ACCEPTED) {
        endpoint = MBEDTLS_SSL_IS_SERVER;
    } else {
        socket->error_code = EINVAL;
        LOG(ERROR, "initialize_ssl_config: invalid socket state");
        return -1;
    }

    mbedtls_ssl_config_init(&socket->config);
    if (mbedtls_ssl_config_defaults(
            &socket->config, endpoint,
            transport_for_socket_type(socket->backend_type),
            MBEDTLS_SSL_PRESET_DEFAULT)) {
        LOG(ERROR, "mbedtls_ssl_config_defaults() failed");
        socket->error_code = EINVAL;
        return -1;
    }

    if (set_min_ssl_version(&socket->config, socket->version)) {
        LOG(ERROR, "Could not set minimum SSL version");
        socket->error_code = EINVAL;
        return -1;
    }

    mbedtls_ssl_conf_rng(&socket->config,
                         mbedtls_ctr_drbg_random, &socket->rng);

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

    if (socket->additional_configuration_clb
            && socket->additional_configuration_clb(&socket->config)) {
        LOG(ERROR, "Error while setting additional SSL configuration");
        socket->error_code = EINVAL;
        return -1;
    }

    socket->error_code = 0;
    return 0;
}

static int start_ssl(ssl_socket_t *socket, const char *host) {
    int result;
    mbedtls_entropy_init(&socket->entropy);

    mbedtls_ctr_drbg_init(&socket->rng);
    if ((result = mbedtls_ctr_drbg_seed(&socket->rng, mbedtls_entropy_func,
                                        &socket->entropy, NULL, 0))) {
        LOG(ERROR, "mbedtls_ctr_drbg_seed() failed: %d", result);
        socket->error_code = ENOSYS;
        return -1;
    }

    if (initialize_ssl_config(socket)) {
        LOG(ERROR, "could not initialize ssl context");
        return -1;
    }

    mbedtls_ssl_init(&socket->context);
    mbedtls_ssl_set_bio(&socket->context, socket,
                        avs_bio_send, NULL, avs_bio_recv);
    mbedtls_ssl_set_timer_cb(&socket->context, &socket->timer,
                             mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);
    if ((result = mbedtls_ssl_setup(&socket->context, &socket->config))) {
        LOG(ERROR, "mbedtls_ssl_setup() failed: %d", result);
        socket->error_code = ENOMEM;
        return -1;
    }

    if ((result = mbedtls_ssl_set_hostname(&socket->context, host))) {
        LOG(ERROR, "mbedtls_ssl_set_hostname() failed: %d", result);
        socket->error_code =
                (result == MBEDTLS_ERR_SSL_ALLOC_FAILED ? ENOMEM : EINVAL);
        return -1;
    }

    for (;;) {
        result = mbedtls_ssl_handshake(&socket->context);
        if (result == 0) {
            LOG(TRACE, "handshake success");
            break;
        } else if (result != MBEDTLS_ERR_SSL_WANT_READ
                && result != MBEDTLS_ERR_SSL_WANT_WRITE) {
            LOG(ERROR, "handshake failed: %d", result);
            break;
        }
    }

    if (!result && is_verification_enabled(socket)) {
        uint32_t verify_result =
                mbedtls_ssl_get_verify_result(&socket->context);
        if (verify_result) {
            LOG(ERROR, "server certificate verification failure: %" PRIu32,
                verify_result);
            result = -1;
        }
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

static int shutdown_ssl(avs_net_abstract_socket_t *socket_) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    int retval;
    LOG(TRACE, "shutdown_ssl(socket=%p)", (void *) socket);
    WRAP_ERRNO(socket, retval, avs_net_socket_shutdown(socket->backend_socket));
    return retval;
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
        errno = 0;
        result = mbedtls_ssl_write(
                &socket->context,
                ((const unsigned char *) buffer) + bytes_sent,
                (size_t) (buffer_length - bytes_sent));
        if (result <= 0) {
            if (result == MBEDTLS_ERR_SSL_WANT_READ
                    || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            } else {
                LOG(DEBUG, "ssl_write result %d", result);
                break;
            }
        } else {
            bytes_sent += (size_t) result;
        }
    }
    if (bytes_sent < buffer_length) {
        LOG(ERROR, "send failed (%lu/%lu): %d",
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

    while (result < 0
            && result != MBEDTLS_ERR_SSL_WANT_READ
            && result != MBEDTLS_ERR_SSL_WANT_WRITE) {
        errno = 0;
        result = mbedtls_ssl_read(&socket->context,
                                  (unsigned char *) buffer, buffer_length);
    }
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
    free(psk->value.psk);
    psk->value.psk = NULL;
    free(psk->value.identity);
    psk->value.identity = NULL;
}

static int cleanup_ssl(avs_net_abstract_socket_t **socket_) {
    ssl_socket_t **socket = (ssl_socket_t **) socket_;
    LOG(TRACE, "cleanup_ssl(*socket=%p)", (void *) *socket);

    close_ssl(*socket_);
    avs_net_socket_cleanup(&(*socket)->backend_socket);

    switch ((*socket)->security_mode) {
    case AVS_NET_SECURITY_PSK:
        cleanup_security_psk(&(*socket)->security.psk);
        break;
    case AVS_NET_SECURITY_CERTIFICATE:
        cleanup_security_cert(&(*socket)->security.cert);
        break;
    }
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

    cleanup_security_psk(&socket->security.psk);

    socket->security.psk.value.psk_size = psk->psk_size;
    socket->security.psk.value.psk = (char *) malloc(psk->psk_size);
    if (!socket->security.psk.value.psk) {
        LOG(ERROR, "out of memory");
        return -1;
    }

    socket->security.psk.value.identity_size = psk->identity_size;
    socket->security.psk.value.identity = (char *) malloc(psk->identity_size);
    if (!socket->security.psk.value.identity) {
        LOG(ERROR, "out of memory");
        cleanup_security_psk(&socket->security.psk);
        return -1;
    }

    memcpy(socket->security.psk.value.psk, psk->psk, psk->psk_size);
    memcpy(socket->security.psk.value.identity, psk->identity,
           psk->identity_size);

    return 0;
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 avs_net_socket_type_t backend_type,
                                 const avs_net_ssl_configuration_t *configuration) {
    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;

    socket->backend_type = backend_type;
    socket->version = configuration->version;
    socket->additional_configuration_clb =
            configuration->additional_configuration_clb;
    socket->backend_configuration = configuration->backend_configuration;

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

    return 0;
}
