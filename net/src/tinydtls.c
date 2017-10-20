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

#include <tinydtls/dtls.h>

#include "net_impl.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    void *out_buffer;
    size_t buffer_size;
    size_t *out_bytes_read;
} ssl_read_context_t;

typedef struct {
    const avs_net_socket_v_table_t *const operations;
    dtls_context_t *ctx;

    avs_net_socket_type_t backend_type;
    avs_net_abstract_socket_t *backend_socket;
    int error_code;
    avs_net_socket_configuration_t backend_configuration;

    ssl_read_context_t *read_ctx;

    avs_net_owned_psk_t psk;
} ssl_socket_t;

#define NET_SSL_COMMON_INTERNALS
#include "ssl_common.h"

static int get_dtls_overhead(ssl_socket_t *socket,
                             int *out_header,
                             int *out_padding_size) {
    (void) socket;
    /* tinyDTLS supports AES-128-CCM-8 ciphersuite only */
    *out_header = 13 /* header */
                + 8 /* nonce */
                + 8 /* integrity verification code */;
    *out_padding_size = 0;
    return 0;
}

/**
 * tinyDTLS stores struct sockaddr inside the session_t. It is internally used
 * by tinyDTLS to distinguish between different peers using the same socket.
 *
 * Yet, in avs_commons, we use single SSL socket to handle single SSL connection,
 * therefore we could just use this fake handle to uniquely identify the peer,
 * and at the same time to simplify code a lot, as extracting sockaddrs and
 * similar is not an easy task in an API that tries to abstract lower networking
 * layers as much as possible.
 */
static const session_t *get_dtls_session() {
    static session_t DTLS_SESSION;
    /**
     * Need to set it to something non-zero, or tinyDTLS won't be able to
     * compare sessions, and in effect it won't be able to free some
     * internally used memory.
     */
    DTLS_SESSION.addr.sa.sa_family = AF_INET;

    return &DTLS_SESSION;
}

static int send_ssl(avs_net_abstract_socket_t *ssl_socket,
                    const void *buffer,
                    size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) ssl_socket;

    while (buffer_length > 0) {
        session_t session = *get_dtls_session();
        /* Welcome to the world of tinyDTLS, where dtls_write takes a non-const
         * pointer to the data to be send. Empirical check proved however that
         * in fact this buffer is not modified, so I guess we may leave that
         * ugly const-cast here. */
        int result = dtls_write(socket->ctx, &session,
                                (uint8 *) (intptr_t) buffer, buffer_length);
        if (result < 0) {
            LOG(ERROR, "send_ssl() failed");
            return result;
        }
        assert((size_t) result <= buffer_length);
        buffer = (const uint8_t *) buffer + result;
        buffer_length -= (size_t) result;
    }
    return 0;
}

static int receive_ssl(avs_net_abstract_socket_t *socket_,
                       size_t *out_bytes_read,
                       void *out_buffer,
                       size_t buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    /* This is technically incorrect as the @p out_buffer is supposed to be used
     * for decoded data, but we use it for encoded data as well to avoid
     * excessive memory consumption. So, in the end, this buffer will never be
     * completely filled with decoded data. */
    size_t message_length;
    int result;
    WRAP_ERRNO(socket, result,
               avs_net_socket_receive(socket->backend_socket, &message_length,
                                      out_buffer, buffer_size));

    if (result) {
        return result;
    }

    ssl_read_context_t read_context = {
        .buffer_size = buffer_size,
        .out_buffer = out_buffer,
        .out_bytes_read = out_bytes_read
    };

    session_t session = *get_dtls_session();
    assert(socket->read_ctx == NULL);
    socket->read_ctx = &read_context;
    assert(message_length <= INT_MAX);
    result = dtls_handle_message(socket->ctx, &session, (uint8 *) out_buffer,
                                 (int) message_length);
    socket->read_ctx = NULL;

    return result;
}

static int cleanup_ssl(avs_net_abstract_socket_t **socket_) {
    ssl_socket_t *socket = *(ssl_socket_t **) socket_;
    LOG(TRACE, "cleanup_ssl(*socket=%p)", (void *) socket);

#ifdef DTLS_PSK
    _avs_net_psk_cleanup(&socket->psk);
#endif
    close_ssl(*socket_);
    free(socket);
    *socket_ = NULL;
    return 0;
}

static void close_ssl_raw(ssl_socket_t *socket) {
    LOG(TRACE, "close_ssl_raw(socket=%p)", (void *) socket);
    if (socket->ctx) {
        dtls_free_context(socket->ctx);
        socket->ctx = NULL;
    }
    if (socket->backend_socket) {
        int retval;
        WRAP_ERRNO(socket, retval, avs_net_socket_close(socket->backend_socket));
        (void) retval;
        avs_net_socket_cleanup(&socket->backend_socket);
    }
}

static bool is_ssl_started(ssl_socket_t *socket) {
    if (!socket->ctx) {
        return false;
    }
    const dtls_peer_t *peer = dtls_get_peer(socket->ctx, get_dtls_session());

    return peer && dtls_peer_is_connected(peer);
}

static int ssl_handshake(ssl_socket_t *socket) {
    const dtls_peer_t *peer = dtls_get_peer(socket->ctx, get_dtls_session());
    /* Arbitrary constant limiting the number of packet exchanges between our
     * client and a server. It is definitely enough to handle normal DTLS
     * handshakes, and should protect us from looping indefinitely if for some
     * reason we couldn't reach the connected state. */
    int handshake_exchanges_remaining = 64;

    while (dtls_peer_state(peer) != DTLS_STATE_CONNECTED) {
        if (!handshake_exchanges_remaining--) {
            LOG(ERROR, "ssl_handshake(): too many handshake retries");
            return -1;
        }

        LOG(DEBUG, "ssl_handshake(): client state %d",
            (int) dtls_peer_state(peer));
        char message[DTLS_MAX_BUF];
        size_t message_length;
        int result;
        WRAP_ERRNO(socket, result,
                   avs_net_socket_receive(socket->backend_socket,
                                          &message_length, message,
                                          sizeof(message)));
        if (result) {
            return result;
        }

        session_t session = *get_dtls_session();
        assert(message_length <= INT_MAX);
        result = dtls_handle_message(socket->ctx, &session, (uint8 *) message,
                                     (int) message_length);
        if (result) {
            LOG(ERROR, "ssl_handshake() failed");
            return result;
        }
    }
    return 0;
}

static int start_ssl(ssl_socket_t *socket, const char *host) {
    (void) host;
    int retval = dtls_connect(socket->ctx, get_dtls_session());
    if (retval > 0) {
        retval = ssl_handshake(socket);
    }
    return retval;
}

static int configure_ssl_psk(ssl_socket_t *socket,
                             const avs_net_psk_t *psk) {
    LOG(TRACE, "configure_ssl_psk");

#ifndef DTLS_PSK
    LOG(ERROR, "support for psk is disabled");
    return -1;
#else
    return _avs_net_psk_copy(&socket->psk, psk);
#endif /* DTLS_PSK */
}

static int configure_ssl_certs(ssl_socket_t *socket,
                               const avs_net_certificate_info_t *cert_info) {
    (void) socket;
    (void) cert_info;
    LOG(ERROR, "support for certificate mode is not yet implemented");
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
                              uint8 *buffer,
                              size_t length) {
    (void) session;
    ssl_socket_t *socket = (ssl_socket_t *) dtls_get_app_data(ctx);
    int result;
    WRAP_ERRNO(socket, result,
               avs_net_socket_send(socket->backend_socket,
                                   (const void *) buffer, length));
    if (result) {
        return result;
    }
    assert(length <= INT_MAX);
    return (int) length;
}

static int dtls_read_handler(dtls_context_t *ctx,
                             session_t *session,
                             uint8 *buf,
                             size_t len) {
    (void) session;
    ssl_read_context_t *read_context =
            ((ssl_socket_t *) dtls_get_app_data(ctx))->read_ctx;
    assert(read_context);
    assert(len <= read_context->buffer_size);

    memmove(read_context->out_buffer, buf, len);
    *read_context->out_bytes_read = len;

    return 0;
}

#ifdef DTLS_PSK
static int dtls_get_psk_info_handler(dtls_context_t *ctx,
                                     const session_t *session,
                                     dtls_credentials_type_t type,
                                     const unsigned char *id,
                                     size_t id_size,
                                     unsigned char *out_buffer,
                                     size_t size) {
    (void) session;

    ssl_socket_t *socket = (ssl_socket_t *) dtls_get_app_data(ctx);
    assert(socket->psk.psk);
    assert(socket->psk.identity);

    switch (type) {
    case DTLS_PSK_HINT:
    case DTLS_PSK_IDENTITY:
        /**
         * We ignore whathever is being provided to us in @p id parameter, as
         * it didn't seem to be used in any way in the example tinyDTLS client.
         */
        (void) id;

        if (size < socket->psk.identity_size) {
            LOG(WARNING, "tinyDTLS buffer for PSK identity is too small");
            return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }
        assert(socket->psk.identity_size <= INT_MAX);
        memcpy(out_buffer, socket->psk.identity, socket->psk.identity_size);
        return (int) socket->psk.identity_size;
    case DTLS_PSK_KEY:
        if (socket->psk.identity_size != id_size
                || memcmp(socket->psk.identity, id, id_size)) {
            return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
        }

        if (size < socket->psk.psk_size) {
            LOG(WARNING, "tinyDTLS buffer for PSK key is too small");
            return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }
        assert(socket->psk.psk_size <= INT_MAX);
        memcpy(out_buffer, socket->psk.psk, socket->psk.psk_size);
        return (int) socket->psk.psk_size;
    default:
        LOG(ERROR, "unsupported request type %d", (int) type);
        break;
    }
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#endif /* #ifdef DTLS_PSK */

#ifdef DTLS_ECC
static int dtls_get_ecdsa_key_handler(dtls_context_t *ctx,
                                      const session_t *session,
                                      const dtls_ecdsa_key_t **result) {
    (void) ctx;
    (void) session;
    (void) result;
    LOG(ERROR, "tinyDTLS with ECC is not supported");
    return -1;
}

static int dtls_verify_ecdsa_key_handler(dtls_context_t *ctx,
                                         const session_t *session,
                                         const unsigned char *other_pub_x,
                                         const unsigned char *other_pub_y,
                                         size_t key_size) {
    (void) ctx;
    (void) session;
    (void) other_pub_x;
    (void) other_pub_y;
    (void) key_size;
    LOG(ERROR, "tinyDTLS with ECC is not supported");
    return -1;
}

#endif /* #ifdef DTLS_ECC */

static int dtls_event_handler(dtls_context_t *ctx,
                              session_t *session,
                              dtls_alert_level_t level,
                              unsigned short code) {
    (void) ctx;
    (void) session;
    LOG(DEBUG, "tinyDTLS reported an event (level=%d, code=%d)", (int) level,
        (int) code);
    (void) level;
    (void) code;
    return 0;
}

static int initialize_ssl_socket(ssl_socket_t *socket,
                                 avs_net_socket_type_t backend_type,
                                 const avs_net_ssl_configuration_t *configuration) {
    if (backend_type != AVS_NET_UDP_SOCKET) {
        LOG(ERROR, "tinyDTLS backend supports UDP sockets only");
        return -1;
    }
    static bool dtls_initialized;

    if (!dtls_initialized) {
        dtls_initialized = true;
        dtls_init();
    }

    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;

    socket->backend_type = backend_type;
    socket->ctx = dtls_new_context(socket);
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
#ifdef DTLS_PSK
        .get_psk_info = dtls_get_psk_info_handler,
#endif

#ifdef DTLS_ECC
        .get_ecdsa_key = dtls_get_ecdsa_key_handler,
        .verify_ecdsa_key = dtls_verify_ecdsa_key_handler
#endif
    };
    dtls_set_handler(socket->ctx, &handlers);

    return 0;
}
