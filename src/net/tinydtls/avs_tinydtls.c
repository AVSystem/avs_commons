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

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_NET) && defined(AVS_COMMONS_WITH_TINYDTLS)

#    include <assert.h>
#    include <inttypes.h>
#    include <string.h>

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>

#    define uthash_malloc(Size) avs_malloc(Size)
#    define uthash_free(Ptr, Size) avs_free(Ptr)

#    include <tinydtls/dtls.h>

#    include "../avs_net_global.h"

#    include "../avs_net_impl.h"

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
    avs_net_socket_t *backend_socket;
    avs_error_t bio_error;
    avs_net_socket_configuration_t backend_configuration;

    ssl_read_context_t *read_ctx;

    avs_net_owned_psk_t psk;
} ssl_socket_t;

#    define NET_SSL_COMMON_INTERNALS
#    include "../avs_ssl_common.h"

avs_error_t _avs_net_initialize_global_ssl_state(void) {
    dtls_init();
    return AVS_OK;
}

void _avs_net_cleanup_global_ssl_state(void) {
    // do nothing
}

static avs_error_t get_dtls_overhead(ssl_socket_t *socket,
                                     int *out_header,
                                     int *out_padding_size) {
    if (!is_ssl_started(socket)) {
        return avs_errno(AVS_EBADF);
    }
    /* tinyDTLS supports AES-128-CCM-8 ciphersuite only */
    *out_header = 13  /* header */
                  + 8 /* nonce */
                  + 8 /* integrity verification code */;
    *out_padding_size = 0;
    return AVS_OK;
}

/**
 * tinyDTLS stores struct sockaddr inside the session_t. It is internally used
 * by tinyDTLS to distinguish between different peers using the same socket.
 *
 * Yet, in avs_commons, we use single SSL socket to handle single SSL
 * connection, therefore we could just use this fake handle to uniquely identify
 * the peer, and at the same time to simplify code a lot, as extracting
 * sockaddrs and similar is not an easy task in an API that tries to abstract
 * lower networking layers as much as possible.
 */
static const session_t *get_dtls_session(void) {
    static session_t DTLS_SESSION;
    /**
     * Need to set it to something non-zero, or tinyDTLS won't be able to
     * compare sessions, and in effect it won't be able to free some
     * internally used memory.
     */
    DTLS_SESSION.addr.sa.sa_family = AF_INET;

    return &DTLS_SESSION;
}

static avs_error_t send_ssl(avs_net_socket_t *ssl_socket,
                            const void *buffer,
                            size_t buffer_length) {
    ssl_socket_t *socket = (ssl_socket_t *) ssl_socket;

    while (buffer_length > 0) {
        session_t session = *get_dtls_session();
        /* Welcome to the world of tinyDTLS, where dtls_write takes a non-const
         * pointer to the data to be send. Empirical check proved however that
         * in fact this buffer is not modified, so I guess we may leave that
         * ugly const-cast here. */
        socket->bio_error = AVS_OK;
        int result = dtls_write(socket->ctx, &session,
                                (uint8 *) (intptr_t) buffer, buffer_length);
        if (result < 0) {
            LOG(ERROR, _("send_ssl() failed"));
            if (avs_is_err(socket->bio_error)) {
                return socket->bio_error;
            } else {
                return avs_errno(AVS_EPROTO);
            }
        }
        assert((size_t) result <= buffer_length);
        buffer = (const uint8_t *) buffer + result;
        buffer_length -= (size_t) result;
    }
    return AVS_OK;
}

static avs_error_t receive_ssl(avs_net_socket_t *socket_,
                               size_t *out_bytes_read,
                               void *out_buffer,
                               size_t buffer_size) {
    ssl_socket_t *socket = (ssl_socket_t *) socket_;
    /* This is technically incorrect as the @p out_buffer is supposed to be used
     * for decoded data, but we use it for encoded data as well to avoid
     * excessive memory consumption. So, in the end, this buffer will never be
     * completely filled with decoded data. */
    size_t message_length;
    avs_error_t err =
            avs_net_socket_receive(socket->backend_socket, &message_length,
                                   out_buffer, buffer_size);

    if (avs_is_err(err)) {
        return err;
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
    if (dtls_handle_message(socket->ctx, &session, (uint8 *) out_buffer,
                            (int) message_length)) {
        err = avs_errno(AVS_EPROTO);
    }
    socket->read_ctx = NULL;

    return err;
}

static avs_error_t cleanup_ssl(avs_net_socket_t **socket_) {
    ssl_socket_t *socket = *(ssl_socket_t **) socket_;
    LOG(TRACE, _("cleanup_ssl(*socket=") "%p" _(")"), (void *) socket);

#    ifdef DTLS_PSK
    _avs_net_psk_cleanup(&socket->psk);
#    endif
    avs_error_t err = close_ssl(*socket_);
    add_err(&err, avs_net_socket_cleanup(&socket->backend_socket));
    avs_free(socket);
    *socket_ = NULL;
    return err;
}

static void close_ssl_raw(ssl_socket_t *socket) {
    LOG(TRACE, _("close_ssl_raw(socket=") "%p" _(")"), (void *) socket);
    if (socket->ctx) {
        dtls_free_context(socket->ctx);
        socket->ctx = NULL;
    }
    if (socket->backend_socket) {
        avs_net_socket_close(socket->backend_socket);
    }
}

static bool is_ssl_started(ssl_socket_t *socket) {
    if (!socket->ctx) {
        return false;
    }
    const dtls_peer_t *peer = dtls_get_peer(socket->ctx, get_dtls_session());

    return peer && dtls_peer_is_connected(peer);
}

static bool is_session_resumed(ssl_socket_t *socket) {
    (void) socket;
    return false;
}

static avs_error_t ssl_handshake(ssl_socket_t *socket) {
    const dtls_peer_t *peer = dtls_get_peer(socket->ctx, get_dtls_session());
    /* Arbitrary constant limiting the number of packet exchanges between our
     * client and a server. It is definitely enough to handle normal DTLS
     * handshakes, and should protect us from looping indefinitely if for some
     * reason we couldn't reach the connected state. */
    int handshake_exchanges_remaining = 64;

    while (dtls_peer_state(peer) != DTLS_STATE_CONNECTED) {
        if (!handshake_exchanges_remaining--) {
            LOG(ERROR, _("ssl_handshake(): too many handshake retries"));
            return avs_errno(AVS_ETIMEDOUT);
        }

        LOG(DEBUG, _("ssl_handshake(): client state ") "%d",
            (int) dtls_peer_state(peer));
        char message[DTLS_MAX_BUF];
        size_t message_length;
        avs_error_t err =
                avs_net_socket_receive(socket->backend_socket, &message_length,
                                       message, sizeof(message));
        if (avs_is_err(err)) {
            return err;
        }

        session_t session = *get_dtls_session();
        assert(message_length <= INT_MAX);
        socket->bio_error = AVS_OK;
        if (dtls_handle_message(socket->ctx, &session, (uint8 *) message,
                                (int) message_length)) {
            LOG(ERROR, _("ssl_handshake() failed"));
            if (avs_is_err(socket->bio_error)) {
                return socket->bio_error;
            } else {
                return avs_errno(AVS_EPROTO);
            }
        }
    }
    return AVS_OK;
}

static avs_error_t start_ssl(ssl_socket_t *socket, const char *host) {
    (void) host;
    socket->bio_error = AVS_OK;
    int retval = dtls_connect(socket->ctx, get_dtls_session());
    if (retval < 0) {
        if (avs_is_err(socket->bio_error)) {
            return socket->bio_error;
        } else {
            return avs_errno(AVS_EPROTO);
        }
    } else if (retval == 0) {
        return AVS_OK;
    } else {
        return ssl_handshake(socket);
    }
}

static avs_error_t configure_ssl_psk(ssl_socket_t *socket,
                                     const avs_net_psk_info_t *psk) {
    LOG(TRACE, _("configure_ssl_psk"));

#    ifndef DTLS_PSK
    LOG(ERROR, _("support for psk is disabled"));
    return avs_errno(AVS_ENOTSUP);
#    else
    return _avs_net_psk_copy(&socket->psk, psk);
#    endif /* DTLS_PSK */
}

static avs_error_t
configure_ssl_certs(ssl_socket_t *socket,
                    const avs_net_certificate_info_t *cert_info) {
    (void) socket;
    (void) cert_info;
    LOG(ERROR, _("support for certificate mode is not yet implemented"));
    return avs_errno(AVS_ENOTSUP);
}

static avs_error_t
configure_ssl(ssl_socket_t *socket,
              const avs_net_ssl_configuration_t *configuration) {
    socket->backend_configuration = configuration->backend_configuration;

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
        err = avs_errno(AVS_EINVAL);
    }
    if (avs_is_err(err)) {
        return err;
    }

    if (configuration->additional_configuration_clb
            && configuration->additional_configuration_clb(socket->ctx)) {
        LOG(ERROR, _("Error while setting additional SSL configuration"));
        return avs_errno(AVS_EPIPE);
    }
    return AVS_OK;
}

static int dtls_write_handler(dtls_context_t *ctx,
                              session_t *session,
                              uint8 *buffer,
                              size_t length) {
    (void) session;
    ssl_socket_t *socket = (ssl_socket_t *) dtls_get_app_data(ctx);
    if (avs_is_err((socket->bio_error = avs_net_socket_send(
                            socket->backend_socket, (const void *) buffer,
                            length)))) {
        return -1;
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

#    ifdef DTLS_PSK
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
            LOG(WARNING, _("tinyDTLS buffer for PSK identity is too small"));
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
            LOG(WARNING, _("tinyDTLS buffer for PSK key is too small"));
            return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }
        assert(socket->psk.psk_size <= INT_MAX);
        memcpy(out_buffer, socket->psk.psk, socket->psk.psk_size);
        return (int) socket->psk.psk_size;
    default:
        LOG(ERROR, _("unsupported request type ") "%d", (int) type);
        break;
    }
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#    endif /* #ifdef DTLS_PSK */

#    ifdef DTLS_ECC
static int dtls_get_ecdsa_key_handler(dtls_context_t *ctx,
                                      const session_t *session,
                                      const dtls_ecdsa_key_t **result) {
    (void) ctx;
    (void) session;
    (void) result;
    LOG(ERROR, _("tinyDTLS with ECC is not supported"));
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
    LOG(ERROR, _("tinyDTLS with ECC is not supported"));
    return -1;
}

#    endif /* #ifdef DTLS_ECC */

static int dtls_event_handler(dtls_context_t *ctx,
                              session_t *session,
                              dtls_alert_level_t level,
                              unsigned short code) {
    (void) ctx;
    (void) session;
    LOG(DEBUG,
        _("tinyDTLS reported an event (level=") "%d" _(", code=") "%d" _(")"),
        (int) level, (int) code);
    (void) level;
    (void) code;
    return 0;
}

static avs_error_t
initialize_ssl_socket(ssl_socket_t *socket,
                      avs_net_socket_type_t backend_type,
                      const avs_net_ssl_configuration_t *configuration) {
    *(const avs_net_socket_v_table_t **) (intptr_t) &socket->operations =
            &ssl_vtable;

    if (backend_type != AVS_NET_UDP_SOCKET) {
        LOG(ERROR, _("tinyDTLS backend supports UDP sockets only"));
        return avs_errno(AVS_ENOTSUP);
    }

    socket->backend_type = backend_type;
    socket->ctx = dtls_new_context(socket);
    if (!socket->ctx) {
        LOG(ERROR, _("could not instantiate tinyDTLS context"));
        return avs_errno(AVS_ENOMEM);
    }

    // TODO: actually use configuration->tls_ciphersuites
    avs_error_t err = configure_ssl(socket, configuration);
    if (avs_is_err(err)) {
        dtls_free_context(socket->ctx);
        socket->ctx = NULL;
        return err;
    }

    static dtls_handler_t handlers = {
        .write = dtls_write_handler,
        .read = dtls_read_handler,
        .event = dtls_event_handler,
#    ifdef DTLS_PSK
        .get_psk_info = dtls_get_psk_info_handler,
#    endif

#    ifdef DTLS_ECC
        .get_ecdsa_key = dtls_get_ecdsa_key_handler,
        .verify_ecdsa_key = dtls_verify_ecdsa_key_handler
#    endif
    };
    dtls_set_handler(socket->ctx, &handlers);

    return AVS_OK;
}

#endif // defined(AVS_COMMONS_WITH_AVS_NET) &&
       // defined(AVS_COMMONS_WITH_TINYDTLS)
