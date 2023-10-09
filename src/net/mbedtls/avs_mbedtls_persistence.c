/*
 * Copyright 2023 AVSystem <avsystem@avsystem.com>
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

#if defined(AVS_COMMONS_WITH_AVS_NET) && defined(AVS_COMMONS_WITH_MBEDTLS) \
        && defined(AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE)

// this uses some symbols such as "printf" - include it before poisoning them
#    include <mbedtls/platform.h>

#    include <avs_commons_poison.h>

#    include <assert.h>

#    include <mbedtls/bignum.h>
#    include <mbedtls/platform.h>
#    include <mbedtls/version.h>
#    include <mbedtls/x509_crt.h>

#    include <avsystem/commons/avs_persistence.h>
#    include <avsystem/commons/avs_stream.h>
#    include <avsystem/commons/avs_stream_inbuf.h>
#    include <avsystem/commons/avs_stream_outbuf.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_mbedtls_persistence.h"

#    include "../avs_net_impl.h"

VISIBILITY_SOURCE_BEGIN

static bool is_all_zeros(const void *buf, size_t buf_size) {
    for (size_t i = 0; i < buf_size; ++i) {
        if (((const char *) buf)[i]) {
            return false;
        }
    }
    return true;
}

#    if MBEDTLS_VERSION_NUMBER < 0x02130000

// Mbed TLS <2.19 - use custom persistence format

#        if MBEDTLS_VERSION_NUMBER < 0x02030000
typedef time_t mbedtls_time_t; // mbed TLS < 2.3 does not have mbedtls_time_t
#        endif

/**
 * Persistence format summary
 *
 * - 4 bytes: format magic ("MSP\0", last byte designed for version number);
 *   this is of course an acronym for Mbedtls Session Persistence
 * - 8 bytes: session start timestamp (seconds)
 * - 4 bytes: ciphersuite ID
 * - 4 bytes: compression ID
 * - 1 byte: session ID length
 * - 32 bytes: session ID
 * - 48 bytes: master secret
 * - 4 bytes length + variable length data: DER-format peer certificate
 * - 4 bytes: verification result
 * - 1 byte: MaxFragmentLength negotiated by peer
 * - 1 byte: flag for truncated hmac activation
 * - 1 byte: flag for EtM activation
 * ----------------------------------------------------------------------------
 * 112 bytes + DER certificate
 */
static const char PERSISTENCE_MAGIC[] = { 'M', 'S', 'P', '\0' };

/**
 * The idea of using raw.p/raw.len for storage and mbedtls_x509_crt_parse_der()
 * for restore comes from mbed TLS session ticket format:
 * https://github.com/ARMmbed/mbedtls/blob/a928e6727876377322d2fafe46383126e9c69e05/library/ssl_ticket.c#L169
 * BTW, we cannot use that code because it is a) internal linkage (and the
 * ticket mechanism that uses it hardcodes a random encryption key, which is
 * unsuitable for long-term persistence), b) based on raw mempcy() of the
 * mbedtls_ssl_session structure without any format magic, which makes it prone
 * to serious problems if we try to restore it on another platform and/or
 * another mbed TLS version.
 */
static avs_error_t handle_cert_persistence(avs_persistence_context_t *ctx,
                                           mbedtls_x509_crt **cert_ptr) {
#        ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
    void *data = (*cert_ptr ? (*cert_ptr)->raw.p : NULL);
    size_t size = (*cert_ptr ? (*cert_ptr)->raw.len : 0);
    // Note that avs_persistence_sized_buffer() avs_malloc()ates the buffer
    // in the restore case
    avs_error_t err = avs_persistence_sized_buffer(ctx, &data, &size);
    if (avs_is_err(err)) {
        return err;
    }
    if (data && avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        assert(!*cert_ptr);
        if (!(*cert_ptr = (mbedtls_x509_crt *) mbedtls_calloc(
                      1, sizeof(mbedtls_x509_crt)))) {
            err = avs_errno(AVS_ENOMEM);
            goto restore_finish;
        }
        mbedtls_x509_crt_init(*cert_ptr);
        if (mbedtls_x509_crt_parse_der(*cert_ptr, (unsigned char *) data,
                                       size)) {
            err = avs_errno(AVS_EBADMSG);
            mbedtls_x509_crt_free(*cert_ptr);
            mbedtls_free(*cert_ptr);
            *cert_ptr = NULL;
        }
    restore_finish:
        avs_free(data);
    }
    return err;
#        else
    (void) cert_ptr;
    void *data = NULL;
    size_t size = 0;
    avs_error_t err = avs_persistence_sized_buffer(ctx, &data, &size);
    if (avs_is_err(err)) {
        return err;
    }
    if (data && avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        // avs_persistence_sized_buffer() could allocate memory if it is restore
        // case
        LOG(WARNING,
            _("x509 certificates support is not compiled in - ignoring ")
                    _("restored certificate"));
        avs_free(data);
    }
    return AVS_OK;
#        endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI
}

static avs_error_t handle_session_persistence(avs_persistence_context_t *ctx,
                                              mbedtls_ssl_session *session) {
    avs_time_real_t session_start;
    int32_t ciphersuite = 0;
    int32_t compression = 0;
    uint8_t id_len = 0;
    // https://github.com/ARMmbed/mbedtls/blob/a928e6727876377322d2fafe46383126e9c69e05/include/mbedtls/ssl.h#L542
    // As you can see, mbedtls_ssl_session structure is crazy with a ton of
    // #ifdefs we need to replicate...
    mbedtls_x509_crt **peer_cert_ptr =
#        if defined(MBEDTLS_X509_CRT_PARSE_C)           \
                && (MBEDTLS_VERSION_NUMBER < 0x02110000 \
                    || defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE))
            &session->peer_cert;
#        else  // defined(MBEDTLS_X509_CRT_PARSE_C) && (MBEDTLS_VERSION_NUMBER <
            // 0x02110000 || defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE))
            &(mbedtls_x509_crt *[]){ NULL }[0];
#        endif // defined(MBEDTLS_X509_CRT_PARSE_C) && (MBEDTLS_VERSION_NUMBER <
               // 0x02110000 || defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE))
    uint8_t *mfl_code_ptr =
#        ifdef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
            &session->mfl_code;
#        else  // MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
            &(uint8_t[]){ 0 }[0];
#        endif // MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    bool trunc_hmac = false;
    bool encrypt_then_mac = false;

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
#        ifdef MBEDTLS_HAVE_TIME
        session_start = avs_time_real_from_scalar(session->start, AVS_TIME_S);
#        else  // MBEDTLS_HAVE_TIME
        session_start = avs_time_real_now();
#        endif // MBEDTLS_HAVE_TIME
        ciphersuite = (int32_t) session->ciphersuite;
        compression = (int32_t) session->compression;
        id_len = (uint8_t) session->id_len;
#        ifdef MBEDTLS_SSL_TRUNCATED_HMAC
        trunc_hmac = !!session->trunc_hmac;
#        endif // MBEDTLS_SSL_TRUNCATED_HMAC
#        ifdef MBEDTLS_SSL_ENCRYPT_THEN_MAC
        encrypt_then_mac = !!session->encrypt_then_mac;
#        endif // MBEDTLS_SSL_ENCRYPT_THEN_MAC
    }

    AVS_STATIC_ASSERT(sizeof(session->id) == 32, session_id_is_32bytes);
    AVS_STATIC_ASSERT(sizeof(session->master) == 48, session_master_is_48bytes);

    avs_error_t err;
    (void) (avs_is_err((err = avs_persistence_i64(
                                ctx, &session_start.since_real_epoch.seconds)))
            || avs_is_err((err = avs_persistence_i32(ctx, &ciphersuite)))
            || avs_is_err((err = avs_persistence_i32(ctx, &compression)))
            || avs_is_err((err = avs_persistence_u8(ctx, &id_len)))
            || avs_is_err((err = avs_persistence_bytes(ctx, session->id,
                                                       sizeof(session->id))))
            || avs_is_err(
                       (err = avs_persistence_bytes(ctx, session->master,
                                                    sizeof(session->master))))
            || avs_is_err((err = handle_cert_persistence(ctx, peer_cert_ptr)))
            || avs_is_err((
                       err = avs_persistence_u32(ctx, &session->verify_result)))
            || avs_is_err((err = avs_persistence_u8(ctx, mfl_code_ptr)))
            || avs_is_err((err = avs_persistence_bool(ctx, &trunc_hmac)))
            || avs_is_err(
                       (err = avs_persistence_bool(ctx, &encrypt_then_mac))));

    if (avs_is_ok(err)
            && avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
#        ifdef MBEDTLS_HAVE_TIME
        session->start =
                (mbedtls_time_t) session_start.since_real_epoch.seconds;
#        endif // MBEDTLS_HAVE_TIME
        session->ciphersuite = (int) ciphersuite;
        session->compression = (int) compression;
        session->id_len = (size_t) id_len;
#        ifdef MBEDTLS_SSL_TRUNCATED_HMAC
        session->trunc_hmac = trunc_hmac;
#        endif // MBEDTLS_SSL_TRUNCATED_HMAC
#        ifdef MBEDTLS_SSL_ENCRYPT_THEN_MAC
        session->encrypt_then_mac = encrypt_then_mac;
#        endif // MBEDTLS_SSL_ENCRYPT_THEN_MAC
    }

#        if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) \
                && !defined(MBEDTLS_X509_CRT_PARSE_C)
    if (*peer_cert_ptr) {
        mbedtls_x509_crt_free(*peer_cert_ptr);
        mbedtls_free(*peer_cert_ptr);
    }
#        endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI && !MBEDTLS_X509_CRT_PARSE_C
    return err;
}

avs_error_t _avs_net_mbedtls_context_save(mbedtls_ssl_context *ctx,
                                          void *out_buf,
                                          size_t out_buf_size,
                                          bool only_if_new) {
    if (only_if_new) {
        return avs_errno(AVS_ENOENT);
    }
    avs_error_t err = AVS_OK;
    avs_stream_outbuf_t out_buf_stream = AVS_STREAM_OUTBUF_STATIC_INITIALIZER;
    avs_stream_outbuf_set_buffer(&out_buf_stream, out_buf, out_buf_size);
    avs_persistence_context_t persistence_ctx =
            avs_persistence_store_context_create(
                    (avs_stream_t *) &out_buf_stream);
    mbedtls_ssl_session session;
    mbedtls_ssl_session_init(&session);
    if (mbedtls_ssl_get_session(ctx, &session)) {
        // no session to persist, ignore
        err = avs_errno(AVS_ENOENT);
    } else if (avs_is_err((err = avs_persistence_magic(
                                   &persistence_ctx,
                                   PERSISTENCE_MAGIC,
                                   sizeof(PERSISTENCE_MAGIC))))) {
        LOG(ERROR, _("Could not write session magic"));
    } else if (avs_is_err((err = handle_session_persistence(&persistence_ctx,
                                                            &session)))) {
        LOG(ERROR, _("Could not persist session data"));
    }
    mbedtls_ssl_session_free(&session);
    // ensure that everything after the persisted data is zeroes, to make
    // "compression" of persistent storage possible; see docs for
    // avs_net_ssl_configuration_t::session_resumption_buffer for details
    size_t clear_start =
            avs_is_ok(err) ? avs_stream_outbuf_offset(&out_buf_stream) : 0;
    assert(clear_start <= out_buf_size);
    memset((char *) out_buf + clear_start, 0, out_buf_size - clear_start);
    return err;
}

avs_error_t _avs_net_mbedtls_context_restore(mbedtls_ssl_context *out_ctx,
                                             bool *out_ctx_freed,
                                             const void *buf,
                                             size_t buf_size) {
    *out_ctx_freed = false;
    if (is_all_zeros(buf, buf_size)) {
        LOG(TRACE, _("Session data empty, not attempting restore"));
        return avs_errno(AVS_EBADMSG);
    }
    avs_stream_inbuf_t in_buf_stream = AVS_STREAM_INBUF_STATIC_INITIALIZER;
    avs_stream_inbuf_set_buffer(&in_buf_stream, buf, buf_size);
    avs_persistence_context_t persistence_ctx =
            avs_persistence_restore_context_create(
                    (avs_stream_t *) &in_buf_stream);
    avs_error_t err = avs_persistence_magic(&persistence_ctx, PERSISTENCE_MAGIC,
                                            sizeof(PERSISTENCE_MAGIC));
    if (avs_is_err(err)) {
        LOG(ERROR, _("Could not restore session: invalid magic"));
    } else {
        mbedtls_ssl_session restored_session;
        mbedtls_ssl_session_init(&restored_session);
        if (avs_is_err((err = handle_session_persistence(&persistence_ctx,
                                                         &restored_session)))) {
            LOG(ERROR, _("Could not restore session data"));
        } else {
            int result = mbedtls_ssl_set_session(out_ctx, &restored_session);
            if (result) {
                LOG(WARNING,
                    _("mbedtls_ssl_set_session() failed: ") "%d" _(
                            "; performing full handshake"),
                    result);
                err = avs_errno(AVS_ENOMEM);
            }
        }
        mbedtls_ssl_session_free(&restored_session);
    }
    return err;
}

#    else // MBEDTLS_VERSION_NUMBER < 0x02130000

// Mbed TLS >=2.19 - wrap native Mbed TLS session persistence routines

// "MSP\1" - "version 1", persists mbedtls_ssl_session only
static const char PERSISTENCE_MAGIC_V1[] = { 'M', 'S', 'P', '\1' };

// "MSP\2" - "version 2", persists entire mbedtls_ssl_context; this has its own
// limitations, so both versions need to coexist in the same version of avs_net
static const char PERSISTENCE_MAGIC_V2[] = { 'M', 'S', 'P', '\2' };

AVS_STATIC_ASSERT(sizeof(PERSISTENCE_MAGIC_V1) == sizeof(PERSISTENCE_MAGIC_V2),
                  persistence_magic_consistent_size);

static const size_t PERSISTENCE_HEADER_SIZE =
        sizeof(PERSISTENCE_MAGIC_V1) + sizeof(uint32_t);

avs_error_t _avs_net_mbedtls_context_save(mbedtls_ssl_context *ctx,
                                          void *out_buf,
                                          size_t out_buf_size,
                                          bool only_if_new) {
#        if MBEDTLS_VERSION_NUMBER < 0x03000000
    if (only_if_new) {
        // In Mbed TLS 2.x, mbedtls_ssl_get_session() is idempotent, so this
        // would save the session every time. We assume that there are no new
        // sessions during renegotiation.
        return avs_errno(AVS_ENOENT);
    }
#        endif // MBEDTLS_VERSION_NUMBER < 0x03000000
    (void) only_if_new;
    bool persist_whole_context = false;
#        if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) \
                && defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    int cid_enabled = 0;
    size_t cid_length = 0;
    (void) mbedtls_ssl_get_peer_cid(ctx, &cid_enabled, NULL, &cid_length);
    if (cid_enabled && cid_length) {
        persist_whole_context = true;
    }
#        endif // defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) &&
               // defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    avs_error_t err = AVS_OK;
    size_t bytes_written = 0;
    mbedtls_ssl_session session;
    mbedtls_ssl_session_init(&session);
    if (mbedtls_ssl_get_session(ctx, &session)) {
        // no session to persist, ignore
        err = avs_errno(AVS_ENOENT);
    } else if (out_buf_size < PERSISTENCE_HEADER_SIZE) {
        err = avs_errno(AVS_EMSGSIZE);
    } else {
        int result = 0;
#        if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) \
                && defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        if (persist_whole_context) {
            result = mbedtls_ssl_context_save(
                    ctx, (unsigned char *) out_buf + PERSISTENCE_HEADER_SIZE,
                    AVS_MIN(out_buf_size - PERSISTENCE_HEADER_SIZE, UINT32_MAX),
                    &bytes_written);
        }
#        endif // defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) &&
               // defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        if (!persist_whole_context || result) {
            persist_whole_context = false;
            result = mbedtls_ssl_session_save(
                    &session,
                    (unsigned char *) out_buf + PERSISTENCE_HEADER_SIZE,
                    AVS_MIN(out_buf_size - PERSISTENCE_HEADER_SIZE, UINT32_MAX),
                    &bytes_written);
        }
        if (result == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
            err = avs_errno(AVS_EMSGSIZE);
        } else if (result) {
            err = avs_errno(AVS_EIO);
        }
#        if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) \
                && defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        // HACK: mbedtls_ssl_context_save() resets the session. To keep things
        // operational, restore what we have just persisted.
        else if (persist_whole_context
                 && (result = mbedtls_ssl_context_load(
                             ctx,
                             (unsigned char *) out_buf
                                     + PERSISTENCE_HEADER_SIZE,
                             bytes_written))) {
            err = avs_errno(AVS_ENOMEM);
        }
#        endif // defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) &&
               // defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    }
    if (avs_is_ok(err)) {
        uint32_t bytes_written32 = (uint32_t) bytes_written;
        assert(bytes_written == bytes_written32);
        memcpy(out_buf,
               persist_whole_context ? PERSISTENCE_MAGIC_V2
                                     : PERSISTENCE_MAGIC_V1,
               sizeof(PERSISTENCE_MAGIC_V1));
        bytes_written32 = avs_convert_be32(bytes_written32);
        memcpy((char *) out_buf + sizeof(PERSISTENCE_MAGIC_V1),
               &bytes_written32, sizeof(bytes_written32));
        memset((char *) out_buf + PERSISTENCE_HEADER_SIZE + bytes_written, 0,
               out_buf_size - PERSISTENCE_HEADER_SIZE - bytes_written);
    } else if (err.category != AVS_ERRNO_CATEGORY || err.code != AVS_ENOENT) {
        memset(out_buf, 0, out_buf_size);
        if (err.category == AVS_ERRNO_CATEGORY && err.code == AVS_EMSGSIZE) {
            LOG(ERROR, _("Could not persist session: buffer too small"));
        } else {
            LOG(ERROR, _("Could not persist session: unknown error"));
        }
    }
    mbedtls_ssl_session_free(&session);
    return err;
}

avs_error_t _avs_net_mbedtls_context_restore(mbedtls_ssl_context *out_ctx,
                                             bool *out_ctx_freed,
                                             const void *buf,
                                             size_t buf_size) {
    *out_ctx_freed = false;
    if (is_all_zeros(buf, buf_size)) {
        LOG(TRACE, _("Session data empty, not attempting restore"));
        return avs_errno(AVS_EBADMSG);
    }
    int version = -1;
    if (buf_size >= PERSISTENCE_HEADER_SIZE) {
        if (memcmp(buf, PERSISTENCE_MAGIC_V1, sizeof(PERSISTENCE_MAGIC_V1))
                == 0) {
            version = 1;
        }
#        if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) \
                && defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        else if (memcmp(buf, PERSISTENCE_MAGIC_V2, sizeof(PERSISTENCE_MAGIC_V2))
                 == 0) {
            version = 2;
        }
#        endif // defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) &&
               // defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    }
    if (version < 0) {
        LOG(ERROR, _("Could not restore session: invalid magic"));
        return avs_errno(AVS_EBADMSG);
    }
    uint32_t bytes_used;
    memcpy(&bytes_used,
           (const char *) buf + sizeof(PERSISTENCE_MAGIC_V1),
           sizeof(bytes_used));
    bytes_used = avs_convert_be32(bytes_used);
    if (bytes_used + PERSISTENCE_HEADER_SIZE > buf_size) {
        LOG(ERROR, _("Could not restore session: malformed header"));
        return avs_errno(AVS_EBADMSG);
    }

    int result = -1;
#        if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) \
                && defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if (version == 2) {
        if ((result = mbedtls_ssl_context_load(
                     out_ctx,
                     (const unsigned char *) buf + PERSISTENCE_HEADER_SIZE,
                     bytes_used))) {
            *out_ctx_freed = true;
        }
    } else
#        endif // defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) &&
               // defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    {
        assert(version == 1);
        mbedtls_ssl_session restored_session;
        mbedtls_ssl_session_init(&restored_session);
        result = mbedtls_ssl_session_load(&restored_session,
                                          (const unsigned char *) buf
                                                  + PERSISTENCE_HEADER_SIZE,
                                          bytes_used);
        if (!result
                && (result = mbedtls_ssl_set_session(out_ctx,
                                                     &restored_session))) {
            LOG(WARNING,
                _("mbedtls_ssl_set_session() failed: ") "%d" _(
                        "; performing full handshake"),
                result);
        }
        mbedtls_ssl_session_free(&restored_session);
    }
    switch (result) {
    case MBEDTLS_ERR_SSL_ALLOC_FAILED:
        LOG(ERROR, _("Could not restore session: out of memory"));
        return avs_errno(AVS_ENOMEM);
    case 0:
        return AVS_OK;
    default:
        LOG(ERROR, _("Could not restore session: invalid data"));
        return avs_errno(AVS_EBADMSG);
    }
}

#    endif // MBEDTLS_VERSION_NUMBER < 0x02130000

#endif // defined(AVS_COMMONS_WITH_AVS_NET) && defined(AVS_COMMONS_WITH_MBEDTLS)
       // && defined(AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE)
