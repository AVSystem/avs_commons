/*
 * Copyright 2018 AVSystem <avsystem@avsystem.com>
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

#include <mbedtls/platform.h>
#include <mbedtls/version.h>

#include <avsystem/commons/persistence.h>
#include <avsystem/commons/stream.h>
#include <avsystem/commons/stream/stream_inbuf.h>
#include <avsystem/commons/stream/stream_outbuf.h>

#include "mbedtls_persistence.h"
#include "../net_impl.h"

VISIBILITY_SOURCE_BEGIN

#if MBEDTLS_VERSION_NUMBER < 0x02030000
typedef time_t mbedtls_time_t; // mbed TLS < 2.3 does not have mbedtls_time_t
#endif

#ifndef WITH_X509
typedef void mbedtls_x509_crt;
#endif // WITH_X509

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
static int handle_cert_persistence(avs_persistence_context_t *ctx,
                                   mbedtls_x509_crt **cert_ptr) {
#ifdef WITH_X509
    void *data = (*cert_ptr ? (*cert_ptr)->raw.p : NULL);
    size_t size = (*cert_ptr ? (*cert_ptr)->raw.len : 0);
#else
    void *data = NULL;
    size_t size = 0;
#endif // WITH_X509
    // Note that avs_persistence_sized_buffer() malloc()ates the buffer
    // in the restore case
    int result = avs_persistence_sized_buffer(ctx, &data, &size);
    if (result) {
        return result;
    }
    if (data && avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
        assert(!*cert_ptr);
#ifdef WITH_X509
        if (!(*cert_ptr = (mbedtls_x509_crt *)
                mbedtls_calloc(1, sizeof(mbedtls_x509_crt)))) {
            result = -1;
            goto restore_finish;
        }
        mbedtls_x509_crt_init(*cert_ptr);
        if ((result = mbedtls_x509_crt_parse_der(
                *cert_ptr, (unsigned char *) data, size))) {
            mbedtls_x509_crt_free(*cert_ptr);
            mbedtls_free(*cert_ptr);
            *cert_ptr = NULL;
        }
restore_finish:
#endif // WITH_X509
        free(data);
    }
    return result;
}

static int handle_session_persistence(avs_persistence_context_t *ctx,
                                      mbedtls_ssl_session *session) {
    avs_time_real_t session_start;
    int32_t ciphersuite;
    int32_t compression;
    uint8_t id_len;
    // https://github.com/ARMmbed/mbedtls/blob/a928e6727876377322d2fafe46383126e9c69e05/include/mbedtls/ssl.h#L542
    // As you can see, mbedtls_ssl_session structure is crazy with a ton of
    // #ifdefs we need to replicate...
    mbedtls_x509_crt **peer_cert_ptr =
#ifdef MBEDTLS_X509_CRT_PARSE_C
            &session->peer_cert;
#else // MBEDTLS_X509_CRT_PARSE_C
            &(mbedtls_x509_crt *[]) { NULL }[0];
#endif // MBEDTLS_X509_CRT_PARSE_C
    uint8_t *mfl_code_ptr =
#ifdef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
            &session->mfl_code;
#else // MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
            &(uint8_t[]) { 0 }[0];
#endif // MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    bool trunc_hmac = false;
    bool encrypt_then_mac = false;

    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
#ifdef MBEDTLS_HAVE_TIME
        session_start = avs_time_real_from_scalar(session->start, AVS_TIME_S);
#else // MBEDTLS_HAVE_TIME
        session_start = avs_time_real_now();
#endif //MBEDTLS_HAVE_TIME
        ciphersuite = (int32_t) session->ciphersuite;
        compression = (int32_t) session->compression;
        id_len = (uint8_t) session->id_len;
#ifdef MBEDTLS_SSL_TRUNCATED_HMAC
        trunc_hmac = !!session->trunc_hmac;
#endif // MBEDTLS_SSL_TRUNCATED_HMAC
#ifdef MBEDTLS_SSL_ENCRYPT_THEN_MAC
        encrypt_then_mac = !!session->encrypt_then_mac;
#endif // MBEDTLS_SSL_ENCRYPT_THEN_MAC
    }

    AVS_STATIC_ASSERT(sizeof(session->id) == 32, session_id_is_32bytes);
    AVS_STATIC_ASSERT(sizeof(session->master) == 48, session_master_is_48bytes);

    int retval;
    (void) ((retval = avs_persistence_i64(
                    ctx, &session_start.since_real_epoch.seconds))
            || (retval = avs_persistence_i32(ctx, &ciphersuite))
            || (retval = avs_persistence_i32(ctx, &compression))
            || (retval = avs_persistence_u8(ctx, &id_len))
            || (retval = avs_persistence_bytes(ctx, session->id,
                                               sizeof(session->id)))
            || (retval = avs_persistence_bytes(ctx, session->master,
                                               sizeof(session->master)))
            || (retval = handle_cert_persistence(ctx, peer_cert_ptr))
            || (retval = avs_persistence_u32(ctx, &session->verify_result))
            || (retval = avs_persistence_u8(ctx, mfl_code_ptr))
            || (retval = avs_persistence_bool(ctx, &trunc_hmac))
            || (retval = avs_persistence_bool(ctx, &encrypt_then_mac)));

    if (!retval && avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE) {
#ifdef MBEDTLS_HAVE_TIME
        session->start =
                (mbedtls_time_t) session_start.since_real_epoch.seconds;
#endif //MBEDTLS_HAVE_TIME
        session->ciphersuite = (int) ciphersuite;
        session->compression = (int) compression;
        session->id_len = (size_t) id_len;
#ifdef MBEDTLS_SSL_TRUNCATED_HMAC
        session->trunc_hmac = trunc_hmac;
#endif // MBEDTLS_SSL_TRUNCATED_HMAC
#ifdef MBEDTLS_SSL_ENCRYPT_THEN_MAC
        session->encrypt_then_mac = encrypt_then_mac;
#endif // MBEDTLS_SSL_ENCRYPT_THEN_MAC
    }

#if defined(WITH_X509) && !defined(MBEDTLS_X509_CRT_PARSE_C)
    if (*peer_cert_ptr) {
        mbedtls_x509_crt_free(*peer_cert_ptr);
        mbedtls_free(*peer_cert_ptr);
    }
#endif // WITH_X509 && !MBEDTLS_X509_CRT_PARSE_C
    return retval;
}

int _avs_net_mbedtls_session_save(mbedtls_ssl_session *session,
                                  void *out_buf, size_t out_buf_size) {
    avs_persistence_context_t *ctx = NULL;
    avs_stream_outbuf_t out_buf_stream = AVS_STREAM_OUTBUF_STATIC_INITIALIZER;
    avs_stream_outbuf_set_buffer(&out_buf_stream, out_buf, out_buf_size);
    int retval = avs_stream_write((avs_stream_abstract_t *) &out_buf_stream,
                                  PERSISTENCE_MAGIC, sizeof(PERSISTENCE_MAGIC));
    if (retval) {
        LOG(ERROR, "Could not write session magic");
        goto finish;
    }
    if (!(ctx = avs_persistence_store_context_new(
            (avs_stream_abstract_t *) &out_buf_stream))) {
        LOG(ERROR, "Could not create session_save() context");
        retval = -1;
        goto finish;
    }
    if ((retval = handle_session_persistence(ctx, session))) {
        LOG(ERROR, "Could not persist session data");
    }
    avs_persistence_context_delete(ctx);
finish:;
    // ensure that everything after the persisted data is zeroes, to make
    // "compression" of persistent storage possible; see docs for
    // avs_net_ssl_configuration_t::session_resumption_buffer for details
    size_t clear_start = retval ? 0 : avs_stream_outbuf_offset(&out_buf_stream);
    assert(clear_start <= out_buf_size);
    memset((char *) out_buf + clear_start, 0, out_buf_size - clear_start);
    return retval;
}

static bool is_all_zeros(const void *buf, size_t buf_size) {
    for (size_t i = 0; i < buf_size; ++i) {
        if (((const char *) buf)[i]) {
            return false;
        }
    }
    return true;
}

int _avs_net_mbedtls_session_restore(mbedtls_ssl_session *out_session,
                                     const void *buf, size_t buf_size) {
    if (is_all_zeros(buf, buf_size)) {
        LOG(TRACE, "Session data empty, not attempting restore");
        return -1;
    }
    avs_stream_inbuf_t in_buf_stream = AVS_STREAM_INBUF_STATIC_INITIALIZER;
    avs_stream_inbuf_set_buffer(&in_buf_stream, buf, buf_size);
    char magic_header[sizeof(PERSISTENCE_MAGIC)];
    int retval = avs_stream_read_reliably(
            (avs_stream_abstract_t *) &in_buf_stream,
            magic_header, sizeof(magic_header));
    if (retval || memcmp(magic_header, PERSISTENCE_MAGIC,
                         sizeof(PERSISTENCE_MAGIC))) {
        // this may happen in a perfectly valid case of empty persistence buffer
        // (no session stored), so it's not on the ERROR level
        LOG(ERROR, "Could not restore session: invalid magic");
        return -1;
    }
    avs_persistence_context_t *ctx = avs_persistence_restore_context_new(
            (avs_stream_abstract_t *) &in_buf_stream);
    if (!ctx) {
        LOG(ERROR, "Could not create session_restore() context");
        return -1;
    }
    if ((retval = handle_session_persistence(ctx, out_session))) {
        LOG(ERROR, "Could not restore session data");
    }
    avs_persistence_context_delete(ctx);
    return retval;
}
