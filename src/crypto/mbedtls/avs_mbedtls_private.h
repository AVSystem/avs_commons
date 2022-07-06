/*
 * Copyright 2022 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_CRYPTO_MBEDTLS_PRIVATE_H
#define AVS_COMMONS_CRYPTO_MBEDTLS_PRIVATE_H

#include <string.h>

#include <mbedtls/version.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
#    include <mbedtls/asn1.h>
#    include <mbedtls/x509_csr.h>
#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)

#if (defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
     || defined(AVS_COMMONS_WITH_AVS_NET))                  \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
#    include <mbedtls/x509_crt.h>
#endif // (defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) ||
       // defined(AVS_COMMONS_WITH_AVS_NET)) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)

#ifdef AVS_COMMONS_WITH_AVS_NET
#    include <mbedtls/ssl.h>
#endif // AVS_COMMONS_WITH_AVS_NET

#include <avsystem/commons/avs_time.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
#    include <mbedtls/private_access.h>
#    if MBEDTLS_VERSION_NUMBER >= 0x03010000
#        define MBEDTLS_PRIVATE_BETWEEN_30_31(Member) Member
#    else // MBEDTLS_VERSION_NUMBER >= 0x03010000
#        define MBEDTLS_PRIVATE_BETWEEN_30_31(Member) MBEDTLS_PRIVATE(Member)
#    endif // MBEDTLS_VERSION_NUMBER >= 0x03010000
#else      // MBEDTLS_VERSION_NUMBER >= 0x03000000
#    define MBEDTLS_PRIVATE(Member) Member
#    define MBEDTLS_PRIVATE_BETWEEN_30_31(Member) Member
#endif // MBEDTLS_VERSION_NUMBER >= 0x03000000

// NOTE: This files encapsulates accesses to MBEDTLS_PRIVATE(). These are
// necessary due to proper public APIs being unavailable in Mbed TLS 3.0.

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
static inline void _avs_crypto_mbedtls_asn1_buf_init(mbedtls_asn1_buf *buf,
                                                     int tag,
                                                     unsigned char *p,
                                                     size_t len) {
    memset(buf, 0, sizeof(*buf));
    buf->MBEDTLS_PRIVATE_BETWEEN_30_31(tag) = tag;
    buf->MBEDTLS_PRIVATE_BETWEEN_30_31(len) = len;
    buf->MBEDTLS_PRIVATE_BETWEEN_30_31(p) = p;
}

static inline void
_avs_crypto_mbedtls_asn1_named_data_set_tag(mbedtls_asn1_named_data *data,
                                            int tag) {
    data->MBEDTLS_PRIVATE_BETWEEN_30_31(val).MBEDTLS_PRIVATE_BETWEEN_30_31(
            tag) = tag;
}

static inline void _avs_crypto_mbedtls_x509write_csr_set_subject(
        mbedtls_x509write_csr *csr, mbedtls_asn1_named_data *subject) {
    csr->MBEDTLS_PRIVATE(subject) = subject;
}

static inline const mbedtls_x509_time *
_avs_crypto_mbedtls_x509_crt_get_valid_to(const mbedtls_x509_crt *crt) {
    return &crt->MBEDTLS_PRIVATE_BETWEEN_30_31(valid_to);
}

avs_time_real_t
_avs_crypto_mbedtls_x509_time_to_avs_time(const mbedtls_x509_time *x509_time);

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)

#if (defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
     || defined(AVS_COMMONS_WITH_AVS_NET))                  \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
static inline bool
_avs_crypto_mbedtls_x509_crt_present(const mbedtls_x509_crt *crt) {
    return crt->MBEDTLS_PRIVATE_BETWEEN_30_31(version) != 0;
}
#endif // (defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) ||
       // defined(AVS_COMMONS_WITH_AVS_NET)) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)

#if defined(AVS_COMMONS_WITH_AVS_NET) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
static inline mbedtls_x509_crt **
_avs_crypto_mbedtls_x509_crt_next_ptr(mbedtls_x509_crt *crt) {
    return &crt->MBEDTLS_PRIVATE_BETWEEN_30_31(next);
}
static inline void
_avs_crypto_mbedtls_x509_crt_get_raw(const mbedtls_x509_crt *crt,
                                     const unsigned char **out_buf,
                                     size_t *out_len) {
    *out_buf = crt->MBEDTLS_PRIVATE_BETWEEN_30_31(raw)
                       .MBEDTLS_PRIVATE_BETWEEN_30_31(p);
    *out_len = crt->MBEDTLS_PRIVATE_BETWEEN_30_31(raw)
                       .MBEDTLS_PRIVATE_BETWEEN_30_31(len);
}

static inline mbedtls_pk_context *
_avs_crypto_mbedtls_x509_crt_get_pk(mbedtls_x509_crt *crt) {
    return &crt->MBEDTLS_PRIVATE_BETWEEN_30_31(pk);
}
#endif // defined(AVS_COMMONS_WITH_AVS_NET) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)

#ifdef AVS_COMMONS_WITH_AVS_NET
static inline int
_avs_crypto_mbedtls_ssl_context_get_current_alert(mbedtls_ssl_context *ctx,
                                                  uint8_t *out_level,
                                                  uint8_t *out_description) {
    // https://tools.ietf.org/html/rfc5246#section-6.2.1
    if (ctx->MBEDTLS_PRIVATE(in_msgtype) != 21) {
        return -1;
    }
    *out_level = ctx->MBEDTLS_PRIVATE(in_msg)[0];
    *out_description = ctx->MBEDTLS_PRIVATE(in_msg)[1];
    return 0;
}

static inline const mbedtls_cipher_info_t *
_avs_crypto_mbedtls_cipher_info_from_ciphersuite(
        const mbedtls_ssl_ciphersuite_t *ciphersuite) {
    return mbedtls_cipher_info_from_type(
            (mbedtls_cipher_type_t) ciphersuite->MBEDTLS_PRIVATE(cipher));
}

static inline mbedtls_cipher_mode_t
_avs_crypto_mbedtls_cipher_info_get_mode(const mbedtls_cipher_info_t *cipher) {
    return cipher->MBEDTLS_PRIVATE(mode);
}

static inline unsigned int
_avs_crypto_mbedtls_cipher_get_block_size(const mbedtls_cipher_info_t *cipher) {
    return cipher->MBEDTLS_PRIVATE(block_size);
}
#endif // AVS_COMMONS_WITH_AVS_NET

#if defined(AVS_COMMONS_WITH_AVS_NET) \
        && defined(MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
static inline void
_avs_crypto_mbedtls_ssl_session_unexport(mbedtls_ssl_context *ctx) {
    assert(ctx);
    assert(ctx->MBEDTLS_PRIVATE(session));
    ctx->MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(exported) = false;
}
#endif // defined(AVS_COMMONS_WITH_AVS_NET) &&
       // defined(MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)

#if !defined(AVS_COMMONS_CRYPTO_MBEDTLS_PRIVATE_C) && !defined(AVS_UNIT_TESTING)
// Make it impossible to use MBEDTLS_PRIVATE outside of this file
#    undef MBEDTLS_PRIVATE_BETWEEN_30_31
#    undef MBEDTLS_PRIVATE
#endif // !defined(AVS_COMMONS_CRYPTO_MBEDTLS_PRIVATE_C) &&
       // !defined(AVS_UNIT_TESTING)

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_CRYPTO_MBEDTLS_PRIVATE_H */
