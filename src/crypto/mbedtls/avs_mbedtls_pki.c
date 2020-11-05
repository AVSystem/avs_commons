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

#ifdef AVS_UNIT_TESTING
#    define _GNU_SOURCE // for timegm() in tests
#endif

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO)                          \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)               \
        && defined(AVS_COMMONS_WITH_MBEDTLS)

#    include <assert.h>
#    include <inttypes.h>
#    include <string.h>

#    include <mbedtls/asn1write.h>
#    include <mbedtls/ecp.h>
#    include <mbedtls/md_internal.h>
#    include <mbedtls/oid.h>
#    include <mbedtls/pk.h>
#    include <mbedtls/x509_csr.h>

#    include <avsystem/commons/avs_crypto_pki.h>
#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>

#    include "avs_mbedtls_data_loader.h"
#    include "avs_mbedtls_prng.h"

#    include "../avs_crypto_global.h"

#    define MODULE_NAME avs_crypto_pki
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static avs_error_t validate_and_cast_asn1_oid(const avs_crypto_asn1_oid_t *oid,
                                              unsigned char **out_ptr,
                                              size_t *out_size) {
    // "const-cast" due to non-const field in mbedtls_asn1_buf
    unsigned char *cast_oid = (unsigned char *) (intptr_t) oid;
    // See http://luca.ntop.org/Teaching/Appunti/asn1.html
    // Sections 2 and 3.1
    // First byte (identifier octet) MUST be 0x06, OBJECT IDENTIFIER
    // Second byte (length octet) MUST have bit 8 unset, indicating short form
    if (!cast_oid || cast_oid[0] != MBEDTLS_ASN1_OID || cast_oid[1] > 0x7f) {
        LOG(ERROR, _("something that is not a syntactically valid OID passed"));
        return avs_errno(AVS_EINVAL);
    }
    *out_ptr = &cast_oid[2];
    *out_size = cast_oid[1];
    return AVS_OK;
}

static void move_der_data_to_start(unsigned char *out_buffer,
                                   size_t *inout_buffer_size,
                                   size_t data_size) {
    size_t buffer_size = *inout_buffer_size;
    assert(data_size <= buffer_size);

    // mbedtls_*write_*_der() weirdly put the result at the end of the buffer
    // let's move it back to the front
    memmove(out_buffer, &out_buffer[buffer_size - data_size], data_size);

    // zero out the rest of bufer to avoid keeping stray copies of
    // sensitive keys in memory
    memset(&out_buffer[data_size], 0, buffer_size - data_size);

    *inout_buffer_size = data_size;
}

avs_error_t avs_crypto_pki_ec_gen(avs_crypto_prng_ctx_t *prng_ctx,
                                  const avs_crypto_asn1_oid_t *ecp_group_oid,
                                  void *out_der_secret_key,
                                  size_t *inout_der_secret_key_size) {
    assert(inout_der_secret_key_size);
    assert(!*inout_der_secret_key_size || out_der_secret_key);

    avs_error_t err = _avs_crypto_ensure_global_state();
    if (avs_is_err(err)) {
        return err;
    }

    if (!prng_ctx) {
        LOG(ERROR, _("PRNG context not specified"));
        return avs_errno(AVS_EINVAL);
    }

    const mbedtls_pk_info_t *pk_info =
            mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    if (!pk_info) {
        LOG(ERROR, _("Mbed TLS does not have PK info for MBEDTLS_PK_ECKEY"));
        return avs_errno(AVS_ENOTSUP);
    }

    // "const-cast" due to non-const field in mbedtls_asn1_buf
    unsigned char *cast_group_oid = (unsigned char *) (intptr_t) ecp_group_oid;
    // See http://luca.ntop.org/Teaching/Appunti/asn1.html
    // Sections 2 and 3.1
    // First byte (identifier octet) MUST be 0x06, OBJECT IDENTIFIER
    // Second byte (length octet) MUST have bit 8 unset, indicating short form
    if (!cast_group_oid || cast_group_oid[0] != MBEDTLS_ASN1_OID
            || cast_group_oid[1] > 0x7f) {
        LOG(ERROR, _("ecp_group_asn1_oid is not a syntactically valid OID"));
        return avs_errno(AVS_EINVAL);
    }

    mbedtls_asn1_buf ecp_group_oid_buf = {
        .tag = MBEDTLS_ASN1_OID
    };
    err = validate_and_cast_asn1_oid(ecp_group_oid, &ecp_group_oid_buf.p,
                                     &ecp_group_oid_buf.len);
    if (avs_is_err(err)) {
        return err;
    }

    mbedtls_ecp_group_id group_id;
    const mbedtls_ecp_curve_info *curve_info = NULL;
    if (!mbedtls_oid_get_ec_grp(&ecp_group_oid_buf, &group_id)) {
        curve_info = mbedtls_ecp_curve_info_from_grp_id(group_id);
    }
    if (!curve_info) {
        LOG(ERROR, _("specified ECP group is not supported"));
        return avs_errno(AVS_ENOTSUP);
    }

    mbedtls_pk_context pk_ctx;
    mbedtls_pk_init(&pk_ctx);
    int result = mbedtls_pk_setup(&pk_ctx, pk_info);
    if (result) {
        LOG(ERROR, _("mbedtls_pk_setup() failed: ") "%d", result);
        return avs_errno(AVS_ENOMEM);
    }

    if ((result = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(pk_ctx),
                                      mbedtls_ctr_drbg_random,
                                      &prng_ctx->mbedtls_prng_ctx))) {
        LOG(ERROR, _("mbedtls_ecp_gen_key() failed: ") "%d", result);
        err = avs_errno(AVS_EPROTO);
    } else {
        unsigned char *cast_buffer = (unsigned char *) out_der_secret_key;
        if ((result = mbedtls_pk_write_key_der(&pk_ctx, cast_buffer,
                                               *inout_der_secret_key_size))
                < 0) {
            LOG(ERROR, _("mbedtls_pk_write_key_der() failed: ") "%d", result);
            err = avs_errno(AVS_EPROTO);
        } else {
            move_der_data_to_start(cast_buffer, inout_der_secret_key_size,
                                   (size_t) result);
        }
    }

    mbedtls_pk_free(&pk_ctx);
    return err;
}

static avs_error_t
convert_subject(mbedtls_asn1_named_data **out_mbedtls_subject,
                const avs_crypto_pki_x509_name_entry_t subject[]) {
    for (const avs_crypto_pki_x509_name_entry_t *subject_entry = subject;
         subject_entry && subject_entry->key.oid;
         ++subject_entry) {
        unsigned char *oid;
        size_t oid_len;
        avs_error_t err = validate_and_cast_asn1_oid(subject_entry->key.oid,
                                                     &oid, &oid_len);
        if (avs_is_err(err)) {
            return err;
        }
        mbedtls_asn1_named_data *entry = mbedtls_asn1_store_named_data(
                out_mbedtls_subject, (const char *) oid, oid_len,
                (const unsigned char *) subject_entry->value,
                subject_entry->value ? strlen(subject_entry->value) : 0);
        if (!entry) {
            LOG(ERROR, _("mbedtls_asn1_store_named_data() failed"));
            return avs_errno(AVS_ENOMEM);
        }
        entry->val.tag = subject_entry->key.value_id_octet;
    }
    return AVS_OK;
}

avs_error_t
avs_crypto_pki_csr_create(avs_crypto_prng_ctx_t *prng_ctx,
                          const avs_crypto_private_key_info_t *private_key_info,
                          const char *md_name,
                          const avs_crypto_pki_x509_name_entry_t subject[],
                          void *out_der_csr,
                          size_t *inout_der_csr_size) {
    assert(inout_der_csr_size);
    assert(!*inout_der_csr_size || out_der_csr);

    avs_error_t err = _avs_crypto_ensure_global_state();
    if (avs_is_err(err)) {
        return err;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(md_name);
    if (!md_info) {
        LOG(ERROR, _("Mbed TLS does not have MD info for ") "%s", md_name);
        return avs_errno(AVS_ENOTSUP);
    }

    mbedtls_x509write_csr csr_ctx;
    mbedtls_x509write_csr_init(&csr_ctx);

    mbedtls_x509write_csr_set_md_alg(&csr_ctx, mbedtls_md_get_type(md_info));

    mbedtls_pk_context *private_key = NULL;

    err = convert_subject(&csr_ctx.subject, subject);
    if (avs_is_ok(err)
            && avs_is_ok((err = _avs_crypto_mbedtls_load_private_key(
                                  &private_key, private_key_info)))) {
        assert(private_key);
        mbedtls_x509write_csr_set_key(&csr_ctx, private_key);

        unsigned char *cast_buffer = (unsigned char *) out_der_csr;
        size_t buffer_size = *inout_der_csr_size;
        int result =
                mbedtls_x509write_csr_der(&csr_ctx, cast_buffer, buffer_size,
                                          mbedtls_ctr_drbg_random,
                                          &prng_ctx->mbedtls_prng_ctx);
        if (result < 0) {
            LOG(ERROR, _("mbedtls_x509write_csr_der() failed: ") "%d", result);
            err = avs_errno(AVS_EPROTO);
        } else {
            move_der_data_to_start(cast_buffer, inout_der_csr_size,
                                   (size_t) result);
        }
    }

    _avs_crypto_mbedtls_pk_context_cleanup(&private_key);
    mbedtls_x509write_csr_free(&csr_ctx);
    return err;
}

static int64_t year_to_days(int year, bool *out_is_leap) {
    // NOTE: Gregorian calendar rules are used proleptically here, which means
    // that dates before 1583 will not align with historical documents. Negative
    // dates handling might also be confusing (i.e. year == -1 means 2 BC).
    //
    // These rules are, however, consistent with the ISO 8601 convention that
    // ASN.1 GeneralizedTime type references, not to mention that X.509
    // certificates are generally not expected to contain dates before 1583 ;)

    static const int64_t LEAP_YEARS_IN_CYCLE = 97;
    static const int64_t LEAP_YEARS_UNTIL_1970 = 478;

    *out_is_leap = ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0);

    int cycles = year / 400;
    int years_since_cycle_start = year % 400;
    if (years_since_cycle_start < 0) {
        --cycles;
        years_since_cycle_start += 400;
    }

    int leap_years_since_cycle_start = (*out_is_leap ? 0 : 1)
                                       + years_since_cycle_start / 4
                                       - years_since_cycle_start / 100;
    int64_t leap_years_since_1970 = cycles * LEAP_YEARS_IN_CYCLE
                                    + leap_years_since_cycle_start
                                    - LEAP_YEARS_UNTIL_1970;
    return (year - 1970) * 365 + leap_years_since_1970;
}

static int month_to_days(int month, bool is_leap) {
    static const uint16_t MONTH_LENGTHS[] = {
        31, 28 /* or 29 */, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    int days = (is_leap && month > 2) ? 1 : 0;
    for (int i = 0; i < month - 1; ++i) {
        days += MONTH_LENGTHS[i];
    }
    return days;
}

static avs_time_real_t convert_x509_time(const mbedtls_x509_time *x509_time) {
    if (x509_time->mon < 1 || x509_time->mon > 12 || x509_time->day < 1
            || x509_time->day > 31 || x509_time->hour < 0
            || x509_time->hour > 23 || x509_time->min < 0 || x509_time->min > 59
            || x509_time->sec < 0
            || x509_time->sec > 60 /* support leap seconds */) {
        LOG(ERROR, _("Invalid X.509 time value"));
        return AVS_TIME_REAL_INVALID;
    }
    bool is_leap;
    int64_t days = year_to_days(x509_time->year, &is_leap)
                   + month_to_days(x509_time->mon, is_leap) + x509_time->day
                   - 1;
    int64_t time =
            60 * (60 * x509_time->hour + x509_time->min) + x509_time->sec;
    return (avs_time_real_t) {
        .since_real_epoch.seconds = days * 86400 + time
    };
}

avs_time_real_t avs_crypto_certificate_expiration_date(
        const avs_crypto_certificate_chain_info_t *cert_info) {
    if (avs_is_err(_avs_crypto_ensure_global_state())) {
        return AVS_TIME_REAL_INVALID;
    }

    mbedtls_x509_crt *cert = NULL;
    if (avs_is_err(_avs_crypto_mbedtls_load_certs(&cert, cert_info))) {
        assert(!cert);
        return AVS_TIME_REAL_INVALID;
    }

    assert(cert);
    if (!cert->version) {
        LOG(ERROR, _("No valid certificate loaded"));
        return AVS_TIME_REAL_INVALID;
    }

    avs_time_real_t result = convert_x509_time(&cert->valid_to);
    _avs_crypto_mbedtls_x509_crt_cleanup(&cert);
    return result;
}

#    ifdef AVS_COMMONS_WITH_AVS_LIST
// NOTE: In the comments to functions below, we are using RFC 2315 definitions
// for the PKCS#7 syntax elements. These are formally obsolete (the current
// version is defined in RFC 5652), but we don't support any structures
// supported in newer versions anyway, so it's simpler this way.

static int process_ber_length(unsigned char **p,
                              const unsigned char *end,
                              long *out_len,
                              int result,
                              size_t ulen) {
    if (result == MBEDTLS_ERR_ASN1_INVALID_LENGTH && *p < end && **p == 0x80) {
        // BER indefinite length
        ++*p;
        *out_len = -1;
        return 0;
    }
    if (!result) {
        if (ulen > LONG_MAX) {
            return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
        }
        *out_len = (long) ulen;
    }
    return result;
}

static int
get_ber_tag(unsigned char **p, const unsigned char *end, long *len, int tag) {
    // This is like mbedtls_asn1_get_tag() but allows BER indefinite length;
    // that's why the len parameter is a signed type here.
    size_t ulen;
    int result = mbedtls_asn1_get_tag(p, end, &ulen, tag);
    return process_ber_length(p, end, len, result, ulen);
}

#        define ASN1_BER_EOC_TAG 0x00

static avs_error_t pkcs7_inner_content_info_verify(unsigned char **p,
                                                   const unsigned char *end) {
    // ContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   content
    //     [0] EXPLICIT ANY DEFINED BY contentType }
    //
    // ContentType ::= OBJECT IDENTIFIER
    static const unsigned char ID_DATA_OID[] = { 0x06, 0x09, 0x2A, 0x86,
                                                 0x48, 0x86, 0xF7, 0x0D,
                                                 0x01, 0x07, 0x01 };

    long len;
    if (get_ber_tag(p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
            || (len >= 0 && len != sizeof(ID_DATA_OID))
            || *p + sizeof(ID_DATA_OID) > end
            || memcmp(*p, ID_DATA_OID, sizeof(ID_DATA_OID)) != 0) {
        goto malformed;
    }

    *p += sizeof(ID_DATA_OID);

    // for indefinite-length encoding, we expect EOC here
    if (len < 0 && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG) || len != 0)) {
        goto malformed;
    }

    return AVS_OK;
malformed:
    LOG(ERROR, _("Encapsulated content for PKCS#7 certs-only MUST be absent"));
    return avs_errno(AVS_EPROTO);
}

static avs_error_t
copy_security_info(AVS_LIST(avs_crypto_security_info_union_t) *out,
                   const unsigned char *p,
                   const unsigned char *end,
                   avs_crypto_security_info_tag_t tag) {
    assert(out && !*out);
    size_t size = (size_t) (end - p);
    AVS_LIST(avs_crypto_security_info_union_t) element =
            (AVS_LIST(avs_crypto_security_info_union_t)) AVS_LIST_NEW_BUFFER(
                    sizeof(avs_crypto_security_info_union_t) + size);
    if (!element) {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }
    unsigned char *buf = ((unsigned char *) element)
                         + sizeof(avs_crypto_security_info_union_t);
    element->type = tag;
    element->source = AVS_CRYPTO_DATA_SOURCE_BUFFER;
    element->info.buffer.buffer = buf;
    element->info.buffer.buffer_size = size;
    memcpy(buf, p, size);
    *out = element;
    return AVS_OK;
}

static avs_error_t
pkcs7_x509_set_parse(AVS_LIST(avs_crypto_security_info_union_t) **tail_ptr_ptr,
                     unsigned char **p,
                     const unsigned char *end,
                     long set_len,
                     avs_crypto_security_info_tag_t tag) {
    // Note: we are inside an implicit SET
    while (*p < end && (set_len >= 0 || **p != ASN1_BER_EOC_TAG)) {
        unsigned char *len_ptr = *p + 1;
        size_t len;
        // We don't support indefinite length here, because Mbed TLS would not
        // be able to parse that anyway.
        if (mbedtls_asn1_get_len(&len_ptr, end, &len)
                || len > (size_t) (end - len_ptr)) {
            LOG(ERROR, _("Malformed data when parsing PKCS#7 data set"));
            return avs_errno(AVS_EPROTO);
        }

        avs_error_t err =
                copy_security_info(*tail_ptr_ptr, *p, len_ptr + len, tag);
        if (avs_is_err(err)) {
            return err;
        }

        *p = len_ptr + len;
        AVS_LIST_ADVANCE_PTR(tail_ptr_ptr);
    }
    assert(set_len < 0 || *p == end);
    return AVS_OK;
}

static avs_error_t pkcs7_signed_data_parse(
        AVS_LIST(avs_crypto_certificate_chain_info_t) *out_certs,
        AVS_LIST(avs_crypto_cert_revocation_list_info_t) *out_crls,
        unsigned char **p,
        const unsigned char *end) {
    // SignedData ::= SEQUENCE {
    //   version Version,
    //   digestAlgorithms DigestAlgorithmIdentifiers,
    //   contentInfo ContentInfo,
    //   certificates
    //      [0] IMPLICIT ExtendedCertificatesAndCertificates
    //        OPTIONAL,
    //   crls
    //     [1] IMPLICIT CertificateRevocationLists OPTIONAL,
    //   signerInfos SignerInfos }
    //
    // Version ::= INTEGER
    //
    // DigestAlgorithmIdentifiers ::=
    //   SET OF DigestAlgorithmIdentifier
    //
    // ExtendedCertificatesAndCertificates ::=
    //   SET OF ExtendedCertificateOrCertificate
    //
    // ExtendedCertificateOrCertificate ::= CHOICE {
    //   certificate Certificate, -- X.509
    //
    //   extendedCertificate [0] IMPLICIT ExtendedCertificate }
    //
    // CertificateRevocationLists ::=
    //   SET OF CertificateRevocationList
    avs_error_t err = AVS_OK;
    long signed_data_len;
    if (get_ber_tag(p, end, &signed_data_len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
            || (signed_data_len >= 0 && signed_data_len != (long) (end - *p))) {
        goto malformed;
    }

    int version;
    if (mbedtls_asn1_get_int(p, end, &version)) {
        goto malformed;
    }
    if (version != 1) {
        LOG(ERROR, _("Only version 1 of SignedData is currently supported"));
        return avs_errno(AVS_EPROTO);
    }

    // skip digestAlgorithms, we don't care about those
    long len;
    if (get_ber_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)
            || len > (long) (end - *p)) {
        goto malformed;
    }
    if (len >= 0) {
        *p += len;
    } else if (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG) || len != 0) {
        // we don't support indefinite-length digestAlgorithms properly,
        // but let's try to support zero-length case as best-effort
        goto malformed;
    }

    if (avs_is_err((err = pkcs7_inner_content_info_verify(p, end)))) {
        return err;
    }

    static const unsigned char CERTIFICATES_TAG =
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0;
    if (*p < end && **p == CERTIFICATES_TAG) {
        if (get_ber_tag(p, end, &len, CERTIFICATES_TAG)
                || len > (long) (end - *p)) {
            goto malformed;
        }
        const unsigned char *certificates_end = len >= 0 ? *p + len : end;
        if (avs_is_err((err = pkcs7_x509_set_parse(
                                (AVS_LIST(avs_crypto_security_info_union_t) *
                                         *) &out_certs,
                                p, certificates_end, len,
                                AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN)))) {
            return err;
        }
        if ((len >= 0 && *p != certificates_end)
                || (len < 0
                    && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG)
                        || len != 0))) {
            goto malformed;
        }
    }

    static const unsigned char CRLS_TAG =
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1;
    if (*p < end && **p == CRLS_TAG) {
        if (get_ber_tag(p, end, &len, CRLS_TAG) || len > (long) (end - *p)) {
            goto malformed;
        }
        const unsigned char *crls_end = len >= 0 ? *p + len : end;
        if (avs_is_err(
                    (err = pkcs7_x509_set_parse(
                             (AVS_LIST(avs_crypto_security_info_union_t) *
                                      *) &out_crls,
                             p, crls_end, len,
                             AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST)))) {
            return err;
        }
        if ((len >= 0 && *p != crls_end)
                || (len < 0
                    && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG)
                        || len != 0))) {
            goto malformed;
        }
    }

    if (get_ber_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)
            || len > (long) (end - *p)) {
        goto malformed;
    }
    if (len > 0
            || (len < 0
                && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG) || len != 0))) {
        LOG(ERROR, _("signerInfos field for PKCS#7 certs-only MUST be empty"));
        return avs_errno(AVS_EPROTO);
    }

    // for indefinite-length encoding, we expect EOC here
    if (signed_data_len < 0
            && (get_ber_tag(p, end, &signed_data_len, ASN1_BER_EOC_TAG)
                || signed_data_len != 0)) {
        goto malformed;
    }

    return AVS_OK;
malformed:
    LOG(ERROR, _("Malformed data when parsing PKCS#7 SignedData"));
    return avs_errno(AVS_EPROTO);
}

static avs_error_t pkcs7_content_info_parse(
        AVS_LIST(avs_crypto_certificate_chain_info_t) *out_certs,
        AVS_LIST(avs_crypto_cert_revocation_list_info_t) *out_crls,
        unsigned char **p,
        const unsigned char *end) {
    // ContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   content
    //     [0] EXPLICIT ANY DEFINED BY contentType }
    //
    // ContentType ::= OBJECT IDENTIFIER
    static const unsigned char SIGNED_DATA_OID[] = { 0x06, 0x09, 0x2A, 0x86,
                                                     0x48, 0x86, 0xF7, 0x0D,
                                                     0x01, 0x07, 0x02 };

    avs_error_t err = AVS_OK;
    long content_info_len;
    if (get_ber_tag(p, end, &content_info_len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
            || (content_info_len >= 0
                && content_info_len != (long) (end - *p))) {
        goto malformed;
    }

    if ((content_info_len >= 0
         && (size_t) content_info_len < sizeof(SIGNED_DATA_OID))
            || *p + sizeof(SIGNED_DATA_OID) > end
            || memcmp(*p, SIGNED_DATA_OID, sizeof(SIGNED_DATA_OID)) != 0) {
        LOG(ERROR, _("CMS Type for PKCS#7 certs-only MUST be SignedData"));
        return avs_errno(AVS_EPROTO);
    }

    *p += sizeof(SIGNED_DATA_OID);

    long len;
    if (get_ber_tag(p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC
                            | 0)
            || (len >= 0 && len != (long) (end - *p))) {
        goto malformed;
    }

    if (avs_is_err(
                (err = pkcs7_signed_data_parse(out_certs, out_crls, p, end)))) {
        return err;
    }

    // EOCs for indefinite-length encodings
    if (len < 0 && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG) || len != 0)) {
        goto malformed;
    }
    if ((content_info_len < 0
         && (get_ber_tag(p, end, &content_info_len, ASN1_BER_EOC_TAG)
             || content_info_len != 0))
            || *p != end) {
        goto malformed;
    }
    return AVS_OK;
malformed:
    LOG(ERROR, _("Malformed data when parsing PKCS#7 ContentInfo"));
    return avs_errno(AVS_EPROTO);
}

avs_error_t avs_crypto_parse_pkcs7_certs_only(
        AVS_LIST(avs_crypto_certificate_chain_info_t) *out_certs,
        AVS_LIST(avs_crypto_cert_revocation_list_info_t) *out_crls,
        const void *buffer,
        size_t buffer_size) {
    avs_error_t err = _avs_crypto_ensure_global_state();
    if (avs_is_err(err)) {
        return err;
    }

    if (!out_certs || *out_certs || !out_crls || *out_crls) {
        return avs_errno(AVS_EINVAL);
    }
    unsigned char *bufptr =
            (unsigned char *) (intptr_t) (const unsigned char *) buffer;
    err = pkcs7_content_info_parse(out_certs, out_crls, &bufptr,
                                   bufptr + buffer_size);
    if (avs_is_err(err)) {
        AVS_LIST_CLEAR(out_certs);
        AVS_LIST_CLEAR(out_crls);
    }
    return err;
}
#    endif // AVS_COMMONS_WITH_AVS_LIST

#    ifdef AVS_UNIT_TESTING
#        include "tests/crypto/mbedtls/mbedtls_pki.c"
#    endif // AVS_UNIT_TESTING

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
