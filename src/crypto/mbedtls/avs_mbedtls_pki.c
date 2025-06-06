/*
 * Copyright 2025 AVSystem <avsystem@avsystem.com>
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

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO)                          \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)               \
        && defined(AVS_COMMONS_WITH_MBEDTLS)

#    include <assert.h>
#    include <inttypes.h>
#    include <string.h>

#    include <mbedtls/asn1write.h>
#    include <mbedtls/ecp.h>
#    include <mbedtls/oid.h>
#    include <mbedtls/pk.h>
#    include <mbedtls/x509_csr.h>

#    if MBEDTLS_VERSION_NUMBER < 0x03000000
#        include <mbedtls/md_internal.h>
#    endif // MBEDTLS_VERSION_NUMBER < 0x03000000

#    include <avsystem/commons/avs_crypto_pki.h>
#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>

#    include "avs_mbedtls_data_loader.h"
#    include "avs_mbedtls_prng.h"

#    include "../avs_crypto_global.h"

#    include "avs_mbedtls_private.h"

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

    avs_crypto_mbedtls_prng_cb_t *random_cb = NULL;
    void *random_cb_arg = NULL;
    if (_avs_crypto_prng_get_random_cb(prng_ctx, &random_cb, &random_cb_arg)) {
        LOG(ERROR, _("PRNG context not valid"));
        return avs_errno(AVS_EINVAL);
    }
    assert(random_cb);

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

    unsigned char *ecp_group_oid_buf_ptr = NULL;
    size_t ecp_group_oid_buf_len = 0;
    err = validate_and_cast_asn1_oid(ecp_group_oid, &ecp_group_oid_buf_ptr,
                                     &ecp_group_oid_buf_len);
    if (avs_is_err(err)) {
        return err;
    }

    mbedtls_asn1_buf ecp_group_oid_buf;
    _avs_crypto_mbedtls_asn1_buf_init(&ecp_group_oid_buf, MBEDTLS_ASN1_OID,
                                      ecp_group_oid_buf_ptr,
                                      ecp_group_oid_buf_len);

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

    if ((result = mbedtls_ecp_gen_key(group_id, mbedtls_pk_ec(pk_ctx),
                                      random_cb, random_cb_arg))) {
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
        _avs_crypto_mbedtls_asn1_named_data_set_tag(
                entry, subject_entry->key.value_id_octet);
    }
    return AVS_OK;
}

#    define AVS_MBEDTLS_ADD_LEN_AND_RETURN_IF_ERR(l, t, func) \
        do {                                                  \
            if (((t) = (func)) < 0) {                         \
                return avs_errno(AVS_EPROTO);                 \
            } else {                                          \
                (l) += (size_t) (t);                          \
            }                                                 \
        } while (0)

static avs_error_t x509write_csr_set_ext_key_usage(
        mbedtls_x509write_csr *ctx,
        const avs_crypto_pki_x509_ext_key_usage_t ext_key_usage[]) {
    /**
     * Size of the buffer was taken from a similar function in mbedtls and it
     * seems to be big enough to hold all possible flags of extended key usage
     */
    unsigned char buf[256] = { 0 };
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;
    int tmp = 0;

    for (const avs_crypto_pki_x509_ext_key_usage_t *eku_entry = ext_key_usage;
         eku_entry && eku_entry->value;
         ++eku_entry) {
        AVS_MBEDTLS_ADD_LEN_AND_RETURN_IF_ERR(
                len, tmp,
                mbedtls_asn1_write_oid(&p, buf, eku_entry->value,
                                       strlen(eku_entry->value)));
    }

    if (len > 0) {
        AVS_MBEDTLS_ADD_LEN_AND_RETURN_IF_ERR(
                len, tmp, mbedtls_asn1_write_len(&p, buf, len));
        AVS_MBEDTLS_ADD_LEN_AND_RETURN_IF_ERR(
                len, tmp,
                mbedtls_asn1_write_tag(&p, buf,
                                       MBEDTLS_ASN1_CONSTRUCTED
                                               | MBEDTLS_ASN1_SEQUENCE));

        if (mbedtls_x509write_csr_set_extension(
                    ctx, MBEDTLS_OID_EXTENDED_KEY_USAGE,
                    MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE),
#    if MBEDTLS_VERSION_NUMBER >= 0x03000000
                    0,
#    endif // MBEDTLS_VERSION_NUMBER >= 0x03000000
                    p, len)) {
            return avs_errno(AVS_EPROTO);
        }
    }

    return AVS_OK;
}

static avs_error_t x509write_csr_set_key_usage(mbedtls_x509write_csr *csr_ctx,
                                               const unsigned char key_usage) {
    return mbedtls_x509write_csr_set_key_usage(csr_ctx, key_usage)
                   ? avs_errno(AVS_EPROTO)
                   : AVS_OK;
}
#    ifdef MBEDTLS_SHA1_C
static avs_error_t x509write_csr_set_key_id(mbedtls_x509write_csr *csr_ctx,
                                            mbedtls_pk_context *key) {
    /* + 20 bytes for the SHA1 message digest */
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE * 2 + 20];
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;
    int tmp = 0;

    AVS_MBEDTLS_ADD_LEN_AND_RETURN_IF_ERR(
            len, tmp, mbedtls_pk_write_pubkey(&p, buf, key));

    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                   buf + sizeof(buf) - len, len, buf + sizeof(buf) - 20)) {
        return avs_errno(AVS_EPROTO);
    }

    /* After writting message digest reset the p and len variables */
    p = buf + sizeof(buf) - 20;
    len = 20;

    AVS_MBEDTLS_ADD_LEN_AND_RETURN_IF_ERR(len, tmp,
                                          mbedtls_asn1_write_len(&p, buf, len));
    AVS_MBEDTLS_ADD_LEN_AND_RETURN_IF_ERR(
            len, tmp,
            mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_OCTET_STRING));

    if (mbedtls_x509write_csr_set_extension(
                csr_ctx, MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER),
#        if MBEDTLS_VERSION_NUMBER >= 0x03000000
                0,
#        endif // MBEDTLS_VERSION_NUMBER >= 0x03000000
                buf + sizeof(buf) - len, len)) {
        return avs_errno(AVS_EPROTO);
    }

    return AVS_OK;
}
#    endif // MBEDTLS_SHA1_C

static avs_error_t
x509write_csr_create_begin(mbedtls_x509write_csr *csr_ctx,
                           const char *md_name,
                           const avs_crypto_pki_x509_name_entry_t subject[]) {
    avs_error_t err = _avs_crypto_ensure_global_state();
    if (avs_is_err(err)) {
        return err;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(md_name);
    if (!md_info) {
        LOG(ERROR, _("Mbed TLS does not have MD info for ") "%s", md_name);
        return avs_errno(AVS_ENOTSUP);
    }

    mbedtls_x509write_csr_init(csr_ctx);
    mbedtls_x509write_csr_set_md_alg(csr_ctx, mbedtls_md_get_type(md_info));

    mbedtls_asn1_named_data *mbedtls_subject = NULL;
    if (avs_is_ok((err = convert_subject(&mbedtls_subject, subject)))) {
        _avs_crypto_mbedtls_x509write_csr_set_subject(csr_ctx, mbedtls_subject);
    }

    return err;
}

static avs_error_t x509write_csr_create_finish(
        mbedtls_x509write_csr *csr_ctx,
        avs_crypto_prng_ctx_t *prng_ctx,
        const avs_crypto_private_key_info_t *private_key_info,
        bool add_key_id,
        void *out_der_csr,
        size_t *inout_der_csr_size) {
    (void) add_key_id;

    assert(inout_der_csr_size);
    assert(!*inout_der_csr_size || out_der_csr);

    avs_crypto_mbedtls_prng_cb_t *random_cb = NULL;
    void *random_cb_arg = NULL;
    if (_avs_crypto_prng_get_random_cb(prng_ctx, &random_cb, &random_cb_arg)) {
        LOG(ERROR, _("PRNG context not valid"));
        return avs_errno(AVS_EINVAL);
    }
    assert(random_cb);

    mbedtls_pk_context *private_key = NULL;
    avs_error_t err;
    if (avs_is_ok((err = _avs_crypto_mbedtls_load_private_key(
                           &private_key, private_key_info, prng_ctx)))) {
        assert(private_key);
        mbedtls_x509write_csr_set_key(csr_ctx, private_key);

#    ifdef MBEDTLS_SHA1_C
        if (add_key_id) {
            if (avs_is_err((err = x509write_csr_set_key_id(csr_ctx,
                                                           private_key)))) {
                goto cleanup;
            }
        }
#    endif // MBEDTLS_SHA1_C

        unsigned char *cast_buffer = (unsigned char *) out_der_csr;
        size_t buffer_size = *inout_der_csr_size;
        int result =
                mbedtls_x509write_csr_der(csr_ctx, cast_buffer, buffer_size,
                                          random_cb, random_cb_arg);
        if (result < 0) {
            LOG(ERROR, _("mbedtls_x509write_csr_der() failed: ") "%d", result);
            err = avs_errno(AVS_EPROTO);
        } else {
            move_der_data_to_start(cast_buffer, inout_der_csr_size,
                                   (size_t) result);
        }
    }
cleanup:
    _avs_crypto_mbedtls_pk_context_cleanup(&private_key);

    return err;
}

avs_error_t
avs_crypto_pki_csr_create(avs_crypto_prng_ctx_t *prng_ctx,
                          const avs_crypto_private_key_info_t *private_key_info,
                          const char *md_name,
                          const avs_crypto_pki_x509_name_entry_t subject[],
                          void *out_der_csr,
                          size_t *inout_der_csr_size) {
    mbedtls_x509write_csr csr_ctx;

    avs_error_t err;
    if (avs_is_ok((err = x509write_csr_create_begin(&csr_ctx, md_name,
                                                    subject)))) {
        err = x509write_csr_create_finish(&csr_ctx, prng_ctx, private_key_info,
                                          false, out_der_csr,
                                          inout_der_csr_size);
    }

    mbedtls_x509write_csr_free(&csr_ctx);
    return err;
}

avs_error_t avs_crypto_pki_csr_create_ext(
        avs_crypto_prng_ctx_t *prng_ctx,
        const avs_crypto_private_key_info_t *private_key_info,
        const char *md_name,
        const avs_crypto_pki_x509_name_entry_t subject[],
        const unsigned char *const key_usage,
        const avs_crypto_pki_x509_ext_key_usage_t ext_key_usage[],
        const bool add_key_id,
        void *out_der_csr,
        size_t *inout_der_csr_size) {
    mbedtls_x509write_csr csr_ctx;

    avs_error_t err;
    if (avs_is_ok(
                (err = x509write_csr_create_begin(&csr_ctx, md_name, subject)))
            && avs_is_ok((err = x509write_csr_set_ext_key_usage(&csr_ctx,
                                                                ext_key_usage)))
            && (!key_usage
                || avs_is_ok((err = x509write_csr_set_key_usage(
                                      &csr_ctx, *key_usage))))) {
        err = x509write_csr_create_finish(&csr_ctx, prng_ctx, private_key_info,
                                          add_key_id, out_der_csr,
                                          inout_der_csr_size);
    }

    mbedtls_x509write_csr_free(&csr_ctx);
    return err;
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
    if (!_avs_crypto_mbedtls_x509_crt_present(cert)) {
        LOG(ERROR, _("No valid certificate loaded"));
        return AVS_TIME_REAL_INVALID;
    }

    // NOTE: In Mbed TLS 3.0, there is no public API to examine the validity
    // time of a certificate.
    avs_time_real_t result = _avs_crypto_mbedtls_x509_time_to_avs_time(
            _avs_crypto_mbedtls_x509_crt_get_valid_to(cert));
    if (!avs_time_real_valid(result)) {
        LOG(ERROR, _("Invalid X.509 time value"));
    }
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
        LOG_OOM();
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

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
