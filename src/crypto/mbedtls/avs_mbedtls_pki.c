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
    avs_error_t err =
            validate_and_cast_asn1_oid(ecp_group_oid, &ecp_group_oid_buf.p,
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
                          const avs_crypto_client_key_info_t *private_key_info,
                          const char *md_name,
                          const avs_crypto_pki_x509_name_entry_t subject[],
                          void *out_der_csr,
                          size_t *inout_der_csr_size) {
    assert(inout_der_csr_size);
    assert(!*inout_der_csr_size || out_der_csr);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(md_name);
    if (!md_info) {
        LOG(ERROR, _("Mbed TLS does not have MD info for ") "%s", md_name);
        return avs_errno(AVS_ENOTSUP);
    }

    mbedtls_x509write_csr csr_ctx;
    mbedtls_x509write_csr_init(&csr_ctx);

    mbedtls_x509write_csr_set_md_alg(&csr_ctx, mbedtls_md_get_type(md_info));

    mbedtls_pk_context *private_key = NULL;

    avs_error_t err = convert_subject(&csr_ctx.subject, subject);
    if (avs_is_ok(err)
            && avs_is_ok((err = _avs_crypto_mbedtls_load_client_key(
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

avs_time_real_t avs_crypto_client_cert_expiration_date(
        const avs_crypto_client_cert_info_t *cert_info) {
    mbedtls_x509_crt *cert = NULL;
    if (avs_is_err(_avs_crypto_mbedtls_load_client_cert(&cert, cert_info))) {
        assert(!cert);
        return AVS_TIME_REAL_INVALID;
    }

    if (!cert || cert->next) {
        LOG(ERROR, _("Wrong number of certificates loaded, expected 1"));
        return AVS_TIME_REAL_INVALID;
    }

    avs_time_real_t result = convert_x509_time(&cert->valid_to);
    _avs_crypto_mbedtls_x509_crt_cleanup(&cert);
    return result;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
