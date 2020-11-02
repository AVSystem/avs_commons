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

// NOTE: OpenSSL headers sometimes (depending on a version) contain some of the
// symbols poisoned via inclusion of avs_commons_init.h. Therefore they must
// be included before poison.
#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO)                          \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)               \
        && defined(AVS_COMMONS_WITH_OPENSSL)

#    include <string.h>

#    include <openssl/ec.h>
#    include <openssl/objects.h>
#    include <openssl/x509.h>

#    include <avs_commons_poison.h>

#    include <avsystem/commons/avs_crypto_pki.h>
#    include <avsystem/commons/avs_errno.h>

#    include "avs_openssl_common.h"
#    include "avs_openssl_data_loader.h"
#    include "avs_openssl_engine.h"
#    include "avs_openssl_prng.h"

#    include "../avs_crypto_global.h"

#    define MODULE_NAME avs_crypto_pki
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static ASN1_OBJECT *asn1_oid_to_obj(const avs_crypto_asn1_oid_t *oid) {
    const unsigned char *cast_oid = (const unsigned char *) oid;
    // See http://luca.ntop.org/Teaching/Appunti/asn1.html
    // Sections 2 and 3.1
    // First byte (identifier octet) MUST be 0x06, OBJECT IDENTIFIER
    // Second byte (length octet) MUST have bit 8 unset, indicating short form
    if (!cast_oid || cast_oid[0] != 0x06 || cast_oid[1] > 0x7f) {
        LOG(ERROR, _("something that is not a syntactically valid OID passed"));
        return NULL;
    }
    return d2i_ASN1_OBJECT(NULL, &cast_oid, cast_oid[1] + 2);
}

static int asn1_oid_to_nid(const avs_crypto_asn1_oid_t *oid) {
    int result = NID_undef;
    ASN1_OBJECT *obj = asn1_oid_to_obj(oid);
    if (obj) {
        result = OBJ_obj2nid(obj);
        ASN1_OBJECT_free(obj);
    }
    return result;
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

    if (!prng_ctx || _avs_crypto_prng_reseed_if_needed(prng_ctx)) {
        LOG(ERROR, _("PRNG context not specified or invalid"));
        return avs_errno(AVS_EINVAL);
    }

    EC_GROUP *group =
            EC_GROUP_new_by_curve_name(asn1_oid_to_nid(ecp_group_oid));
    if (!group) {
        LOG(ERROR, _("specified ECP group is invalid or not supported"));
        return avs_errno(AVS_ENOTSUP);
    }

    EC_KEY *ec_key = EC_KEY_new();
    if (!ec_key) {
        LOG(ERROR, _("EC_KEY_new() failed"));
        err = avs_errno(AVS_ENOMEM);
    } else {
        if (!EC_KEY_set_group(ec_key, group) || !EC_KEY_generate_key(ec_key)) {
            log_openssl_error();
            err = avs_errno(AVS_EPROTO);
        } else {
            int result = i2d_ECPrivateKey(ec_key, NULL);
            if (result > 0) {
                if ((size_t) result > *inout_der_secret_key_size) {
                    LOG(ERROR, _("Output buffer is too small to fit the key"));
                    err = avs_errno(AVS_E2BIG);
                } else {
                    result = i2d_ECPrivateKey(
                            ec_key,
                            &(unsigned char *[]){
                                    (unsigned char *) out_der_secret_key }[0]);
                }
            }
            if (result <= 0) {
                log_openssl_error();
                err = avs_errno(AVS_EPROTO);
            } else {
                *inout_der_secret_key_size = (size_t) result;
            }
        }
        EC_KEY_free(ec_key);
    }

    EC_GROUP_free(group);
    return err;
}

static avs_error_t
convert_subject(X509_NAME **out_x509_name,
                const avs_crypto_pki_x509_name_entry_t subject[]) {
    assert(out_x509_name && !*out_x509_name);
    if (!(*out_x509_name = X509_NAME_new())) {
        LOG(ERROR, _("X509_NAME_new() failed"));
        return avs_errno(AVS_ENOMEM);
    }

    avs_error_t err = AVS_OK;
    for (const avs_crypto_pki_x509_name_entry_t *subject_entry = subject;
         avs_is_ok(err) && subject_entry && subject_entry->key.oid;
         ++subject_entry) {
        ASN1_OBJECT *obj = asn1_oid_to_obj(subject_entry->key.oid);
        if (!obj) {
            LOG(ERROR, _("specified subject name key is invalid or unknown"));
            err = avs_errno(AVS_ENOTSUP);
        } else {
            if (!X509_NAME_add_entry_by_OBJ(
                        *out_x509_name, obj, subject_entry->key.value_id_octet,
                        (const unsigned char *) subject_entry->value,
                        subject_entry->value
                                ? (int) strlen(subject_entry->value)
                                : 0,
                        -1, 0)) {
                log_openssl_error();
                err = avs_errno(AVS_ENOMEM);
            }
            ASN1_OBJECT_free(obj);
        }
    }

    if (avs_is_err(err)) {
        X509_NAME_free(*out_x509_name);
        *out_x509_name = NULL;
    }
    return err;
}

avs_error_t
avs_crypto_pki_csr_create(avs_crypto_prng_ctx_t *prng_ctx,
                          const avs_crypto_private_key_info_t *private_key_info,
                          const char *md_name,
                          const avs_crypto_pki_x509_name_entry_t subject[],
                          void *out_der_csr,
                          size_t *inout_der_csr_size) {
    (void) prng_ctx;

    avs_error_t err = _avs_crypto_ensure_global_state();
    if (avs_is_err(err)) {
        return err;
    }

    X509_REQ *req = X509_REQ_new();
    if (!req) {
        LOG(ERROR, _("X509_REQ_new() failed"));
        return avs_errno(AVS_ENOMEM);
    }

    X509_NAME *x509_name = NULL;
    err = convert_subject(&x509_name, subject);
    if (avs_is_ok(err)) {
        if (!X509_REQ_set_subject_name(req, x509_name)) {
            log_openssl_error();
            err = avs_errno(AVS_EPROTO);
        }
        X509_NAME_free(x509_name);
    }

    EVP_PKEY *key = NULL;
    if (avs_is_ok(err)
            && avs_is_ok((err = _avs_crypto_openssl_load_private_key(
                                  &key, private_key_info)))) {
        assert(key);
        if (!X509_REQ_set_pubkey(req, key)) {
            log_openssl_error();
            err = avs_errno(AVS_EPROTO);
        }
    }

    if (avs_is_ok(err)) {
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            LOG(ERROR, _("EVP_MD_CTX_new() failed"));
            err = avs_errno(AVS_ENOMEM);
        } else {
            const EVP_MD *md = NULL;
            int default_md_nid = NID_undef;
            if (EVP_PKEY_get_default_digest_nid(key, &default_md_nid) != 2
                    || default_md_nid != NID_undef) {
                md = EVP_get_digestbyname(md_name);
                if (!md) {
                    LOG(ERROR, _("Unknown digest: ") "%s", md_name);
                    err = avs_errno(AVS_ENOTSUP);
                }
            }
            if (avs_is_ok(err)
                    && (!EVP_DigestSignInit(md_ctx, NULL, md, NULL, key)
                        || !X509_REQ_sign_ctx(req, md_ctx))) {
                log_openssl_error();
                err = avs_errno(AVS_EPROTO);
            }
            EVP_MD_CTX_free(md_ctx);
        }
    }

    if (avs_is_ok(err)) {
        int result = i2d_X509_REQ(req, NULL);
        if (result > 0) {
            if ((size_t) result > *inout_der_csr_size) {
                LOG(ERROR, _("Output buffer is too small to fit the CSR"));
                err = avs_errno(AVS_E2BIG);
            } else {
                result = i2d_X509_REQ(
                        req, &(unsigned char *[]){
                                     (unsigned char *) out_der_csr }[0]);
            }
        }
        if (result <= 0) {
            log_openssl_error();
            err = avs_errno(AVS_EPROTO);
        } else {
            *inout_der_csr_size = (size_t) result;
        }
    }

    EVP_PKEY_free(key);
    X509_REQ_free(req);
    return err;
}

avs_time_real_t avs_crypto_certificate_expiration_date(
        const avs_crypto_certificate_chain_info_t *cert_info) {
    if (avs_is_err(_avs_crypto_ensure_global_state())) {
        return AVS_TIME_REAL_INVALID;
    }
    avs_time_real_t result = AVS_TIME_REAL_INVALID;
    X509 *cert = NULL;
    if (avs_is_err(
                _avs_crypto_openssl_load_first_client_cert(&cert, cert_info))) {
        assert(!cert);
    } else {
        assert(cert);
        const ASN1_TIME *valid_until = X509_get0_notAfter(cert);
        if (valid_until) {
            static const struct tm EPOCH_TM = {
                .tm_mday = 1,
                .tm_mon = 0,
                .tm_year = 70
            };
            struct tm valid_until_tm = { 0 };
            int days, secs;
            if (ASN1_TIME_to_tm(valid_until, &valid_until_tm) == 1
                    && OPENSSL_gmtime_diff(&days, &secs, &EPOCH_TM,
                                           &valid_until_tm)) {
                result = (avs_time_real_t) {
                    .since_real_epoch.seconds =
                            86400 * (int64_t) days + (int64_t) secs
                };
            }
        }
        X509_free(cert);
        if (!avs_time_real_valid(result)) {
            LOG(ERROR, _("No valid NotAfter field in the certificate"));
        }
    }
    return result;
}

#    ifdef AVS_COMMONS_WITH_AVS_LIST
static avs_error_t copy_cert(AVS_LIST(avs_crypto_certificate_chain_info_t) *out,
                             X509 *cert) {
    assert(out && !*out);
    int result = i2d_X509(cert, NULL);
    if (result > 0) {
        if (!(*out = (AVS_LIST(avs_crypto_certificate_chain_info_t))
                      AVS_LIST_NEW_BUFFER(
                              sizeof(avs_crypto_certificate_chain_info_t)
                              + (size_t) result))) {
            LOG(ERROR, _("Out of memory"));
            return avs_errno(AVS_ENOMEM);
        }
        unsigned char *buf = ((unsigned char *) *out)
                             + sizeof(avs_crypto_certificate_chain_info_t);
        **out = avs_crypto_certificate_chain_info_from_buffer(buf,
                                                              (size_t) result);
        result = i2d_X509(cert, &(unsigned char *[]){ buf }[0]);
    }
    if (result <= 0) {
        log_openssl_error();
        AVS_LIST_CLEAR(out);
        return avs_errno(AVS_EPROTO);
    }
    return AVS_OK;
}

static avs_error_t
copy_crl(AVS_LIST(avs_crypto_cert_revocation_list_info_t) *out, X509_CRL *crl) {
    assert(out && !*out);
    int result = i2d_X509_CRL(crl, NULL);
    if (result > 0) {
        if (!(*out = (AVS_LIST(avs_crypto_cert_revocation_list_info_t))
                      AVS_LIST_NEW_BUFFER(
                              sizeof(avs_crypto_cert_revocation_list_info_t)
                              + (size_t) result))) {
            LOG(ERROR, _("Out of memory"));
            return avs_errno(AVS_ENOMEM);
        }
        unsigned char *buf = ((unsigned char *) *out)
                             + sizeof(avs_crypto_cert_revocation_list_info_t);
        **out = avs_crypto_cert_revocation_list_info_from_buffer(
                buf, (size_t) result);
        result = i2d_X509_CRL(crl, &(unsigned char *[]){ buf }[0]);
    }
    if (result <= 0) {
        log_openssl_error();
        AVS_LIST_CLEAR(out);
        return avs_errno(AVS_EPROTO);
    }
    return AVS_OK;
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
    BIO *bio = BIO_new_mem_buf((void *) (intptr_t) buffer, (int) buffer_size);
    if (!bio) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }
    PKCS7 *p7 = d2i_PKCS7_bio(bio, NULL);
    BIO_free(bio);
    if (!p7) {
        log_openssl_error();
        return avs_errno(AVS_EPROTO);
    }

    err = avs_errno(AVS_EPROTO);
    if (OBJ_obj2nid(p7->type) != NID_pkcs7_signed) {
        LOG(ERROR, _("CMS Type for PKCS#7 certs-only MUST be SignedData"));
        goto finish;
    }
    if (p7->d.sign) {
        if (sk_PKCS7_SIGNER_INFO_num(p7->d.sign->signer_info) > 0) {
            LOG(ERROR,
                _("signerInfos field for PKCS#7 certs-only MUST be empty"));
            goto finish;
        }
        if (p7->d.sign->contents
                && (OBJ_obj2nid(p7->d.sign->contents->type) != NID_pkcs7_data
                    || p7->d.sign->contents->length > 0)) {
            LOG(ERROR,
                _("Encapsulated content for PKCS#7 certs-only MUST be absent"));
            goto finish;
        }

        AVS_LIST(avs_crypto_certificate_chain_info_t) *certs_tail_ptr =
                out_certs;
        for (int i = 0; i < sk_X509_num(p7->d.sign->cert); ++i) {
            X509 *cert = sk_X509_value(p7->d.sign->cert, i);
            if (avs_is_err((err = copy_cert(certs_tail_ptr, cert)))) {
                goto finish;
            }
            AVS_LIST_ADVANCE_PTR(&certs_tail_ptr);
        }
        AVS_LIST(avs_crypto_cert_revocation_list_info_t) *crls_tail_ptr =
                out_crls;
        for (int i = 0; i < sk_X509_CRL_num(p7->d.sign->crl); ++i) {
            X509_CRL *crl = sk_X509_CRL_value(p7->d.sign->crl, i);
            if (avs_is_err((err = copy_crl(crls_tail_ptr, crl)))) {
                goto finish;
            }
            AVS_LIST_ADVANCE_PTR(&crls_tail_ptr);
        }
    }
finish:
    PKCS7_free(p7);
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
       // defined(AVS_COMMONS_WITH_OPENSSL)
