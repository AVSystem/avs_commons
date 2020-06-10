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

    mbedtls_ecp_group_id group_id;
    const mbedtls_ecp_curve_info *curve_info = NULL;
    if (!mbedtls_oid_get_ec_grp(&(const mbedtls_asn1_buf) {
                                    .tag = MBEDTLS_ASN1_OID,
                                    .len = cast_group_oid[1],
                                    .p = &cast_group_oid[2]
                                },
                                &group_id)) {
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

    avs_error_t err = avs_errno(AVS_EPROTO);
    if ((result = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(pk_ctx),
                                      mbedtls_ctr_drbg_random,
                                      &prng_ctx->mbedtls_prng_ctx))) {
        LOG(ERROR, _("mbedtls_ecp_gen_key() failed: ") "%d", result);
    } else {
        unsigned char *cast_buffer = (unsigned char *) out_der_secret_key;
        if ((result = mbedtls_pk_write_key_der(&pk_ctx, cast_buffer,
                                               *inout_der_secret_key_size))
                < 0) {
            LOG(ERROR, _("mbedtls_pk_write_key_der() failed: ") "%d", result);
        } else {
            move_der_data_to_start(cast_buffer, inout_der_secret_key_size,
                                   (size_t) result);
            err = AVS_OK;
        }
    }

    mbedtls_pk_free(&pk_ctx);
    return err;
}

avs_error_t
avs_crypto_pki_csr_create(avs_crypto_prng_ctx_t *prng_ctx,
                          const avs_crypto_client_key_info_t *private_key_info,
                          const char *md_name,
                          const char *subject_name,
                          void *out_der_csr,
                          size_t *inout_der_csr_size) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(md_name);
    if (!md_info) {
        LOG(ERROR, _("Mbed TLS does not have MD info for ") "%s", md_name);
        return avs_errno(AVS_ENOTSUP);
    }

    mbedtls_x509write_csr csr_ctx;
    mbedtls_x509write_csr_init(&csr_ctx);

    mbedtls_x509write_csr_set_md_alg(&csr_ctx, mbedtls_md_get_type(md_info));

    avs_error_t err = AVS_OK;
    int result = mbedtls_x509write_csr_set_subject_name(&csr_ctx, subject_name);
    if (result) {
        LOG(ERROR, _("mbedtls_x509write_csr_set_subject_name() failed: ") "%d",
            result);
        err = avs_errno(AVS_EPROTO);
    }

    mbedtls_pk_context *private_key = NULL;

    if (avs_is_ok(err)
            && avs_is_ok((err = _avs_crypto_mbedtls_load_client_key(
                                  &private_key, private_key_info)))) {
        assert(private_key);
        mbedtls_x509write_csr_set_key(&csr_ctx, private_key);

        unsigned char *cast_buffer = (unsigned char *) out_der_csr;
        size_t buffer_size = *inout_der_csr_size;
        if ((result = mbedtls_x509write_csr_der(
                     &csr_ctx, cast_buffer, buffer_size,
                     mbedtls_ctr_drbg_random, &prng_ctx->mbedtls_prng_ctx))
                < 0) {
            LOG(ERROR, _("mbedtls_x509write_csr_der() failed: ") "%d", result);
            err = avs_errno(AVS_EPROTO);
        } else {
            move_der_data_to_start(cast_buffer, inout_der_csr_size,
                                   (size_t) result);
        }
    }

    if (private_key) {
        mbedtls_pk_free(private_key);
        avs_free(private_key);
    }
    mbedtls_x509write_csr_free(&csr_ctx);
    return err;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
