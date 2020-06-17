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

#    include <inttypes.h>
#    include <string.h>

#    include <mbedtls/ecp.h>
#    include <mbedtls/oid.h>
#    include <mbedtls/pk.h>

#    include <avsystem/commons/avs_crypto_pki.h>
#    include <avsystem/commons/avs_errno.h>

#    include "avs_mbedtls_prng.h"

#    define MODULE_NAME avs_crypto_pki
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static avs_error_t wrap_mbedtls_pk_write_der_impl(
        int (*write_func)(mbedtls_pk_context *, unsigned char *, size_t),
        const char *write_func_name,
        mbedtls_pk_context *pk_ctx,
        void *out_buffer,
        size_t *inout_buffer_size) {
    unsigned char *cast_buffer = (unsigned char *) out_buffer;
    size_t buffer_size = *inout_buffer_size;
    int result = write_func(pk_ctx, cast_buffer, buffer_size);
    if (result < 0) {
        LOG(ERROR, "%s" _("() failed: ") "%d", write_func_name, result);
        return avs_errno(AVS_EPROTO);
    }

    size_t key_size = (size_t) result;
    assert(key_size <= buffer_size);

    // mbedtls_pk_write_*_der() weirdly puts the result at the end of the buffer
    // let's move it back to the front
    memmove(cast_buffer, &cast_buffer[buffer_size - key_size], key_size);

    // zero out the rest of bufer to avoid keeping stray copies of
    // sensitive keys in memory
    memset(&cast_buffer[key_size], 0, buffer_size - key_size);

    *inout_buffer_size = key_size;
    return AVS_OK;
}

#    define wrap_mbedtls_pk_write_der(WriteFunc, ...) \
        wrap_mbedtls_pk_write_der_impl(               \
                (WriteFunc), AVS_QUOTE_MACRO(WriteFunc), __VA_ARGS__)

avs_error_t avs_crypto_pki_ec_gen(avs_crypto_prng_ctx_t *prng_ctx,
                                  const void *ecp_group_asn1_oid,
                                  void *out_der_secret_key,
                                  size_t *inout_der_secret_key_size,
                                  void *out_der_public_key,
                                  size_t *inout_der_public_key_size) {
    const mbedtls_pk_info_t *pk_info =
            mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    if (!pk_info) {
        LOG(ERROR, _("Mbed TLS does not have PK info for MBEDTLS_PK_ECKEY"));
        return avs_errno(AVS_ENOTSUP);
    }

    // "const-cast" due to non-const field in mbedtls_asn1_buf
    unsigned char *cast_group_oid =
            (unsigned char *) (intptr_t) ecp_group_asn1_oid;
    // See http://luca.ntop.org/Teaching/Appunti/asn1.html
    // Sections 2 and 3.1
    // First byte (identifier octet) MUST be 0x06, OBJECT IDENTIFIER
    // Second byte (length octect) MUST have bit 8 unset, indicating short form
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

    avs_error_t err = AVS_OK;
    if ((result = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(pk_ctx),
                                      mbedtls_ctr_drbg_random,
                                      &prng_ctx->mbedtls_prng_ctx))) {
        LOG(ERROR, _("mbedtls_ecp_gen_key() failed: ") "%d", result);
        err = avs_errno(AVS_EPROTO);
    } else {
        (void) (avs_is_err((err = wrap_mbedtls_pk_write_der(
                                    mbedtls_pk_write_key_der, &pk_ctx,
                                    out_der_secret_key,
                                    inout_der_secret_key_size)))
                || avs_is_err((err = wrap_mbedtls_pk_write_der(
                                       mbedtls_pk_write_pubkey_der, &pk_ctx,
                                       out_der_public_key,
                                       inout_der_public_key_size))));
    }

    mbedtls_pk_free(&pk_ctx);
    return err;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
