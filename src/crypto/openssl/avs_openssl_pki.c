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

#    include <openssl/ec.h>
#    include <openssl/objects.h>
#    include <openssl/x509.h>

#    include <avs_commons_poison.h>

#    include <avsystem/commons/avs_crypto_pki.h>

#    include "avs_openssl_common.h"

#    define MODULE_NAME avs_crypto_pki
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

avs_error_t avs_crypto_pki_ec_gen(avs_crypto_prng_ctx_t *prng_ctx,
                                  const void *ecp_group_asn1_oid,
                                  void *out_der_secret_key,
                                  size_t *inout_der_secret_key_size) {
    const unsigned char *cast_group_oid =
            (const unsigned char *) ecp_group_asn1_oid;
    // See http://luca.ntop.org/Teaching/Appunti/asn1.html
    // Sections 2 and 3.1
    // First byte (identifier octet) MUST be 0x06, OBJECT IDENTIFIER
    // Second byte (length octect) MUST have bit 8 unset, indicating short form
    if (!cast_group_oid || cast_group_oid[0] != 0x06
            || cast_group_oid[1] > 0x7f) {
        LOG(ERROR, _("ecp_group_asn1_oid is not a syntactically valid OID"));
        return avs_errno(AVS_EINVAL);
    }

    int ec_group_nid = NID_undef;
    ASN1_OBJECT *obj =
            d2i_ASN1_OBJECT(NULL, &cast_group_oid, cast_group_oid[1] + 2);
    if (obj) {
        ec_group_nid = OBJ_obj2nid(obj);
        ASN1_OBJECT_free(obj);
    }

    EC_GROUP *group = EC_GROUP_new_by_curve_name(ec_group_nid);
    if (!group) {
        LOG(ERROR, _("specified ECP group is not supported"));
        return avs_errno(AVS_ENOTSUP);
    }

    avs_error_t err = AVS_OK;

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

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_OPENSSL)
