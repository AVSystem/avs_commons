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

#ifndef NET_MBEDTLS_DATA_LOADER_H
#define NET_MBEDTLS_DATA_LOADER_H

#include <mbedtls/ssl.h>

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#    include <avsystem/commons/avs_crypto_pki.h>
#endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PSK
#    include <avsystem/commons/avs_crypto_psk.h>
#endif // AVS_COMMONS_WITH_AVS_CRYPTO_PSK

#include "../avs_crypto_utils.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI

void _avs_crypto_mbedtls_x509_crt_cleanup(mbedtls_x509_crt **crt);

avs_error_t
_avs_crypto_mbedtls_load_certs(mbedtls_x509_crt **out,
                               const avs_crypto_certificate_chain_info_t *info);

void _avs_crypto_mbedtls_x509_crl_cleanup(mbedtls_x509_crl **crl);

avs_error_t _avs_crypto_mbedtls_load_crls(
        mbedtls_x509_crl **out,
        const avs_crypto_cert_revocation_list_info_t *info);

void _avs_crypto_mbedtls_pk_context_cleanup(mbedtls_pk_context **ctx);

avs_error_t
_avs_crypto_mbedtls_load_private_key(mbedtls_pk_context **pk,
                                     const avs_crypto_private_key_info_t *info,
                                     avs_crypto_prng_ctx_t *prng_ctx);

#endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PSK

typedef avs_error_t avs_crypto_mbedtls_identity_cb_t(const uint8_t *identity,
                                                     size_t identity_size,
                                                     void *arg);

avs_error_t _avs_crypto_mbedtls_call_with_identity_loaded(
        const avs_crypto_psk_identity_info_t *info,
        avs_crypto_mbedtls_identity_cb_t *cb,
        void *cb_arg);

avs_error_t
_avs_crypto_mbedtls_load_psk(mbedtls_ssl_config *config,
                             const avs_crypto_psk_key_info_t *key,
                             const avs_crypto_psk_identity_info_t *identity);

#endif // AVS_COMMONS_WITH_AVS_CRYPTO_PSK

VISIBILITY_PRIVATE_HEADER_END
#endif // NET_MBEDTLS_DATA_LOADER_H
