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

#ifndef CRYPTO_MBEDTLS_ENGINE_H
#define CRYPTO_MBEDTLS_ENGINE_H

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) \
        || defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE)

#    include "avs_mbedtls_data_loader.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE

avs_error_t _avs_crypto_mbedtls_engine_append_cert(mbedtls_x509_crt *chain,
                                                   const char *query);

avs_error_t _avs_crypto_mbedtls_engine_append_crl(mbedtls_x509_crl *crl,
                                                  const char *query);

avs_error_t
_avs_crypto_mbedtls_engine_load_private_key(mbedtls_pk_context *client_key,
                                            const char *query);

#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE

avs_error_t _avs_crypto_mbedtls_engine_call_with_psk_identity_loaded(
        const char *query, avs_crypto_mbedtls_identity_cb_t *cb, void *cb_arg);

avs_error_t
_avs_crypto_mbedtls_engine_load_psk_key(mbedtls_ssl_config *config,
                                        const char *query,
                                        const unsigned char *identity,
                                        size_t identity_size);

#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE

avs_error_t _avs_crypto_mbedtls_engine_initialize_global_state(void);
void _avs_crypto_mbedtls_engine_cleanup_global_state(void);

VISIBILITY_PRIVATE_HEADER_END

#endif /* defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) || \
          defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE) */

#endif // CRYPTO_MBEDTLS_ENGINE_H
