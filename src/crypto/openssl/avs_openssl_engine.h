/*
 * Copyright 2020 AVSystem <avsystem@avsystem.com>
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
#ifndef CRYPTO_OPENSSL_ENGINE_H
#define CRYPTO_OPENSSL_ENGINE_H

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
#    include <openssl/x509.h>

#    include "avs_openssl_data_loader.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

avs_error_t _avs_crypto_openssl_engine_load_crls(X509_STORE *store,
                                                 const char *query);
EVP_PKEY *_avs_crypto_openssl_engine_load_private_key(const char *query);
avs_error_t
_avs_crypto_openssl_engine_load_certs(const char *cert_id,
                                      avs_crypto_ossl_object_load_t *load_cb,
                                      void *cb_arg);

avs_error_t _avs_crypto_openssl_engine_initialize_global_state(void);
void _avs_crypto_openssl_engine_cleanup_global_state(void);

VISIBILITY_PRIVATE_HEADER_END

#endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE

#endif // CRYPTO_OPENSSL_ENGINE_H
