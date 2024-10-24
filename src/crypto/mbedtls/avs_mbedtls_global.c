/*
 * Copyright 2024 AVSystem <avsystem@avsystem.com>
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

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) && defined(AVS_COMMONS_WITH_MBEDTLS)

#    include <inttypes.h>

#    if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) \
            || defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE)
#        include "avs_mbedtls_engine.h"
#    endif /* defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) || \
              defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE) */

#    include "../avs_crypto_global.h"

#    include <mbedtls/version.h>
#    if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_PSA_CRYPTO_C) \
            || defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
#        include <psa/crypto.h>
#    endif // defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_PSA_CRYPTO_C)
           // || defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)

#    define MODULE_NAME avs_crypto_global
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

avs_error_t _avs_crypto_initialize_global_state() {
    avs_error_t err = AVS_OK;
#    if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_PSA_CRYPTO_C) \
            || defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
    // NOTE: When MBEDTLS_USE_PSA_CRYPTO is enabled, psa_crypto_init() is
    // required even when only using the regular Mbed TLS API. Also, even when
    // MBEDTLS_USE_PSA_CRYPTO is disabled, we may need to initialize the PSA
    // layer to use the PSA RNG API.
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        LOG(ERROR, _("psa_crypto_init() failed: ") "%" PRId32, status);
        return avs_errno(AVS_EPROTO);
    }
#    endif // defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_PSA_CRYPTO_C)
           // || defined(AVS_COMMONS_WITH_MBEDTLS_PSA_RNG)
#    if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) \
            || defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE)
    err = _avs_crypto_mbedtls_engine_initialize_global_state();
#    endif /* defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) || \
              defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE) */
    return err;
}

void _avs_crypto_cleanup_global_state() {
#    if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) \
            || defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE)
    _avs_crypto_mbedtls_engine_cleanup_global_state();
#    endif /* defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) || \
              defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE) */
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
