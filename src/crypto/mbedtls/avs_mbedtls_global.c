/*
 * Copyright 2021 AVSystem <avsystem@avsystem.com>
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

#    include "avs_mbedtls_engine.h"

#    include "../avs_crypto_global.h"

#    define MODULE_NAME avs_crypto_global
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

avs_error_t _avs_crypto_initialize_global_state() {
    avs_error_t err = AVS_OK;
#    ifdef MBEDTLS_USE_PSA_CRYPTO
    // NOTE: When MBEDTLS_USE_PSA_CRYPTO is enabled, psa_crypto_init() is
    // required even when only using the regular Mbed TLS API.
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        LOG(ERROR, _("psa_crypto_init() failed: ") "%" PRId32, status);
        return avs_errno(AVS_EPROTO);
    }
#    endif // MBEDTLS_USE_PSA_CRYPTO
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    err = _avs_crypto_mbedtls_engine_initialize_global_state();
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    return err;
}

void _avs_crypto_cleanup_global_state() {
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    _avs_crypto_mbedtls_engine_cleanup_global_state();
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
