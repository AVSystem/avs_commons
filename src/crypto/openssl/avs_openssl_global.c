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

#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) && defined(AVS_COMMONS_WITH_OPENSSL)

#    include <openssl/ssl.h>

#    include "avs_openssl_common.h"
#    include "avs_openssl_engine.h"

#    include "../avs_crypto_global.h"

#    include <avs_commons_poison.h>

#    define MODULE_NAME avs_crypto
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

avs_error_t _avs_crypto_initialize_global_state() {
    LOG(TRACE, _("OpenSSL initialization"));

    SSL_library_init();
#    ifdef AVS_LOG_WITH_TRACE
    SSL_load_error_strings();
#    endif
    OpenSSL_add_all_algorithms();

    avs_error_t err = AVS_OK;
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    err = _avs_crypto_openssl_engine_initialize_global_state();
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    return err;
}

void _avs_crypto_cleanup_global_state() {
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    _avs_crypto_openssl_engine_cleanup_global_state();
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_OPENSSL)
