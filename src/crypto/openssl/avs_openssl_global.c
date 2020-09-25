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

#ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
#    include <openssl/engine.h>
#endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE

#include "avs_openssl_global.h"

#define MODULE_NAME avs_crypto
#include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#ifdef AVS_COMMONS_WITH_OPENSSL

#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
ENGINE *_avs_global_engine = NULL;
#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE

avs_error_t _avs_crypto_initialize_global_state() {
    LOG(TRACE, _("OpenSSL initialization"));

    SSL_library_init();
#    ifdef AVS_LOG_WITH_TRACE
    SSL_load_error_strings();
#    endif
    OpenSSL_add_all_algorithms();

#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
    _avs_global_engine = ENGINE_by_id("pkcs11");
    if (_avs_global_engine == NULL) {
        return avs_errno(AVS_ENOTSUP);
    }
#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
    return AVS_OK;
}

void _avs_crypto_cleanup_global_state() {
#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
    ENGINE_free(_avs_global_engine);
#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
}

#endif // AVS_COMMONS_WITH_OPENSSL
