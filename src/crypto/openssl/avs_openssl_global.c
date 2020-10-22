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

#define AVS_GLOBAL_SOURCE

#ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
#    include <libp11.h>
#    include <openssl/engine.h>
#endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE

#include "avs_openssl_global.h"

#include "avs_openssl_common.h"

#define MODULE_NAME avs_crypto
#include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#ifdef AVS_COMMONS_WITH_OPENSSL

#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
ENGINE *_avs_global_engine = NULL;
PKCS11_CTX *_avs_global_pkcs11_ctx = NULL;
PKCS11_SLOT *_avs_global_pkcs11_slots = NULL;
unsigned int _avs_global_pkcs11_slot_num = 0;
#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE

avs_error_t _avs_crypto_initialize_global_state() {
    LOG(TRACE, _("OpenSSL initialization"));

    SSL_library_init();
#    ifdef AVS_LOG_WITH_TRACE
    SSL_load_error_strings();
#    endif
    OpenSSL_add_all_algorithms();

#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
    const char *pkcs11_path = getenv("PKCS11_MODULE_PATH");
    if (pkcs11_path) {
        if (!(_avs_global_pkcs11_ctx = PKCS11_CTX_new())
                || PKCS11_CTX_load(_avs_global_pkcs11_ctx, pkcs11_path)
                || PKCS11_enumerate_slots(_avs_global_pkcs11_ctx,
                                          &_avs_global_pkcs11_slots,
                                          &_avs_global_pkcs11_slot_num)
                || !(_avs_global_engine = ENGINE_by_id("pkcs11"))) {
            log_openssl_error();
            return avs_errno(AVS_ENOTSUP);
        }
    } else {
        LOG(WARNING,
            "PKCS11_MODULE_PATH not set, not loading the PKCS11 engine.");
    }

#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
    return AVS_OK;
}

void _avs_crypto_cleanup_global_state() {
#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
    ENGINE_free(_avs_global_engine);
    PKCS11_release_all_slots(_avs_global_pkcs11_ctx,
                             _avs_global_pkcs11_slots,
                             _avs_global_pkcs11_slot_num);
    PKCS11_CTX_unload(_avs_global_pkcs11_ctx);
    PKCS11_CTX_free(_avs_global_pkcs11_ctx);
#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
}

#endif // AVS_COMMONS_WITH_OPENSSL
