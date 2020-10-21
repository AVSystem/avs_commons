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

#define AVS_GLOBAL_SOURCE

// NOTE: libp11 headers contain some of the symbols poisoned via inclusion of
// avs_commons_init.h. Therefore they must be included before poison.
#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO)                          \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)               \
        && defined(AVS_COMMONS_WITH_OPENSSL)                      \
        && defined(AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE)

#    include <string.h>

#    include <libp11.h>

#    include <avs_commons_poison.h>

#    include <avsystem/commons/avs_crypto_pki.h>

#    include "../avs_openssl_common.h"
#    include "../avs_openssl_global.h"

#    define MODULE_NAME avs_crypto_engine
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

ENGINE *_avs_global_engine;
static PKCS11_CTX *global_pkcs11_ctx;
static PKCS11_SLOT *global_pkcs11_slots;
static unsigned int global_pkcs11_slot_num;

avs_error_t _avs_crypto_engine_initialize_global_state(void) {
    const char *pkcs11_path = getenv("PKCS11_MODULE_PATH");
    if (pkcs11_path) {
        if (!(global_pkcs11_ctx = PKCS11_CTX_new())
                || PKCS11_CTX_load(global_pkcs11_ctx, pkcs11_path)
                || PKCS11_enumerate_slots(global_pkcs11_ctx,
                                          &global_pkcs11_slots,
                                          &global_pkcs11_slot_num)
                || !(_avs_global_engine = ENGINE_by_id("pkcs11"))) {
            log_openssl_error();
            return avs_errno(AVS_ENOTSUP);
        }
    } else {
        LOG(WARNING,
            "PKCS11_MODULE_PATH not set, not loading the PKCS11 engine.");
    }
    return AVS_OK;
}

void _avs_crypto_engine_cleanup_global_state(void) {
    ENGINE_free(_avs_global_engine);
    PKCS11_release_all_slots(global_pkcs11_ctx, global_pkcs11_slots,
                             global_pkcs11_slot_num);
    PKCS11_CTX_unload(global_pkcs11_ctx);
    PKCS11_CTX_free(global_pkcs11_ctx);
    _avs_global_engine = NULL;
    global_pkcs11_ctx = NULL;
    global_pkcs11_slots = NULL;
    global_pkcs11_slot_num = 0;
}

static PKCS11_SLOT *get_pkcs11_slot(const char *token_label) {
    PKCS11_SLOT *current_slot =
            PKCS11_find_token(global_pkcs11_ctx, global_pkcs11_slots,
                              global_pkcs11_slot_num);
    while (current_slot != NULL) {
        if (strcmp(token_label, current_slot->token->label) == 0) {
            return current_slot;
        }
        current_slot =
                PKCS11_find_next_token(global_pkcs11_ctx, global_pkcs11_slots,
                                       global_pkcs11_slot_num, current_slot);
    }

    return NULL;
}

avs_error_t avs_crypto_pki_ec_gen_pkcs11(const char *token,
                                         const char *label,
                                         const char *pin) {
    assert(token && label && pin);

    PKCS11_SLOT *slot = NULL;
    avs_error_t err = avs_errno(AVS_UNKNOWN_ERROR);

#    ifdef AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
#        pragma GCC diagnostic push
#        pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#    endif // AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
    if ((slot = get_pkcs11_slot(token)) && !PKCS11_open_session(slot, 1)
            && !PKCS11_login(slot, 0, pin)
            && !PKCS11_generate_key(
                       slot->token, 0, 2048, (char *) (intptr_t) label,
                       (unsigned char *) (intptr_t) label, strlen(label))) {
        err = AVS_OK;
    }
#    ifdef AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
#        pragma GCC diagnostic pop
#    endif // AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC

    if (avs_is_err(err)) {
        LOG(ERROR, "%s", ERR_error_string(ERR_get_error(), NULL));
    }

    return err;
}

static int remove_pkcs11_keys_with_label(PKCS11_KEY *keys,
                                         unsigned int key_num,
                                         const char *label) {
    for (unsigned int k = 0; k < key_num; k++) {
        if (strcmp(keys[k].label, label) == 0) {
            if (PKCS11_remove_key(&keys[k])) {
                return -1;
            }
        }
    }
    return 0;
}

avs_error_t avs_crypto_pki_ec_rm_pkcs11(const char *token,
                                        const char *label,
                                        const char *pin) {
    assert(token && label && pin);

    PKCS11_SLOT *slot = NULL;
    avs_error_t err = avs_errno(AVS_UNKNOWN_ERROR);

    PKCS11_KEY *keys;
    unsigned int key_num;

    if ((slot = get_pkcs11_slot(token)) && !PKCS11_open_session(slot, 1)
            && !PKCS11_login(slot, 0, pin)
            && !PKCS11_enumerate_keys(slot->token, &keys, &key_num)
            && !remove_pkcs11_keys_with_label(keys, key_num, label)
            && !PKCS11_enumerate_public_keys(slot->token, &keys, &key_num)
            && !remove_pkcs11_keys_with_label(keys, key_num, label)) {
        err = AVS_OK;
    }

    if (avs_is_err(err)) {
        LOG(ERROR, "%s", ERR_error_string(ERR_get_error(), NULL));
    }

    return err;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_OPENSSL) &&
       // defined(AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE)
