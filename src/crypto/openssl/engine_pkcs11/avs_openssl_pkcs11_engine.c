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

#ifdef AVS_COMMONS_OPENSSL_PKCS11_ENGINE_UNIT_TESTING
#    define _GNU_SOURCE // for mkstemps()
#endif                  // AVS_COMMONS_OPENSSL_PKCS11_ENGINE_UNIT_TESTING

// NOTE: libp11 headers contain some of the symbols poisoned via inclusion of
// avs_commons_init.h. Therefore they must be included before poison.
#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO)            \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) \
        && defined(AVS_COMMONS_WITH_OPENSSL)        \
        && defined(AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE)

#    include <string.h>

#    include <libp11.h>
#    include <openssl/engine.h>

#    include <avs_commons_poison.h>

#    include <avsystem/commons/avs_crypto_pki.h>

#    include "../avs_openssl_common.h"
#    include "../avs_openssl_engine.h"

#    define MODULE_NAME avs_crypto_engine
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static ENGINE *global_engine;
static PKCS11_CTX *global_pkcs11_ctx;
static PKCS11_SLOT *global_pkcs11_slots;
static unsigned int global_pkcs11_slot_num;

avs_error_t _avs_crypto_openssl_engine_initialize_global_state(void) {
    const char *pkcs11_path = getenv("PKCS11_MODULE_PATH");
    if (pkcs11_path) {
        if (!(global_pkcs11_ctx = PKCS11_CTX_new())
                || PKCS11_CTX_load(global_pkcs11_ctx, pkcs11_path)
                || PKCS11_enumerate_slots(global_pkcs11_ctx,
                                          &global_pkcs11_slots,
                                          &global_pkcs11_slot_num)
                || !(global_engine = ENGINE_by_id("pkcs11"))) {
            log_openssl_error();
            return avs_errno(AVS_ENOTSUP);
        }
    } else {
        LOG(WARNING,
            "PKCS11_MODULE_PATH not set, not loading the PKCS11 engine.");
    }
    return AVS_OK;
}

void _avs_crypto_openssl_engine_cleanup_global_state(void) {
    ENGINE_free(global_engine);
    PKCS11_release_all_slots(global_pkcs11_ctx, global_pkcs11_slots,
                             global_pkcs11_slot_num);
    PKCS11_CTX_unload(global_pkcs11_ctx);
    PKCS11_CTX_free(global_pkcs11_ctx);
    global_engine = NULL;
    global_pkcs11_ctx = NULL;
    global_pkcs11_slots = NULL;
    global_pkcs11_slot_num = 0;
}

avs_error_t _avs_crypto_openssl_engine_load_crls(X509_STORE *store,
                                                 const char *query) {
    (void) store;
    (void) query;
    LOG(ERROR, "Loading CRLs from HSM not supported");
    return avs_errno(AVS_ENOTSUP);
}

EVP_PKEY *_avs_crypto_openssl_engine_load_private_key(const char *query) {
    if (!global_engine || !query || !ENGINE_init(global_engine)) {
        LOG(ERROR,
            _("Cannot load key from the engine - engine uninitialized."));
        return NULL;
    }

    EVP_PKEY *pkey = ENGINE_load_private_key(global_engine, query, NULL, NULL);

    ENGINE_finish(global_engine);

    return pkey;
}

avs_error_t
_avs_crypto_openssl_engine_load_certs(const char *cert_id,
                                      avs_crypto_ossl_object_load_t *load_cb,
                                      void *cb_arg) {
    assert(cert_id);

    LOG(DEBUG, _("certificate <cert_id=") "%s" _(">: going to load"), cert_id);

    struct {
        const char *cert_id;
        X509 *cert;
    } params = {
        .cert_id = cert_id,
        .cert = NULL
    };

    if (!ENGINE_ctrl_cmd(global_engine, "LOAD_CERT_CTRL", 0, &params, NULL, 1)
            || params.cert == NULL) {
        return avs_errno(AVS_EIO);
    }

    avs_error_t err = load_cb((void *) params.cert, cb_arg);
    X509_free(params.cert);

    return err;
}

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES
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

#        ifdef AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
#            pragma GCC diagnostic push
#            pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#        endif // AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
    if ((slot = get_pkcs11_slot(token)) && !PKCS11_open_session(slot, 1)
            && !PKCS11_login(slot, 0, pin)
            && !PKCS11_generate_key(
                       slot->token, 0, 2048, (char *) (intptr_t) label,
                       (unsigned char *) (intptr_t) label, strlen(label))) {
        err = AVS_OK;
    }
#        ifdef AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC
#            pragma GCC diagnostic pop
#        endif // AVS_COMMONS_HAVE_PRAGMA_DIAGNOSTIC

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

avs_error_t avs_crypto_pki_certificate_store_pkcs11(
        const char *token,
        const char *label,
        const char *pin,
        const avs_crypto_certificate_chain_info_t *cert_info) {
    assert(token && label && pin);

    X509 *cert = NULL;
    avs_error_t err =
            _avs_crypto_openssl_load_first_client_cert(&cert, cert_info);
    if (avs_is_err(err)) {
        return err;
    }

    assert(cert);
    PKCS11_SLOT *slot = NULL;
    if (!(slot = get_pkcs11_slot(token)) || PKCS11_open_session(slot, 1)
            || PKCS11_login(slot, 0, pin)
            || PKCS11_store_certificate(slot->token, cert,
                                        (char *) (intptr_t) label,
                                        (unsigned char *) (intptr_t) label,
                                        strlen(label), NULL)) {
        err = avs_errno(AVS_UNKNOWN_ERROR);
    }

    if (avs_is_err(err)) {
        LOG(ERROR, "%s", ERR_error_string(ERR_get_error(), NULL));
    }

    X509_free(cert);
    return err;
}

static int remove_pkcs11_certs_with_label(PKCS11_CERT *certs,
                                          unsigned int cert_num,
                                          const char *label) {
    for (unsigned int k = 0; k < cert_num; k++) {
        if (strcmp(certs[k].label, label) == 0) {
            if (PKCS11_remove_certificate(&certs[k])) {
                return -1;
            }
        }
    }
    return 0;
}

avs_error_t avs_crypto_pki_certificate_rm_pkcs11(const char *token,
                                                 const char *label,
                                                 const char *pin) {
    assert(token && label && pin);

    PKCS11_SLOT *slot = NULL;
    avs_error_t err = avs_errno(AVS_UNKNOWN_ERROR);

    PKCS11_CERT *certs;
    unsigned int cert_num;

    if ((slot = get_pkcs11_slot(token)) && !PKCS11_open_session(slot, 1)
            && !PKCS11_login(slot, 0, pin)
            && !PKCS11_enumerate_certs(slot->token, &certs, &cert_num)
            && !remove_pkcs11_certs_with_label(certs, cert_num, label)) {
        err = AVS_OK;
    }

    if (avs_is_err(err)) {
        LOG(ERROR, "%s", ERR_error_string(ERR_get_error(), NULL));
    }

    return err;
}
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES

#    ifdef AVS_COMMONS_OPENSSL_PKCS11_ENGINE_UNIT_TESTING
#        include "tests/crypto/openssl_engine/openssl_engine_data_loader.c"
#    endif // AVS_COMMONS_OPENSSL_PKCS11_ENGINE_UNIT_TESTING

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_OPENSSL) &&
       // defined(AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE)
