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

// NOTE: OpenSSL headers sometimes (depending on a version) contain some of the
// symbols poisoned via inclusion of avs_commons_init.h. Therefore they must
// be included before poison.
#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO)                          \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_OPENSSL)

#    include <openssl/evp.h>
#    include <openssl/kdf.h>

#    include <avs_commons_poison.h>

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_hkdf.h>
#    include <avsystem/commons/avs_log.h>

#    include "../avs_crypto_global.h"

VISIBILITY_SOURCE_BEGIN

// Adapted from:
// https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_set1_hkdf_key.html
int avs_crypto_hkdf_sha_256(const unsigned char *salt,
                            size_t salt_len,
                            const unsigned char *ikm,
                            size_t ikm_len,
                            const unsigned char *info,
                            size_t info_len,
                            unsigned char *out_okm,
                            size_t *inout_okm_len) {
    assert(!salt_len || salt);
    assert(ikm && ikm_len);
    assert(!info_len || info);
    assert(out_okm && inout_okm_len);

    if (avs_is_err(_avs_crypto_ensure_global_state())) {
        return -1;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        return -1;
    }

    int result = -1;
    if (EVP_PKEY_derive_init(pctx) != 1
            || EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1
            || EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int) ikm_len) != 1) {
        goto finish;
    }

    if (salt_len
            && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int) salt_len) != 1) {
        goto finish;
    }

    if (info_len
            && EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int) info_len) != 1) {
        goto finish;
    }

    if (EVP_PKEY_derive(pctx, out_okm, inout_okm_len) != 1) {
        goto finish;
    }

    result = 0;

finish:
    EVP_PKEY_CTX_free(pctx);
    return result;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_OPENSSL)
