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

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO)                          \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_MBEDTLS)

#    include <avsystem/commons/avs_aead.h>
#    include <avsystem/commons/avs_errno.h>

#    include <mbedtls/ccm.h>

#    include "../avs_crypto_global.h"
#    include "../avs_crypto_utils.h"

#    define MODULE_NAME avs_crypto_aead
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

int avs_crypto_aead_aes_ccm_encrypt(const unsigned char *key,
                                    size_t key_len,
                                    const unsigned char *iv,
                                    size_t iv_len,
                                    const unsigned char *aad,
                                    size_t aad_len,
                                    const unsigned char *input,
                                    size_t input_len,
                                    unsigned char *tag,
                                    size_t tag_len,
                                    unsigned char *output) {
    assert(key);
    assert(iv);
    assert(!aad_len || aad);
    assert(!input_len || input);
    assert(tag);
    assert(!input_len || output);

    if (avs_is_err(_avs_crypto_ensure_global_state())
            || !_avs_crypto_aead_parameters_valid(key_len, iv_len, tag_len)) {
        return -1;
    }

    mbedtls_ccm_context ccm_ctx;
    mbedtls_ccm_init(&ccm_ctx);
    int result;
    (void) ((result = mbedtls_ccm_setkey(&ccm_ctx, MBEDTLS_CIPHER_ID_AES, key,
                                         (unsigned int) key_len * 8U))
            || (result = mbedtls_ccm_encrypt_and_tag(
                        &ccm_ctx, input_len, iv, iv_len, aad, aad_len, input,
                        output, tag, tag_len)));
    mbedtls_ccm_free(&ccm_ctx);
    if (result) {
        LOG(ERROR, _("mbed TLS error ") "%d", result);
        return -1;
    }
    return 0;
}

int avs_crypto_aead_aes_ccm_decrypt(const unsigned char *key,
                                    size_t key_len,
                                    const unsigned char *iv,
                                    size_t iv_len,
                                    const unsigned char *aad,
                                    size_t aad_len,
                                    const unsigned char *input,
                                    size_t input_len,
                                    const unsigned char *tag,
                                    size_t tag_len,
                                    unsigned char *output) {
    assert(key);
    assert(iv);
    assert(!aad_len || aad);
    assert(!input_len || input);
    assert(tag);
    assert(!input_len || output);

    if (avs_is_err(_avs_crypto_ensure_global_state())
            || !_avs_crypto_aead_parameters_valid(key_len, iv_len, tag_len)) {
        return -1;
    }

    mbedtls_ccm_context ccm_ctx;
    mbedtls_ccm_init(&ccm_ctx);

    int result;
    (void) ((result = mbedtls_ccm_setkey(&ccm_ctx, MBEDTLS_CIPHER_ID_AES, key,
                                         (unsigned int) key_len * 8U))
            || (result = mbedtls_ccm_auth_decrypt(&ccm_ctx, input_len, iv,
                                                  iv_len, aad, aad_len, input,
                                                  output, tag, tag_len)));
    mbedtls_ccm_free(&ccm_ctx);
    if (result) {
        LOG(ERROR, _("mbed TLS error ") "%d", result);
        return -1;
    }
    return 0;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
