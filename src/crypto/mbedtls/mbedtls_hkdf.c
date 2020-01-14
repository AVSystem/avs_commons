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

#include <avs_commons_config.h>

#if defined(WITH_AVS_CRYPTO) && defined(WITH_MBEDTLS)

#    define MODULE_NAME avs_crypto_hkdf
#    include <x_log_config.h>

#    include <avsystem/commons/hkdf.h>

#    include <mbedtls/hkdf.h>

VISIBILITY_SOURCE_BEGIN

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

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) {
        return -1;
    }
    // As defined in docs for mbedtls_hkdf.
    size_t max_size = 255U * mbedtls_md_get_size(md);
    if (*inout_okm_len > max_size) {
        *inout_okm_len = max_size;
    }
    int result = mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len,
                              out_okm, *inout_okm_len);
    if (result) {
        LOG(ERROR, _("mbed TLS error ") "%d", result);
        return -1;
    }
    return 0;
}

#endif // defined(WITH_AVS_CRYPTO) && defined(WITH_MBEDTLS)
