/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#define MODULE_NAME avs_crypto_hkdf
#include <x_log_config.h>

#include <avsystem/commons/hkdf.h>

VISIBILITY_SOURCE_BEGIN

int avs_crypto_hkdf_sha_256(const unsigned char *salt, size_t salt_len,
                            const unsigned char *ikm, size_t ikm_len,
                            const unsigned char *info, size_t info_len,
                            char unsigned *out_okm, size_t *inout_okm_len) {
    (void) salt;
    (void) salt_len;
    (void) ikm;
    (void) ikm_len;
    (void) info;
    (void) info_len;
    (void) out_okm;
    (void) inout_okm_len;
    LOG(ERROR, "HKDF not supported in tinydtls");
    return -1;
}
