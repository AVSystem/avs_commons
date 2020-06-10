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

#ifndef AVS_COMMONS_CRYPTO_UTILS_H
#define AVS_COMMONS_CRYPTO_UTILS_H

#include <stddef.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef enum {
    AVS_CRYPTO_DATA_SOURCE_EMPTY,
    AVS_CRYPTO_DATA_SOURCE_FILE,
    AVS_CRYPTO_DATA_SOURCE_PATH,
    AVS_CRYPTO_DATA_SOURCE_BUFFER
} avs_crypto_data_source_t;

typedef enum {
    AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT,
    AVS_CRYPTO_SECURITY_INFO_CLIENT_CERT,
    AVS_CRYPTO_SECURITY_INFO_CLIENT_KEY
} avs_crypto_security_info_tag_t;

bool _avs_crypto_aead_parameters_valid(size_t key_len,
                                       size_t iv_len,
                                       size_t tag_len);

VISIBILITY_PRIVATE_HEADER_END

#endif // AVS_COMMONS_CRYPTO_UTILS_H
