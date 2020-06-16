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

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO

#    include <string.h>

#    include <avsystem/commons/avs_crypto_pki.h>

#    include "avs_crypto_utils.h"

#    define MODULE_NAME avs_crypto
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_file(const char *filename) {
    avs_crypto_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    return result;
}

avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_path(const char *path) {
    avs_crypto_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_PATH;
    result.desc.info.path.path = path;
    return result;
}

avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_buffer(const void *buffer,
                                         size_t buffer_size) {
    avs_crypto_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    return result;
}

avs_crypto_client_key_info_t
avs_crypto_client_key_info_from_file(const char *filename,
                                     const char *password) {
    avs_crypto_client_key_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CLIENT_KEY;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    result.desc.info.file.password = password;
    return result;
}

avs_crypto_client_key_info_t avs_crypto_client_key_info_from_buffer(
        const void *buffer, size_t buffer_size, const char *password) {
    avs_crypto_client_key_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CLIENT_KEY;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    result.desc.info.buffer.password = password;
    return result;
}

avs_crypto_client_cert_info_t
avs_crypto_client_cert_info_from_file(const char *filename) {
    avs_crypto_client_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CLIENT_CERT;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    return result;
}

avs_crypto_client_cert_info_t
avs_crypto_client_cert_info_from_buffer(const void *buffer,
                                        size_t buffer_size) {
    avs_crypto_client_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CLIENT_CERT;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    return result;
}

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES

bool _avs_crypto_aead_parameters_valid(size_t key_len,
                                       size_t iv_len,
                                       size_t tag_len) {
    if (key_len != 16 && key_len != 32) {
        LOG(ERROR, _("invalid key length"));
        return false;
    }
    if (iv_len < 7 || iv_len > 13) {
        LOG(ERROR, _("invalid IV length"));
        return false;
    }
    if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0) {
        LOG(ERROR, _("invalid tag length"));
        return false;
    }
    return true;
}

#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES

#endif // AVS_COMMONS_WITH_AVS_CRYPTO
