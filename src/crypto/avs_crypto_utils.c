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

#    include <assert.h>
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

avs_crypto_trusted_cert_info_t avs_crypto_trusted_cert_info_from_array(
        const avs_crypto_trusted_cert_info_t *array_ptr,
        size_t array_element_count) {
    avs_crypto_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_COMPOUND_ARRAY;
    result.desc.info.compound_array.array_ptr = array_ptr;
    result.desc.info.compound_array.element_count = array_element_count;
#    ifndef NDEBUG
    for (size_t i = 0; i < array_element_count; ++i) {
        assert(array_ptr[i].desc.type == AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT);
    }
#    endif // NDEBUG
    return result;
}

#    ifdef AVS_COMMONS_WITH_AVS_LIST
avs_crypto_trusted_cert_info_t avs_crypto_trusted_cert_info_from_list(
        AVS_LIST(avs_crypto_trusted_cert_info_t) list) {
    avs_crypto_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_COMPOUND_LIST;
    result.desc.info.compound_list.list_head = list;
#        ifndef NDEBUG
    AVS_LIST_ITERATE(list) {
        assert(list->desc.type == AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT);
    }
#        endif // NDEBUG
    return result;
}
#    endif // AVS_COMMONS_WITH_AVS_LIST

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

const avs_crypto_pki_x509_name_key_t AVS_CRYPTO_PKI_X509_NAME_CN = {
    .oid = (const avs_crypto_asn1_oid_t *) "\x06\x03\x55\x04\x03",
    .value_id_octet = 0x0C // UTF8String
};

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
