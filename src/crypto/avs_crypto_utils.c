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
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_TRUSTED_CERT_ARRAY;
    result.desc.info.trusted_cert_array.array_ptr = array_ptr;
    result.desc.info.trusted_cert_array.element_count = array_element_count;
#    ifndef NDEBUG
    for (size_t i = 0; i < array_element_count; ++i) {
        assert(array_ptr[i].desc.type == AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT);
    }
#    endif // NDEBUG
    return result;
}

typedef avs_error_t
trusted_cert_info_visit_t(const avs_crypto_trusted_cert_info_t *info,
                          void *arg);

static avs_error_t
trusted_cert_info_iterate(const avs_crypto_trusted_cert_info_t *info,
                          trusted_cert_info_visit_t *visitor,
                          void *visitor_arg) {
    if (info->desc.type != AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT) {
        return avs_errno(AVS_EINVAL);
    }
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_TRUSTED_CERT_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err)
             && i < info->desc.info.trusted_cert_array.element_count;
             ++i) {
            err = trusted_cert_info_iterate(
                    &info->desc.info.trusted_cert_array.array_ptr[i],
                    visitor,
                    visitor_arg);
        }
        return err;
    }
#    ifdef AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_TRUSTED_CERT_LIST: {
        AVS_LIST(avs_crypto_trusted_cert_info_t) entry;
        AVS_LIST_FOREACH(entry, info->desc.info.trusted_cert_list.list_head) {
            avs_error_t err =
                    trusted_cert_info_iterate(entry, visitor, visitor_arg);
            if (avs_is_err(err)) {
                return err;
            }
        }
        return AVS_OK;
    }
#    endif // AVS_COMMONS_WITH_AVS_LIST
    default:
        return visitor(info, visitor_arg);
    }
}

static avs_error_t
calculate_data_buffer_size(size_t *out_buffer_size,
                           const avs_crypto_trusted_cert_info_t *info) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        *out_buffer_size = info->desc.info.file.filename
                                   ? strlen(info->desc.info.file.filename) + 1
                                   : 0;
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        *out_buffer_size = info->desc.info.path.path
                                   ? strlen(info->desc.info.path.path) + 1
                                   : 0;
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        *out_buffer_size = info->desc.info.buffer.buffer_size;
        return AVS_OK;
    default:
        return avs_errno(AVS_EINVAL);
    }
}

typedef struct {
    size_t element_count;
    size_t data_buffer_size;
} trusted_cert_stats_t;

static avs_error_t
calculate_cert_stats(const avs_crypto_trusted_cert_info_t *info, void *stats_) {
    trusted_cert_stats_t *stats = (trusted_cert_stats_t *) stats_;
    ++stats->element_count;
    size_t element_buffer_size = 0;
    avs_error_t err = calculate_data_buffer_size(&element_buffer_size, info);
    if (avs_is_ok(err)
            && element_buffer_size >= SIZE_MAX - stats->data_buffer_size) {
        err = avs_errno(AVS_ENOMEM);
    }
    if (avs_is_ok(err)) {
        stats->data_buffer_size += element_buffer_size;
    }
    return err;
}

static void copy_element(avs_crypto_trusted_cert_info_t *dest,
                         char **data_buffer_ptr,
                         const avs_crypto_trusted_cert_info_t *src) {
    *dest = *src;
    const void *source = NULL;
    size_t size = 0;
    switch (src->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (src->desc.info.file.filename) {
            source = src->desc.info.file.filename;
            size = strlen(src->desc.info.file.filename) + 1;
            dest->desc.info.file.filename = *data_buffer_ptr;
        }
        break;
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        if (src->desc.info.path.path) {
            source = src->desc.info.path.path;
            size = strlen(src->desc.info.path.path) + 1;
            dest->desc.info.path.path = *data_buffer_ptr;
        }
        break;
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        if (src->desc.info.buffer.buffer) {
            source = src->desc.info.buffer.buffer;
            size = src->desc.info.buffer.buffer_size;
            dest->desc.info.buffer.buffer = *data_buffer_ptr;
        }
        break;
    default:
        AVS_UNREACHABLE("Invalid data source type");
    }
    memcpy(*data_buffer_ptr, source, size);
    *data_buffer_ptr += size;
}

typedef struct {
    avs_crypto_trusted_cert_info_t *array_ptr;
    char *data_buffer_ptr;
} array_copy_state_t;

static avs_error_t copy_into_array(const avs_crypto_trusted_cert_info_t *info,
                                   void *state_) {
    array_copy_state_t *state = (array_copy_state_t *) state_;
    copy_element(state->array_ptr++, &state->data_buffer_ptr, info);
    return AVS_OK;
}

avs_error_t avs_crypto_trusted_cert_info_copy_as_array(
        avs_crypto_trusted_cert_info_t **out_array,
        size_t *out_element_count,
        avs_crypto_trusted_cert_info_t trusted_cert_info) {
    if (!out_array || *out_array) {
        return avs_errno(AVS_EINVAL);
    }
    trusted_cert_stats_t stats = { 0 };
    avs_error_t err = trusted_cert_info_iterate(
            &trusted_cert_info, calculate_cert_stats, &stats);
    if (avs_is_err(err)) {
        return err;
    }
    *out_element_count = stats.element_count;
    if (stats.element_count > SIZE_MAX / sizeof(avs_crypto_trusted_cert_info_t)
            || stats.data_buffer_size
                           > SIZE_MAX
                                         - stats.element_count
                                                       * sizeof(avs_crypto_trusted_cert_info_t)) {
        return avs_errno(AVS_ENOMEM);
    }
    size_t buffer_size =
            stats.element_count * sizeof(avs_crypto_trusted_cert_info_t)
            + stats.data_buffer_size;
    if (!(*out_array =
                  (avs_crypto_trusted_cert_info_t *) avs_malloc(buffer_size))) {
        return avs_errno(AVS_ENOMEM);
    }
    array_copy_state_t state = {
        .array_ptr = *out_array,
        .data_buffer_ptr = (char *) &(*out_array)[stats.element_count]
    };
    err = trusted_cert_info_iterate(
            &trusted_cert_info, copy_into_array, &state);
    assert(avs_is_ok(err));
    return AVS_OK;
}

#    ifdef AVS_COMMONS_WITH_AVS_LIST
avs_crypto_trusted_cert_info_t avs_crypto_trusted_cert_info_from_list(
        AVS_LIST(avs_crypto_trusted_cert_info_t) list) {
    avs_crypto_trusted_cert_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_TRUSTED_CERT_LIST;
    result.desc.info.trusted_cert_list.list_head = list;
#        ifndef NDEBUG
    AVS_LIST_ITERATE(list) {
        assert(list->desc.type == AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT);
    }
#        endif // NDEBUG
    return result;
}

static avs_error_t copy_into_list(const avs_crypto_trusted_cert_info_t *info,
                                  void *tail_ptr_ptr_) {
    AVS_LIST(avs_crypto_trusted_cert_info_t) **tail_ptr_ptr =
            (AVS_LIST(avs_crypto_trusted_cert_info_t) **) tail_ptr_ptr_;
    size_t data_buffer_size;
    avs_error_t err = calculate_data_buffer_size(&data_buffer_size, info);
    if (avs_is_err(err)) {
        return err;
    }
    assert(!**tail_ptr_ptr);
    if (data_buffer_size > SIZE_MAX - sizeof(avs_crypto_trusted_cert_info_t)
            || !(**tail_ptr_ptr = (AVS_LIST(avs_crypto_trusted_cert_info_t))
                         AVS_LIST_NEW_BUFFER(
                                 sizeof(avs_crypto_trusted_cert_info_t)
                                 + data_buffer_size))) {
        return avs_errno(AVS_ENOMEM);
    }
    copy_element(
            **tail_ptr_ptr, &(char *) { (char *) &(**tail_ptr_ptr)[1] }, info);
    AVS_LIST_ADVANCE_PTR(tail_ptr_ptr);
    return AVS_OK;
}

avs_error_t avs_crypto_trusted_cert_info_copy_as_list(
        AVS_LIST(avs_crypto_trusted_cert_info_t) *out_list,
        avs_crypto_trusted_cert_info_t trusted_cert_info) {
    if (!out_list || *out_list) {
        return avs_errno(AVS_EINVAL);
    }
    AVS_LIST(avs_crypto_trusted_cert_info_t) *tail_ptr = out_list;
    avs_error_t err = trusted_cert_info_iterate(
            &trusted_cert_info, copy_into_list, &tail_ptr);
    if (avs_is_err(err)) {
        AVS_LIST_CLEAR(out_list);
    }
    return err;
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
