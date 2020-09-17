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
#    include <avsystem/commons/avs_memory.h>

#    include "avs_crypto_utils.h"

#    define MODULE_NAME avs_crypto
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

avs_crypto_certificate_chain_info_t
avs_crypto_certificate_chain_info_from_file(const char *filename) {
    avs_crypto_certificate_chain_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    return result;
}

avs_crypto_certificate_chain_info_t
avs_crypto_certificate_chain_info_from_path(const char *path) {
    avs_crypto_certificate_chain_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_PATH;
    result.desc.info.path.path = path;
    return result;
}

avs_crypto_certificate_chain_info_t
avs_crypto_certificate_chain_info_from_buffer(const void *buffer,
                                              size_t buffer_size) {
    avs_crypto_certificate_chain_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    return result;
}

avs_crypto_cert_revocation_list_info_t
avs_crypto_cert_revocation_list_info_from_file(const char *filename) {
    avs_crypto_cert_revocation_list_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    return result;
}

avs_crypto_cert_revocation_list_info_t
avs_crypto_cert_revocation_list_info_from_buffer(const void *buffer,
                                                 size_t buffer_size) {
    avs_crypto_cert_revocation_list_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    return result;
}

avs_crypto_certificate_chain_info_t
avs_crypto_certificate_chain_info_from_array(
        const avs_crypto_certificate_chain_info_t *array_ptr,
        size_t array_element_count) {
    avs_crypto_certificate_chain_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_ARRAY;
    result.desc.info.array.array_ptr = &array_ptr->desc;
    result.desc.info.array.element_count = array_element_count;
#    ifndef NDEBUG
    for (size_t i = 0; i < array_element_count; ++i) {
        assert(array_ptr[i].desc.type
               == AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
    }
#    endif // NDEBUG
    return result;
}

avs_crypto_cert_revocation_list_info_t
avs_crypto_cert_revocation_list_info_from_array(
        const avs_crypto_cert_revocation_list_info_t *array_ptr,
        size_t array_element_count) {
    avs_crypto_cert_revocation_list_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_ARRAY;
    result.desc.info.array.array_ptr = &array_ptr->desc;
    result.desc.info.array.element_count = array_element_count;
#    ifndef NDEBUG
    for (size_t i = 0; i < array_element_count; ++i) {
        assert(array_ptr[i].desc.type
               == AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
    }
#    endif // NDEBUG
    return result;
}

typedef avs_error_t
security_info_visit_t(const avs_crypto_security_info_union_t *desc, void *arg);

static avs_error_t
security_info_iterate(const avs_crypto_security_info_union_t *desc,
                      security_info_visit_t *visitor,
                      void *visitor_arg) {
    switch (desc->source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0; avs_is_ok(err) && i < desc->info.array.element_count;
             ++i) {
            err = security_info_iterate(&desc->info.array.array_ptr[i], visitor,
                                        visitor_arg);
        }
        return err;
    }
#    ifdef AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_LIST: {
        AVS_LIST(avs_crypto_security_info_union_t) entry;
        AVS_LIST_FOREACH(entry, desc->info.list.list_head) {
            avs_error_t err =
                    security_info_iterate(entry, visitor, visitor_arg);
            if (avs_is_err(err)) {
                return err;
            }
        }
        return AVS_OK;
    }
#    endif // AVS_COMMONS_WITH_AVS_LIST
    default:
        return visitor(desc, visitor_arg);
    }
}

static avs_error_t
calculate_data_buffer_size(size_t *out_buffer_size,
                           const avs_crypto_security_info_union_t *desc) {
    switch (desc->source) {
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        *out_buffer_size = desc->info.file.filename
                                   ? strlen(desc->info.file.filename) + 1
                                   : 0;
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        *out_buffer_size =
                desc->info.path.path ? strlen(desc->info.path.path) + 1 : 0;
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        *out_buffer_size = desc->info.buffer.buffer_size;
        return AVS_OK;
    default:
        return avs_errno(AVS_EINVAL);
    }
}

typedef struct {
    const int expected_type;
    size_t element_count;
    size_t data_buffer_size;
} security_info_stats_t;

static avs_error_t
calculate_info_stats(const avs_crypto_security_info_union_t *desc,
                     void *stats_) {
    security_info_stats_t *stats = (security_info_stats_t *) stats_;
    if (desc->type != stats->expected_type) {
        return avs_errno(AVS_EINVAL);
    }
    ++stats->element_count;
    size_t element_buffer_size = 0;
    avs_error_t err = calculate_data_buffer_size(&element_buffer_size, desc);
    if (avs_is_ok(err)
            && element_buffer_size >= SIZE_MAX - stats->data_buffer_size) {
        err = avs_errno(AVS_ENOMEM);
    }
    if (avs_is_ok(err)) {
        stats->data_buffer_size += element_buffer_size;
    }
    return err;
}

static void copy_element(avs_crypto_security_info_union_t *dest,
                         char **data_buffer_ptr,
                         const avs_crypto_security_info_union_t *src) {
    *dest = *src;
    const void *source = NULL;
    size_t size = 0;
    switch (src->source) {
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (src->info.file.filename) {
            source = src->info.file.filename;
            size = strlen(src->info.file.filename) + 1;
            dest->info.file.filename = *data_buffer_ptr;
        }
        break;
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        if (src->info.path.path) {
            source = src->info.path.path;
            size = strlen(src->info.path.path) + 1;
            dest->info.path.path = *data_buffer_ptr;
        }
        break;
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        if (src->info.buffer.buffer) {
            source = src->info.buffer.buffer;
            size = src->info.buffer.buffer_size;
            dest->info.buffer.buffer = *data_buffer_ptr;
        }
        break;
    default:
        AVS_UNREACHABLE("Invalid data source type");
    }
    assert(!size || source);
    if (size) {
        memcpy(*data_buffer_ptr, source, size);
        *data_buffer_ptr += size;
    }
}

typedef struct {
    avs_crypto_security_info_union_t *array_ptr;
    char *data_buffer_ptr;
} array_copy_state_t;

static avs_error_t copy_into_array(const avs_crypto_security_info_union_t *desc,
                                   void *state_) {
    array_copy_state_t *state = (array_copy_state_t *) state_;
    copy_element(state->array_ptr++, &state->data_buffer_ptr, desc);
    return AVS_OK;
}

static avs_error_t copy_as_array(avs_crypto_security_info_union_t **out_array,
                                 size_t *out_element_count,
                                 const avs_crypto_security_info_union_t *desc,
                                 avs_crypto_security_info_tag_t tag) {
    if (!out_array || !out_element_count || *out_array) {
        return avs_errno(AVS_EINVAL);
    }
    security_info_stats_t stats = {
        .expected_type = tag
    };
    avs_error_t err = security_info_iterate(desc, calculate_info_stats, &stats);
    if (avs_is_err(err)) {
        return err;
    }
    *out_element_count = stats.element_count;
    if (stats.element_count
                    > SIZE_MAX / sizeof(avs_crypto_security_info_union_t)
            || stats.data_buffer_size
                           > SIZE_MAX
                                         - stats.element_count
                                                       * sizeof(avs_crypto_security_info_union_t)) {
        return avs_errno(AVS_ENOMEM);
    }
    size_t buffer_size =
            stats.element_count * sizeof(avs_crypto_security_info_union_t)
            + stats.data_buffer_size;
    if (buffer_size) {
        if (!(*out_array = (avs_crypto_security_info_union_t *) avs_malloc(
                      buffer_size))) {
            return avs_errno(AVS_ENOMEM);
        }
        array_copy_state_t state = {
            .array_ptr = *out_array,
            .data_buffer_ptr = (char *) &(*out_array)[stats.element_count]
        };
        err = security_info_iterate(desc, copy_into_array, &state);
        assert(avs_is_ok(err));
    }
    return AVS_OK;
}

avs_error_t avs_crypto_certificate_chain_info_copy_as_array(
        avs_crypto_certificate_chain_info_t **out_array,
        size_t *out_element_count,
        avs_crypto_certificate_chain_info_t trusted_cert_info) {
    return copy_as_array((avs_crypto_security_info_union_t **) out_array,
                         out_element_count, &trusted_cert_info.desc,
                         AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
}

avs_error_t avs_crypto_cert_revocation_list_info_copy_as_array(
        avs_crypto_cert_revocation_list_info_t **out_array,
        size_t *out_element_count,
        avs_crypto_cert_revocation_list_info_t crl_info) {
    return copy_as_array((avs_crypto_security_info_union_t **) out_array,
                         out_element_count, &crl_info.desc,
                         AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
}

#    ifdef AVS_COMMONS_WITH_AVS_LIST
avs_crypto_certificate_chain_info_t avs_crypto_certificate_chain_info_from_list(
        AVS_LIST(avs_crypto_certificate_chain_info_t) list) {
    avs_crypto_certificate_chain_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_LIST;
    result.desc.info.list.list_head = &list->desc;
#        ifndef NDEBUG
    AVS_LIST_ITERATE(list) {
        assert(list->desc.type == AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
    }
#        endif // NDEBUG
    return result;
}

avs_crypto_cert_revocation_list_info_t
avs_crypto_cert_revocation_list_info_from_list(
        AVS_LIST(avs_crypto_cert_revocation_list_info_t) list) {
    avs_crypto_cert_revocation_list_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_LIST;
    result.desc.info.list.list_head = &list->desc;
#        ifndef NDEBUG
    AVS_LIST_ITERATE(list) {
        assert(list->desc.type
               == AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
    }
#        endif // NDEBUG
    return result;
}

typedef struct {
    const int expected_type;
    AVS_LIST(avs_crypto_security_info_union_t) *tail_ptr;
} copy_into_list_state_t;

static avs_error_t copy_into_list(const avs_crypto_security_info_union_t *desc,
                                  void *state_) {
    copy_into_list_state_t *state = (copy_into_list_state_t *) state_;
    if (desc->type != state->expected_type) {
        return avs_errno(AVS_EINVAL);
    }
    size_t data_buffer_size = SIZE_MAX;
    avs_error_t err = calculate_data_buffer_size(&data_buffer_size, desc);
    if (avs_is_err(err)) {
        return err;
    }
    assert(!*state->tail_ptr);
    if (data_buffer_size > SIZE_MAX - sizeof(avs_crypto_security_info_union_t)
            || !(*state->tail_ptr = (AVS_LIST(avs_crypto_security_info_union_t))
                         AVS_LIST_NEW_BUFFER(
                                 sizeof(avs_crypto_security_info_union_t)
                                 + data_buffer_size))) {
        return avs_errno(AVS_ENOMEM);
    }
    // We allocated more data than sizeof(avs_crypto_trusted_cert_info_t)
    // so that the data buffer can be right after it in the same allocated
    // element. Let's calculate a pointer to that data.
    char *data_buffer_ptr = (char *) &(*state->tail_ptr)[1];
    copy_element(*state->tail_ptr, &data_buffer_ptr, desc);
    AVS_LIST_ADVANCE_PTR(&state->tail_ptr);
    return AVS_OK;
}

avs_error_t avs_crypto_certificate_chain_info_copy_as_list(
        AVS_LIST(avs_crypto_certificate_chain_info_t) *out_list,
        avs_crypto_certificate_chain_info_t trusted_cert_info) {
    if (!out_list || *out_list) {
        return avs_errno(AVS_EINVAL);
    }
    copy_into_list_state_t state = {
        .expected_type = AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN,
        .tail_ptr = (AVS_LIST(avs_crypto_security_info_union_t) *) out_list
    };
    avs_error_t err = security_info_iterate(&trusted_cert_info.desc,
                                            copy_into_list, &state);
    if (avs_is_err(err)) {
        AVS_LIST_CLEAR(out_list);
    }
    return err;
}

avs_error_t avs_crypto_cert_revocation_list_info_copy_as_list(
        AVS_LIST(avs_crypto_cert_revocation_list_info_t) *out_list,
        avs_crypto_cert_revocation_list_info_t crl_info) {
    if (!out_list || *out_list) {
        return avs_errno(AVS_EINVAL);
    }
    copy_into_list_state_t state = {
        .expected_type = AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST,
        .tail_ptr = (AVS_LIST(avs_crypto_security_info_union_t) *) out_list
    };
    avs_error_t err =
            security_info_iterate(&crl_info.desc, copy_into_list, &state);
    if (avs_is_err(err)) {
        AVS_LIST_CLEAR(out_list);
    }
    return err;
}
#    endif // AVS_COMMONS_WITH_AVS_LIST

avs_crypto_private_key_info_t
avs_crypto_private_key_info_from_file(const char *filename,
                                      const char *password) {
    avs_crypto_private_key_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_FILE;
    result.desc.info.file.filename = filename;
    result.desc.info.file.password = password;
    return result;
}

avs_crypto_private_key_info_t avs_crypto_private_key_info_from_buffer(
        const void *buffer, size_t buffer_size, const char *password) {
    avs_crypto_private_key_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_BUFFER;
    result.desc.info.buffer.buffer = buffer;
    result.desc.info.buffer.buffer_size = buffer_size;
    result.desc.info.buffer.password = password;
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
