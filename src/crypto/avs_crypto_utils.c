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

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
avs_crypto_certificate_chain_info_t
avs_crypto_certificate_chain_info_from_engine(const char *query) {
    avs_crypto_certificate_chain_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_ENGINE;
    result.desc.info.engine.query = query;
    return result;
}
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE

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

avs_error_t
_avs_crypto_security_info_iterate(const avs_crypto_security_info_union_t *desc,
                                  avs_crypto_security_info_iterate_cb_t *cb,
                                  void *cb_arg) {
    switch (desc->source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0; avs_is_ok(err) && i < desc->info.array.element_count;
             ++i) {
            err = _avs_crypto_security_info_iterate(
                    &desc->info.array.array_ptr[i], cb, cb_arg);
        }
        return err;
    }
#    ifdef AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_LIST: {
        AVS_LIST(avs_crypto_security_info_union_t) entry;
        AVS_LIST_FOREACH(entry, desc->info.list.list_head) {
            avs_error_t err =
                    _avs_crypto_security_info_iterate(entry, cb, cb_arg);
            if (avs_is_err(err)) {
                return err;
            }
        }
        return AVS_OK;
    }
#    endif // AVS_COMMONS_WITH_AVS_LIST
    default:
        return cb(desc, cb_arg);
    }
}

// NOTE: If the layout of any of the existing types changes (i.e., list of types
// and their semantics), proper persistence version number handling will need to
// be introduced; see also security_info_persistence().
static const avs_crypto_data_source_element_t
        *const DATA_SOURCE_DEFINITIONS[] = {
            [AVS_CRYPTO_DATA_SOURCE_EMPTY] =
                    &(const avs_crypto_data_source_element_t[]) {
                        {
                            .type = DATA_SOURCE_ELEMENT_END
                        }
                    }[0],
            [AVS_CRYPTO_DATA_SOURCE_FILE] =
                    &(const avs_crypto_data_source_element_t[]) {
                        {
                            .type = DATA_SOURCE_ELEMENT_STRING,
                            .offset = offsetof(avs_crypto_security_info_union_t,
                                               info.file.filename)
                        },
                        {
                            .type = DATA_SOURCE_ELEMENT_STRING,
                            .offset = offsetof(avs_crypto_security_info_union_t,
                                               info.file.password)
                        },
                        {
                            .type = DATA_SOURCE_ELEMENT_END
                        }
                    }[0],
            [AVS_CRYPTO_DATA_SOURCE_PATH] =
                    &(const avs_crypto_data_source_element_t[]) {
                        {
                            .type = DATA_SOURCE_ELEMENT_STRING,
                            .offset = offsetof(avs_crypto_security_info_union_t,
                                               info.path.path)
                        },
                        {
                            .type = DATA_SOURCE_ELEMENT_END
                        }
                    }[0],
            [AVS_CRYPTO_DATA_SOURCE_BUFFER] =
                    &(const avs_crypto_data_source_element_t[]) {
                        {
                            .type = DATA_SOURCE_ELEMENT_BUFFER,
                            .offset = offsetof(avs_crypto_security_info_union_t,
                                               info.buffer.buffer),
                            .size_offset =
                                    offsetof(avs_crypto_security_info_union_t,
                                             info.buffer.buffer_size)
                        },
                        {
                            .type = DATA_SOURCE_ELEMENT_STRING,
                            .offset = offsetof(avs_crypto_security_info_union_t,
                                               info.buffer.password)
                        },
                        {
                            .type = DATA_SOURCE_ELEMENT_END
                        }
                    }[0]
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
            ,
            [AVS_CRYPTO_DATA_SOURCE_ENGINE] =
                    &(const avs_crypto_data_source_element_t[]) {
                        {
                            .type = DATA_SOURCE_ELEMENT_STRING,
                            .offset = offsetof(avs_crypto_security_info_union_t,
                                               info.engine.query)
                        },
                        {
                            .type = DATA_SOURCE_ELEMENT_END
                        }
                    }[0]
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
        };

const avs_crypto_data_source_element_t *
_avs_crypto_get_data_source_definition(avs_crypto_data_source_t source) {
    if ((int) source < 0
            || (size_t) source > AVS_ARRAY_SIZE(DATA_SOURCE_DEFINITIONS)) {
        return NULL;
    }
    return DATA_SOURCE_DEFINITIONS[source];
}

static avs_error_t
calculate_data_buffer_size(size_t *out_buffer_size,
                           const avs_crypto_security_info_union_t *desc) {
    const avs_crypto_data_source_element_t *source_def =
            _avs_crypto_get_data_source_definition(desc->source);
    if (!source_def) {
        return avs_errno(AVS_EINVAL);
    }
    *out_buffer_size = 0;
    for (const avs_crypto_data_source_element_t *element = source_def;
         element->type != DATA_SOURCE_ELEMENT_END;
         ++element) {
        switch (element->type) {
        case DATA_SOURCE_ELEMENT_STRING: {
            const char *str =
                    *AVS_APPLY_OFFSET(const char *const, desc, element->offset);
            if (str) {
                *out_buffer_size += strlen(str) + 1;
            }
            break;
        }
        case DATA_SOURCE_ELEMENT_BUFFER:
            if (*AVS_APPLY_OFFSET(const void *const, desc, element->offset)) {
                *out_buffer_size += *AVS_APPLY_OFFSET(const size_t, desc,
                                                      element->size_offset);
            }
            break;
        default:
            AVS_UNREACHABLE("Invalid data source element type");
        }
    }
    return AVS_OK;
}

typedef struct {
    const avs_crypto_security_info_tag_t expected_type;
    size_t *out_element_count;
    size_t *out_data_buffer_size;
} calculate_info_stats_args_t;

static avs_error_t
calculate_info_stats_cb(const avs_crypto_security_info_union_t *desc,
                        void *args_) {
    calculate_info_stats_args_t *args = (calculate_info_stats_args_t *) args_;
    if (desc->type != args->expected_type) {
        return avs_errno(AVS_EINVAL);
    }
    if (args->out_element_count) {
        ++*args->out_element_count;
    }
    if (args->out_data_buffer_size) {
        size_t element_buffer_size = 0;
        avs_error_t err =
                calculate_data_buffer_size(&element_buffer_size, desc);
        if (avs_is_ok(err)
                && element_buffer_size
                               >= SIZE_MAX - *args->out_data_buffer_size) {
            err = avs_errno(AVS_ENOMEM);
        }
        if (avs_is_err(err)) {
            return err;
        }
        *args->out_data_buffer_size += element_buffer_size;
    }
    return AVS_OK;
}

avs_error_t
_avs_crypto_calculate_info_stats(const avs_crypto_security_info_union_t *desc,
                                 avs_crypto_security_info_tag_t expected_type,
                                 size_t *out_element_count,
                                 size_t *out_data_buffer_size) {
    if (out_element_count) {
        *out_element_count = 0;
    }
    if (out_data_buffer_size) {
        *out_data_buffer_size = 0;
    }
    return _avs_crypto_security_info_iterate(
            desc, calculate_info_stats_cb,
            &(calculate_info_stats_args_t) {
                .expected_type = expected_type,
                .out_element_count = out_element_count,
                .out_data_buffer_size = out_data_buffer_size
            });
}

static void copy_element(avs_crypto_security_info_union_t *dest,
                         char **data_buffer_ptr,
                         const avs_crypto_security_info_union_t *src) {
    *dest = *src;
    for (const avs_crypto_data_source_element_t *element =
                 _avs_crypto_get_data_source_definition(src->source);
         element->type != DATA_SOURCE_ELEMENT_END;
         ++element) {
        switch (element->type) {
        case DATA_SOURCE_ELEMENT_STRING: {
            const char *str =
                    *AVS_APPLY_OFFSET(const char *const, src, element->offset);
            if (str) {
                size_t size = strlen(str) + 1;
                *AVS_APPLY_OFFSET(const char *, dest, element->offset) =
                        *data_buffer_ptr;
                memcpy(*data_buffer_ptr, str, size);
                *data_buffer_ptr += size;
            }
            break;
        }
        case DATA_SOURCE_ELEMENT_BUFFER: {
            const void *buffer =
                    *AVS_APPLY_OFFSET(const void *const, src, element->offset);
            if (buffer) {
                size_t size = *AVS_APPLY_OFFSET(const size_t, src,
                                                element->size_offset);
                *AVS_APPLY_OFFSET(const void *, dest, element->offset) =
                        *data_buffer_ptr;
                memcpy(*data_buffer_ptr, buffer, size);
                *AVS_APPLY_OFFSET(size_t, dest, element->size_offset) = size;
                *data_buffer_ptr += size;
            }
            break;
        }
        default:
            AVS_UNREACHABLE("Invalid data source element type");
        }
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
    size_t data_buffer_size = 0;
    avs_error_t err =
            _avs_crypto_calculate_info_stats(desc, tag, out_element_count,
                                             &data_buffer_size);
    if (avs_is_err(err)) {
        return err;
    }
    if (*out_element_count > SIZE_MAX / sizeof(avs_crypto_security_info_union_t)
            || data_buffer_size
                           > SIZE_MAX
                                         - *out_element_count
                                                       * sizeof(avs_crypto_security_info_union_t)) {
        return avs_errno(AVS_ENOMEM);
    }
    size_t buffer_size =
            *out_element_count * sizeof(avs_crypto_security_info_union_t)
            + data_buffer_size;
    if (buffer_size) {
        if (!(*out_array = (avs_crypto_security_info_union_t *) avs_malloc(
                      buffer_size))) {
            return avs_errno(AVS_ENOMEM);
        }
        array_copy_state_t state = {
            .array_ptr = *out_array,
            .data_buffer_ptr = (char *) &(*out_array)[*out_element_count]
        };
        err = _avs_crypto_security_info_iterate(desc, copy_into_array, &state);
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
    const avs_crypto_security_info_tag_t expected_type;
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
    avs_error_t err = _avs_crypto_security_info_iterate(&trusted_cert_info.desc,
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
    avs_error_t err = _avs_crypto_security_info_iterate(&crl_info.desc,
                                                        copy_into_list, &state);
    if (avs_is_err(err)) {
        AVS_LIST_CLEAR(out_list);
    }
    return err;
}
#    endif // AVS_COMMONS_WITH_AVS_LIST

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
avs_crypto_private_key_info_t
avs_crypto_private_key_info_from_engine(const char *query) {
    avs_crypto_private_key_info_t result;
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_ENGINE;
    result.desc.info.engine.query = query;
    return result;
}
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE

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

avs_error_t avs_crypto_private_key_info_copy(
        avs_crypto_private_key_info_t **out_ptr,
        avs_crypto_private_key_info_t private_key_info) {
    if (!out_ptr || *out_ptr
            || private_key_info.desc.source == AVS_CRYPTO_DATA_SOURCE_ARRAY
            || private_key_info.desc.source == AVS_CRYPTO_DATA_SOURCE_LIST) {
        return avs_errno(AVS_EINVAL);
    }
    size_t element_count = 0;
    size_t data_buffer_size = 0;
    avs_error_t err = _avs_crypto_calculate_info_stats(
            &private_key_info.desc, AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY,
            &element_count, &data_buffer_size);
    if (avs_is_err(err)) {
        return err;
    }
    assert(element_count == 0 || element_count == 1);
    if (!(*out_ptr = (avs_crypto_private_key_info_t *) avs_malloc(
                  sizeof(avs_crypto_private_key_info_t) + data_buffer_size))) {
        return avs_errno(AVS_ENOMEM);
    }
    char *buffer_ptr = (char *) &(*out_ptr)[1];
    copy_element(&(*out_ptr)->desc, &buffer_ptr, &private_key_info.desc);
    assert(buffer_ptr == ((char *) &(*out_ptr)[1]) + data_buffer_size);
    if ((*out_ptr)->desc.source == AVS_CRYPTO_DATA_SOURCE_EMPTY) {
        // EMPTY entries are allowed to have uninitialized type,
        // to support zero-initialization
        (*out_ptr)->desc.type = AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY;
    }
    assert((*out_ptr)->desc.type == AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY);
    return AVS_OK;
}

#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PKI

_avs_crypto_cert_encoding_t _avs_crypto_detect_cert_encoding(const void *buffer,
                                                             size_t len) {
    static const char PEM_PREFIX[] = "-----BEGIN ";
    assert(buffer || !len);
    if (len >= strlen(PEM_PREFIX)
            && !memcmp(buffer, PEM_PREFIX, strlen(PEM_PREFIX))) {
        return ENCODING_PEM;
    } else {
        return ENCODING_DER;
    }
}

#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_PKI

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
