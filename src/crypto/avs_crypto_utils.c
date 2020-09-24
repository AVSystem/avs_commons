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

#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
avs_crypto_certificate_chain_info_t
avs_crypto_certificate_chain_info_from_engine(const char *query) {
    avs_crypto_certificate_chain_info_t result;
    memset(&result, 0, sizeof(result));
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_ENGINE;
    result.desc.info.engine.query = query;
    return result;
}
#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE

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

typedef enum {
    DATA_SOURCE_ELEMENT_END = 0,
    DATA_SOURCE_ELEMENT_STRING,
    DATA_SOURCE_ELEMENT_BUFFER
} avs_crypto_data_source_element_type_t;

typedef struct {
    avs_crypto_data_source_element_type_t type;
    size_t offset;
    size_t size_offset;
} avs_crypto_data_source_element_t;

// NOTE: If the layout of any of the existing types changes (i.e., list of types
// and their semantics), proper persistence version number handling will need to
// be introduced; see also security_info_persistence().
const avs_crypto_data_source_element_t *const DATA_SOURCE_DEFINITIONS[] = {
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
                    .size_offset = offsetof(avs_crypto_security_info_union_t,
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
#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
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
#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
};

static avs_error_t
calculate_data_buffer_size(size_t *out_buffer_size,
                           const avs_crypto_security_info_union_t *desc) {
    if ((int) desc->source < 0
            || (size_t) desc->source > AVS_ARRAY_SIZE(DATA_SOURCE_DEFINITIONS)
            || !DATA_SOURCE_DEFINITIONS[desc->source]) {
        return avs_errno(AVS_EINVAL);
    }
    *out_buffer_size = 0;
    for (const avs_crypto_data_source_element_t *element =
                 DATA_SOURCE_DEFINITIONS[desc->source];
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
calculate_info_stats(const avs_crypto_security_info_union_t *desc,
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

static void copy_element(avs_crypto_security_info_union_t *dest,
                         char **data_buffer_ptr,
                         const avs_crypto_security_info_union_t *src) {
    assert(src->source >= 0);
    assert(src->source < AVS_ARRAY_SIZE(DATA_SOURCE_DEFINITIONS));
    assert(DATA_SOURCE_DEFINITIONS[src->source]);

    *dest = *src;
    for (const avs_crypto_data_source_element_t *element =
                 DATA_SOURCE_DEFINITIONS[src->source];
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
    *out_element_count = 0;
    avs_error_t err =
            security_info_iterate(desc, calculate_info_stats,
                                  &(calculate_info_stats_args_t) {
                                      .expected_type = tag,
                                      .out_element_count = out_element_count,
                                      .out_data_buffer_size = &data_buffer_size
                                  });
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

#    ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
avs_crypto_private_key_info_t
avs_crypto_private_key_info_from_engine(const char *query) {
    avs_crypto_private_key_info_t result;
    result.desc.type = AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY;
    result.desc.source = AVS_CRYPTO_DATA_SOURCE_ENGINE;
    result.desc.info.engine.query = query;
    return result;
}
#    endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE

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
    avs_error_t err = security_info_iterate(
            &private_key_info.desc, calculate_info_stats,
            &(calculate_info_stats_args_t) {
                .expected_type = AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY,
                .out_element_count = &element_count,
                .out_data_buffer_size = &data_buffer_size
            });
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

#    ifdef AVS_COMMONS_WITH_AVS_PERSISTENCE
static avs_error_t data_source_persistence(avs_persistence_context_t *ctx,
                                           avs_crypto_data_source_t *source) {
    avs_persistence_direction_t direction = avs_persistence_direction(ctx);
    int8_t source_ch;
    if (direction == AVS_PERSISTENCE_STORE) {
        switch (*source) {
        case AVS_CRYPTO_DATA_SOURCE_EMPTY:
            source_ch = '\0';
            break;
        case AVS_CRYPTO_DATA_SOURCE_FILE:
            source_ch = 'F';
            break;
        case AVS_CRYPTO_DATA_SOURCE_PATH:
            source_ch = 'P';
            break;
        case AVS_CRYPTO_DATA_SOURCE_BUFFER:
            source_ch = 'B';
            break;
#        ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
        case AVS_CRYPTO_DATA_SOURCE_ENGINE:
            source_ch = 'E';
            break;
#        endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
        default:
            return avs_errno(AVS_EINVAL);
        }
    }

    avs_error_t err = avs_persistence_i8(ctx, &source_ch);
    if (avs_is_err(err)) {
        return err;
    }

    if (direction == AVS_PERSISTENCE_RESTORE) {
        switch (source_ch) {
        case '\0':
            *source = AVS_CRYPTO_DATA_SOURCE_EMPTY;
            break;
        case 'F':
            *source = AVS_CRYPTO_DATA_SOURCE_FILE;
            break;
        case 'P':
            *source = AVS_CRYPTO_DATA_SOURCE_PATH;
            break;
        case 'B':
            *source = AVS_CRYPTO_DATA_SOURCE_BUFFER;
            break;
#        ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
        case 'E':
            *source = AVS_CRYPTO_DATA_SOURCE_ENGINE;
            break;
#        endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
        default:
            return avs_errno(AVS_EIO);
        }
    }

    return AVS_OK;
}

static avs_error_t
security_info_buffer_contents_persist(avs_persistence_context_t *ctx,
                                      avs_crypto_security_info_union_t *desc,
                                      size_t buffer_size) {
    assert(avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE);
    size_t bytes_written = 0;
    for (const avs_crypto_data_source_element_t *element =
                 DATA_SOURCE_DEFINITIONS[desc->source];
         element->type != DATA_SOURCE_ELEMENT_END;
         ++element) {
        switch (element->type) {
        case DATA_SOURCE_ELEMENT_STRING: {
            const char **str_ptr =
                    AVS_APPLY_OFFSET(const char *, desc, element->offset);
            if (*str_ptr) {
                size_t size = strlen(*str_ptr) + 1;
                avs_error_t err =
                        avs_persistence_bytes(ctx, (char *) (intptr_t) *str_ptr,
                                              size);
                if (avs_is_err(err)) {
                    return err;
                }
                bytes_written += size;
            }
            break;
        }
        case DATA_SOURCE_ELEMENT_BUFFER: {
            const void **entry_ptr =
                    AVS_APPLY_OFFSET(const void *, desc, element->offset);
            size_t *size_ptr =
                    AVS_APPLY_OFFSET(size_t, desc, element->size_offset);
            if (*entry_ptr) {
                avs_error_t err = avs_persistence_bytes(
                        ctx, (void *) (intptr_t) *entry_ptr, *size_ptr);
                if (avs_is_err(err)) {
                    return err;
                }
                bytes_written += *size_ptr;
            }
            break;
        }
        default:
            AVS_UNREACHABLE("Invalid data source element type");
        }
    }
    assert(bytes_written == buffer_size);
    (void) buffer_size;
    return AVS_OK;
}

static avs_error_t security_info_buffer_offsets_persistence(
        avs_persistence_context_t *ctx,
        char *data_buffer,
        size_t buffer_size,
        avs_crypto_security_info_union_t *desc) {
    avs_persistence_direction_t direction = avs_persistence_direction(ctx);
    assert(data_buffer || direction != AVS_PERSISTENCE_RESTORE);
    size_t offset = 0;
    for (const avs_crypto_data_source_element_t *element =
                 DATA_SOURCE_DEFINITIONS[desc->source];
         element->type != DATA_SOURCE_ELEMENT_END;
         ++element) {
        switch (element->type) {
        case DATA_SOURCE_ELEMENT_STRING: {
            const char **str_ptr =
                    AVS_APPLY_OFFSET(const char *, desc, element->offset);
            uint32_t size32 = UINT32_MAX;
            if (direction == AVS_PERSISTENCE_STORE && *str_ptr) {
                size_t size = strlen(*str_ptr);
                if (size >= UINT32_MAX) {
                    return avs_errno(AVS_E2BIG);
                }
                size32 = (uint32_t) size;
            }
            avs_error_t err = avs_persistence_u32(ctx, &size32);
            if (avs_is_err(err)) {
                return err;
            }
            if (size32 != UINT32_MAX) {
                if (offset + size32 >= buffer_size) {
                    return avs_errno(AVS_EINVAL);
                }
                if (direction == AVS_PERSISTENCE_RESTORE) {
                    if (data_buffer[offset + size32] != '\0') {
                        return avs_errno(AVS_EINVAL);
                    }
                    *str_ptr = &data_buffer[offset];
                }
                offset += size32 + 1;
            }
            break;
        }
        case DATA_SOURCE_ELEMENT_BUFFER: {
            const void **entry_ptr =
                    AVS_APPLY_OFFSET(const void *, desc, element->offset);
            size_t *size_ptr =
                    AVS_APPLY_OFFSET(size_t, desc, element->size_offset);
            uint32_t size = UINT32_MAX;
            if (direction == AVS_PERSISTENCE_STORE && *entry_ptr) {
                if (*size_ptr >= UINT32_MAX) {
                    return avs_errno(AVS_E2BIG);
                }
                size = (uint32_t) *size_ptr;
            }
            avs_error_t err = avs_persistence_u32(ctx, &size);
            if (avs_is_err(err)) {
                return err;
            }
            if (size != UINT32_MAX) {
                if (offset + size > buffer_size) {
                    return avs_errno(AVS_EINVAL);
                }
                if (direction == AVS_PERSISTENCE_RESTORE) {
                    *entry_ptr = &data_buffer[offset];
                    *size_ptr = size;
                }
                offset += size;
            }
            break;
        }
        default:
            AVS_UNREACHABLE("Invalid data source element type");
        }
    }
    if (offset != buffer_size) {
        return avs_errno(AVS_EINVAL);
    }
    return AVS_OK;
}

typedef avs_error_t security_info_persistence_allocator_t(
        avs_crypto_security_info_union_t **out_desc_ptr,
        void **out_buffer_ptr,
        size_t buffer_size,
        void *arg);

static avs_error_t
security_info_persistence(avs_persistence_context_t *ctx,
                          avs_crypto_security_info_union_t **desc_ptr,
                          avs_crypto_security_info_tag_t tag,
                          security_info_persistence_allocator_t *allocator,
                          void *allocator_arg) {
    avs_persistence_direction_t direction = avs_persistence_direction(ctx);
    avs_crypto_data_source_t source;
    if (direction == AVS_PERSISTENCE_STORE) {
        assert((*desc_ptr)->type == tag);
        source = (*desc_ptr)->source;
    }
    avs_error_t err = data_source_persistence(ctx, &source);
    if (avs_is_err(err)) {
        return err;
    }
    if ((int) source < 0 || source >= AVS_ARRAY_SIZE(DATA_SOURCE_DEFINITIONS)
            || !DATA_SOURCE_DEFINITIONS[source]) {
        return avs_errno(AVS_EINVAL);
    }

    // NOTE: Version hardcoded to 0 for now.
    // This will need to be updated if incompatible changes to
    // DATA_SOURCE_DEFINITIONS are made.
    if (avs_is_err((err = avs_persistence_version(ctx, &(uint8_t) { 0 },
                                                  &(const uint8_t[]) { 0 }[0],
                                                  1)))) {
        return err;
    }

    uint32_t buffer_size32 = 0;
    if (DATA_SOURCE_DEFINITIONS[source][0].type != DATA_SOURCE_ELEMENT_END) {
        if (direction == AVS_PERSISTENCE_STORE) {
            size_t buffer_size;
            if (avs_is_ok((err = calculate_data_buffer_size(&buffer_size,
                                                            *desc_ptr)))
                    && buffer_size > UINT32_MAX) {
                err = avs_errno(AVS_E2BIG);
            }
            if (avs_is_err(err)) {
                return err;
            }
            buffer_size32 = (uint32_t) buffer_size;
        }
        if (avs_is_err((err = avs_persistence_u32(ctx, &buffer_size32)))) {
            return err;
        }
    }

    void *data_buffer = NULL;
    if (direction == AVS_PERSISTENCE_STORE) {
        if (avs_is_err((err = security_info_buffer_contents_persist(
                                ctx, *desc_ptr, buffer_size32)))) {
            return err;
        }
    } else {
        assert(desc_ptr && !*desc_ptr);
        assert(allocator);
        if (avs_is_err((err = allocator(desc_ptr, &data_buffer, buffer_size32,
                                        allocator_arg)))) {
            return err;
        }
        assert(*desc_ptr);
        assert(data_buffer);
        (*desc_ptr)->type = tag;
        (*desc_ptr)->source = source;
        if (avs_is_err((err = avs_persistence_bytes(ctx, data_buffer,
                                                    buffer_size32)))) {
            return err;
        }
    }

    return security_info_buffer_offsets_persistence(ctx, (char *) data_buffer,
                                                    buffer_size32, *desc_ptr);
}

typedef struct {
    avs_persistence_context_t *ctx;
    avs_crypto_security_info_tag_t tag;
} security_info_persist_args_t;

static avs_error_t
security_info_persist_entry_clb(const avs_crypto_security_info_union_t *desc,
                                void *args_) {
    security_info_persist_args_t *args = (security_info_persist_args_t *) args_;
    assert(avs_persistence_direction(args->ctx) == AVS_PERSISTENCE_STORE);
    avs_crypto_security_info_union_t *desc_noconst =
            (avs_crypto_security_info_union_t *) (intptr_t) desc;
    return security_info_persistence(args->ctx, &desc_noconst, args->tag, NULL,
                                     NULL);
}

static avs_error_t
security_info_persist(avs_persistence_context_t *ctx,
                      const avs_crypto_security_info_union_t *desc,
                      avs_crypto_security_info_tag_t tag) {
    if (avs_persistence_direction(ctx) != AVS_PERSISTENCE_STORE) {
        return avs_errno(AVS_EINVAL);
    }
    size_t element_count = 0;
    avs_error_t err =
            security_info_iterate(desc, calculate_info_stats,
                                  &(calculate_info_stats_args_t) {
                                      .expected_type = tag,
                                      .out_element_count = &element_count
                                  });
    if (avs_is_err(err)) {
        return err;
    }
    if (element_count > UINT32_MAX) {
        return avs_errno(AVS_E2BIG);
    }
    err = avs_persistence_u32(ctx, &(uint32_t) { (uint32_t) element_count });
    return security_info_iterate(desc, security_info_persist_entry_clb,
                                 &(security_info_persist_args_t) {
                                     .ctx = ctx,
                                     .tag = tag
                                 });
}

typedef struct {
    avs_crypto_security_info_union_t *array;
    size_t element_count;
    size_t allocated_size;
    size_t next_index;
} security_info_array_allocator_state_t;

static avs_error_t
security_info_array_allocator(avs_crypto_security_info_union_t **out_desc_ptr,
                              void **out_buffer_ptr,
                              size_t buffer_size,
                              void *state_) {
    security_info_array_allocator_state_t *state =
            (security_info_array_allocator_state_t *) state_;
    assert(state->next_index < state->element_count);
    avs_crypto_security_info_union_t *reallocated = state->array;
    if (buffer_size > 0) {
        if (!(reallocated = (avs_crypto_security_info_union_t *) avs_realloc(
                      reallocated, state->allocated_size + buffer_size))) {
            return avs_errno(AVS_ENOMEM);
        }
    }
    if (reallocated != state->array) {
        // Array have been moved, fix existing data pointers
        for (size_t i = 0; i < state->next_index; ++i) {
            for (const avs_crypto_data_source_element_t *element =
                         DATA_SOURCE_DEFINITIONS[reallocated[i].source];
                 element->type != DATA_SOURCE_ELEMENT_END;
                 ++element) {
                switch (element->type) {
                case DATA_SOURCE_ELEMENT_STRING: {
                    const char **str_ptr =
                            AVS_APPLY_OFFSET(const char *, &reallocated[i],
                                             element->offset);
                    if (*str_ptr) {
                        *str_ptr = (const char *) reallocated
                                   + (*str_ptr - (const char *) state->array);
                    }
                    break;
                }
                case DATA_SOURCE_ELEMENT_BUFFER: {
                    const void **entry_ptr =
                            AVS_APPLY_OFFSET(const void *, &reallocated[i],
                                             element->offset);
                    if (*entry_ptr) {
                        *entry_ptr = (const char *) reallocated
                                     + ((const char *) *entry_ptr
                                        - (const char *) state->array);
                    }
                    break;
                }
                default:
                    AVS_UNREACHABLE("Invalid data source element type");
                }
            }
        }
    }
    *out_desc_ptr = &reallocated[state->next_index++];
    *out_buffer_ptr = (char *) reallocated + state->allocated_size;
    state->array = reallocated;
    state->allocated_size += buffer_size;
    return AVS_OK;
}

static avs_error_t security_info_array_persistence(
        avs_persistence_context_t *ctx,
        const avs_crypto_security_info_union_t **array_ptr,
        size_t *element_count_ptr,
        avs_crypto_security_info_tag_t tag) {
    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        return security_info_persist(
                ctx,
                &(avs_crypto_security_info_union_t) {
                    .type = tag,
                    .source = AVS_CRYPTO_DATA_SOURCE_ARRAY,
                    .info = {
                        .array = {
                            .array_ptr = *array_ptr,
                            .element_count = *element_count_ptr
                        }
                    }
                },
                tag);
    } else {
        uint32_t element_count32;
        avs_error_t err = avs_persistence_u32(ctx, &element_count32);
        if (avs_is_err(err)) {
            return err;
        }

        security_info_array_allocator_state_t state = {
            .element_count = element_count32
        };
        state.allocated_size =
                element_count32 * sizeof(avs_crypto_security_info_union_t);
        if (!(state.array = (avs_crypto_security_info_union_t *) avs_calloc(
                      1, state.allocated_size))) {
            return avs_errno(AVS_ENOMEM);
        }

        for (size_t i = 0; avs_is_ok(err) && i < state.element_count; ++i) {
            err = security_info_persistence(
                    ctx, &(avs_crypto_security_info_union_t *) { NULL }, tag,
                    security_info_array_allocator, &state);
        }
        if (avs_is_err(err)) {
            avs_free(state.array);
        } else {
            *array_ptr = state.array;
            *element_count_ptr = element_count32;
        }
        return err;
    }
}

static avs_error_t
security_info_list_allocator(avs_crypto_security_info_union_t **out_desc_ptr,
                             void **out_buffer_ptr,
                             size_t buffer_size,
                             void *arg) {
    (void) arg;
    if (!(*out_desc_ptr = (AVS_LIST(avs_crypto_security_info_union_t))
                  AVS_LIST_NEW_BUFFER(sizeof(avs_crypto_security_info_union_t)
                                      + buffer_size))) {
        return avs_errno(AVS_ENOMEM);
    }
    *out_buffer_ptr = *out_desc_ptr + 1;
    return AVS_OK;
}

static avs_error_t
security_info_list_element_persistence(avs_persistence_context_t *ctx,
                                       AVS_LIST(void) *element,
                                       void *tag_ptr) {
    return security_info_persistence(
            ctx, (AVS_LIST(avs_crypto_security_info_union_t) *) element,
            *(avs_crypto_security_info_tag_t *) tag_ptr,
            security_info_list_allocator, NULL);
}

static void null_cleanup(void *element) {
    (void) element;
}

static avs_error_t security_info_list_persistence(
        avs_persistence_context_t *ctx,
        AVS_LIST(avs_crypto_security_info_union_t) *list_ptr,
        avs_crypto_security_info_tag_t tag) {
    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        return security_info_persist(ctx,
                                     &(avs_crypto_security_info_union_t) {
                                         .type = tag,
                                         .source = AVS_CRYPTO_DATA_SOURCE_LIST,
                                         .info = {
                                             .list = {
                                                 .list_head = *list_ptr
                                             }
                                         }
                                     },
                                     tag);
    } else {
        return avs_persistence_custom_allocated_list(
                ctx, (AVS_LIST(void) *) list_ptr,
                security_info_list_element_persistence, &tag, null_cleanup);
    }
}

avs_error_t avs_crypto_certificate_chain_info_persist(
        avs_persistence_context_t *ctx,
        avs_crypto_certificate_chain_info_t certificate_chain_info) {
    return security_info_persist(ctx, &certificate_chain_info.desc,
                                 AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
}

avs_error_t avs_crypto_certificate_chain_info_array_persistence(
        avs_persistence_context_t *ctx,
        const avs_crypto_certificate_chain_info_t **array_ptr,
        size_t *element_count_ptr) {
    return security_info_array_persistence(
            ctx, (const avs_crypto_security_info_union_t **) array_ptr,
            element_count_ptr, AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
}

avs_error_t avs_crypto_certificate_chain_info_list_persistence(
        avs_persistence_context_t *ctx,
        AVS_LIST(avs_crypto_certificate_chain_info_t) *list_ptr) {
    return security_info_list_persistence(
            ctx, (AVS_LIST(avs_crypto_security_info_union_t) *) list_ptr,
            AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
}

avs_error_t avs_crypto_cert_revocation_list_info_persist(
        avs_persistence_context_t *ctx,
        avs_crypto_cert_revocation_list_info_t crl_info) {
    return security_info_persist(ctx, &crl_info.desc,
                                 AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
}

avs_error_t avs_crypto_cert_revocation_list_info_array_persistence(
        avs_persistence_context_t *ctx,
        const avs_crypto_cert_revocation_list_info_t **array_ptr,
        size_t *element_count_ptr) {
    return security_info_array_persistence(
            ctx, (const avs_crypto_security_info_union_t **) array_ptr,
            element_count_ptr, AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
}

avs_error_t avs_crypto_cert_revocation_list_info_list_persistence(
        avs_persistence_context_t *ctx,
        AVS_LIST(avs_crypto_cert_revocation_list_info_t) *list_ptr) {
    return security_info_list_persistence(
            ctx, (AVS_LIST(avs_crypto_security_info_union_t) *) list_ptr,
            AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
}

static avs_error_t
private_key_allocator(avs_crypto_security_info_union_t **out_desc_ptr,
                      void **out_buffer_ptr,
                      size_t buffer_size,
                      void *arg) {
    (void) arg;
    if (!(*out_desc_ptr = (avs_crypto_security_info_union_t *) avs_calloc(
                  1, sizeof(avs_crypto_security_info_union_t) + buffer_size))) {
        return avs_errno(AVS_ENOMEM);
    }
    *out_buffer_ptr = *out_desc_ptr + 1;
    return AVS_OK;
}

avs_error_t avs_crypto_private_key_info_persistence(
        avs_persistence_context_t *ctx,
        avs_crypto_private_key_info_t **private_key_ptr) {
    return security_info_persistence(
            ctx, (avs_crypto_security_info_union_t **) private_key_ptr,
            AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY, private_key_allocator, NULL);
}
#    endif // AVS_COMMONS_WITH_AVS_PERSISTENCE

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
