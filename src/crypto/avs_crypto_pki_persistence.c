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

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) \
        && defined(AVS_COMMONS_WITH_AVS_PERSISTENCE)

#    include <avsystem/commons/avs_crypto_pki.h>

#    include "avs_crypto_utils.h"

#    define MODULE_NAME avs_crypto
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

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
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
        case AVS_CRYPTO_DATA_SOURCE_ENGINE:
            source_ch = 'E';
            break;
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
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
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
        case 'E':
            *source = AVS_CRYPTO_DATA_SOURCE_ENGINE;
            break;
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
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
                 _avs_crypto_get_data_source_definition(desc->source);
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
                 _avs_crypto_get_data_source_definition(desc->source);
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
                if (size32 >= buffer_size - offset) {
                    return avs_errno(AVS_EINVAL);
                }
                if (direction == AVS_PERSISTENCE_RESTORE) {
                    if (data_buffer[offset + size32] != '\0'
                            || strlen(&data_buffer[offset])
                                           != (size_t) size32) {
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
                if (size > buffer_size - offset) {
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

// NOTE: Version hardcoded to 0 for now.
// This will need to be updated if incompatible changes to
// DATA_SOURCE_DEFINITIONS are made.
static const uint8_t SECURITY_INFO_PERSISTENCE_VERSION = 0;

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
    avs_crypto_data_source_t source = AVS_CRYPTO_DATA_SOURCE_EMPTY;
    assert(desc_ptr);
    if (direction == AVS_PERSISTENCE_STORE) {
        assert(*desc_ptr);
        source = (*desc_ptr)->source;
        if (source != AVS_CRYPTO_DATA_SOURCE_EMPTY) {
            assert((*desc_ptr)->type == tag);
        }
    }
    avs_error_t err = data_source_persistence(ctx, &source);
    if (avs_is_err(err)) {
        return err;
    }
    const avs_crypto_data_source_element_t *source_def =
            _avs_crypto_get_data_source_definition(source);
    if (!source_def) {
        return avs_errno(AVS_EINVAL);
    }

    if (avs_is_err(
                (err = avs_persistence_version(
                         ctx, &(uint8_t) { SECURITY_INFO_PERSISTENCE_VERSION },
                         &SECURITY_INFO_PERSISTENCE_VERSION, 1)))) {
        return err;
    }

    uint32_t buffer_size32 = 0;
    if (source_def[0].type != DATA_SOURCE_ELEMENT_END) {
        if (direction == AVS_PERSISTENCE_STORE) {
            size_t buffer_size;
            if (avs_is_ok((err = _avs_crypto_calculate_info_stats(
                                   *desc_ptr, tag, NULL, &buffer_size)))
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
        assert(!*desc_ptr);
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
            _avs_crypto_calculate_info_stats(desc, tag, &element_count, NULL);
    if (avs_is_err(err)) {
        return err;
    }
    if (element_count > UINT32_MAX) {
        return avs_errno(AVS_E2BIG);
    }
    if (avs_is_err((err = avs_persistence_u32(
                            ctx, &(uint32_t) { (uint32_t) element_count })))) {
        return err;
    }
    return _avs_crypto_security_info_iterate(desc,
                                             security_info_persist_entry_clb,
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
                         _avs_crypto_get_data_source_definition(
                                 reallocated[i].source);
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

static avs_error_t
security_info_array_persistence(avs_persistence_context_t *ctx,
                                avs_crypto_security_info_union_t **array_ptr,
                                size_t *element_count_ptr,
                                avs_crypto_security_info_tag_t tag) {
    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        assert(array_ptr);
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
        assert(array_ptr && !*array_ptr);
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
        if (state.allocated_size
                && !(state.array = (avs_crypto_security_info_union_t *)
                             avs_calloc(1, state.allocated_size))) {
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
        assert(list_ptr);
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
        avs_crypto_certificate_chain_info_t **array_ptr,
        size_t *element_count_ptr) {
    return security_info_array_persistence(
            ctx, (avs_crypto_security_info_union_t **) array_ptr,
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
        avs_crypto_cert_revocation_list_info_t **array_ptr,
        size_t *element_count_ptr) {
    return security_info_array_persistence(
            ctx, (avs_crypto_security_info_union_t **) array_ptr,
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
    avs_persistence_direction_t direction = avs_persistence_direction(ctx);
    avs_crypto_security_info_union_t *private_key = NULL;
    if (direction == AVS_PERSISTENCE_STORE) {
        private_key = &(*private_key_ptr)->desc;
    }
    avs_error_t err =
            security_info_persistence(ctx, &private_key,
                                      AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY,
                                      private_key_allocator, NULL);
    if (direction == AVS_PERSISTENCE_RESTORE) {
        assert(private_key_ptr && !*private_key_ptr);
        if (avs_is_ok(err)) {
            assert(private_key);
            *private_key_ptr =
                    AVS_CONTAINER_OF(private_key, avs_crypto_private_key_info_t,
                                     desc);
            assert((void *) private_key == (void *) *private_key_ptr);
        } else {
            avs_free(private_key);
        }
    }
    return err;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_PERSISTENCE)
