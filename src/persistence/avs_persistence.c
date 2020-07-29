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

#ifdef AVS_COMMONS_WITH_AVS_PERSISTENCE

#    include <assert.h>
#    include <inttypes.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_persistence.h>
#    include <avsystem/commons/avs_utils.h>

#    define MODULE_NAME avs_persistence
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

typedef avs_error_t persistence_handler_u16_t(avs_persistence_context_t *ctx,
                                              uint16_t *value);
typedef avs_error_t persistence_handler_u32_t(avs_persistence_context_t *ctx,
                                              uint32_t *value);
typedef avs_error_t persistence_handler_u64_t(avs_persistence_context_t *ctx,
                                              uint64_t *value);
typedef avs_error_t persistence_handler_bool_t(avs_persistence_context_t *ctx,
                                               bool *value);
typedef avs_error_t persistence_handler_bytes_t(avs_persistence_context_t *ctx,
                                                void *buffer,
                                                size_t buffer_size);
typedef avs_error_t persistence_handler_float_t(avs_persistence_context_t *ctx,
                                                float *value);
typedef avs_error_t persistence_handler_double_t(avs_persistence_context_t *ctx,
                                                 double *value);
typedef avs_error_t persistence_handler_sized_buffer_t(
        avs_persistence_context_t *ctx, void **data_ptr, size_t *size_ptr);
typedef avs_error_t persistence_handler_string_t(avs_persistence_context_t *ctx,
                                                 char **string_ptr);
typedef avs_error_t persistence_handler_list_t(
        avs_persistence_context_t *ctx,
        AVS_LIST(void) *list_ptr,
        avs_persistence_handler_custom_allocated_list_element_t *handler,
        void *handler_user_ptr,
        avs_persistence_cleanup_collection_element_t *cleanup);
typedef avs_error_t persistence_handler_tree_t(
        avs_persistence_context_t *ctx,
        AVS_RBTREE(void) tree,
        avs_persistence_handler_custom_allocated_tree_element_t *handler,
        void *handler_user_ptr,
        avs_persistence_cleanup_collection_element_t *cleanup);

struct avs_persistence_context_vtable_struct {
    avs_persistence_direction_t direction;
    persistence_handler_u16_t *handle_u16;
    persistence_handler_u32_t *handle_u32;
    persistence_handler_u64_t *handle_u64;
    persistence_handler_bool_t *handle_bool;
    persistence_handler_bytes_t *handle_bytes;
    persistence_handler_float_t *handle_float;
    persistence_handler_double_t *handle_double;
    persistence_handler_sized_buffer_t *handle_sized_buffer;
    persistence_handler_string_t *handle_string;
    persistence_handler_list_t *handle_list;
    persistence_handler_tree_t *handle_tree;
};

//// PERSIST ///////////////////////////////////////////////////////////////////

static avs_error_t persist_bool(avs_persistence_context_t *ctx, bool *value) {
    AVS_STATIC_ASSERT(sizeof(*value) == 1, bool_is_1byte);
    return avs_stream_write(ctx->stream, value, 1);
}

static avs_error_t persist_bytes(avs_persistence_context_t *ctx,
                                 void *buffer,
                                 size_t buffer_size) {
    return avs_stream_write(ctx->stream, buffer, buffer_size);
}

static avs_error_t persist_u16(avs_persistence_context_t *ctx,
                               uint16_t *value) {
    const uint16_t tmp = avs_convert_be16(*value);
    return avs_stream_write(ctx->stream, &tmp, sizeof(tmp));
}

static avs_error_t persist_u32(avs_persistence_context_t *ctx,
                               uint32_t *value) {
    const uint32_t tmp = avs_convert_be32(*value);
    return avs_stream_write(ctx->stream, &tmp, sizeof(tmp));
}

static avs_error_t persist_u64(avs_persistence_context_t *ctx,
                               uint64_t *value) {
    const uint64_t tmp = avs_convert_be64(*value);
    return avs_stream_write(ctx->stream, &tmp, sizeof(tmp));
}

static avs_error_t persist_float(avs_persistence_context_t *ctx, float *value) {
    const uint32_t value_be = avs_htonf(*value);
    AVS_STATIC_ASSERT(sizeof(*value) == sizeof(value_be), float_is_32);
    return avs_stream_write(ctx->stream, &value_be, sizeof(value_be));
}

static avs_error_t persist_double(avs_persistence_context_t *ctx,
                                  double *value) {
    const uint64_t value_be = avs_htond(*value);
    AVS_STATIC_ASSERT(sizeof(*value) == sizeof(value_be), double_is_64);
    return avs_stream_write(ctx->stream, &value_be, sizeof(value_be));
}

static avs_error_t persist_sized_buffer(avs_persistence_context_t *ctx,
                                        void **data_ptr,
                                        size_t *size_ptr) {
    uint32_t size32 = (uint32_t) *size_ptr;
    if (size32 != *size_ptr) {
        LOG(ERROR,
            _("Element too big to persist (") "%lu" _(
                    " is larger than ") "%" PRIu32 _(")"),
            (unsigned long) *size_ptr, UINT32_MAX);
        return avs_errno(AVS_EOVERFLOW);
    }
    avs_error_t err = persist_u32(ctx, &size32);
    if (avs_is_ok(err) && size32 > 0) {
        err = persist_bytes(ctx, *data_ptr, *size_ptr);
    }
    return err;
}

static avs_error_t persist_string(avs_persistence_context_t *ctx,
                                  char **string_ptr) {
    size_t size = (string_ptr && *string_ptr) ? (strlen(*string_ptr) + 1) : 0;
    return persist_sized_buffer(ctx, (void **) string_ptr, &size);
}

static avs_error_t
persist_list(avs_persistence_context_t *ctx,
             AVS_LIST(void) *list_ptr,
             avs_persistence_handler_custom_allocated_list_element_t *handler,
             void *handler_user_ptr,
             avs_persistence_cleanup_collection_element_t *cleanup) {
    (void) cleanup;
    const size_t count = AVS_LIST_SIZE(*list_ptr);
    uint32_t count32 = (uint32_t) count;
    if (count != count32) {
        return avs_errno(AVS_EOVERFLOW);
    }
    avs_error_t err = persist_u32(ctx, &count32);
    if (avs_is_ok(err)) {
        AVS_LIST(void) *element_ptr;
        AVS_LIST_FOREACH_PTR(element_ptr, list_ptr) {
            if (avs_is_err(
                        (err = handler(ctx, element_ptr, handler_user_ptr)))) {
                break;
            }
        }
    }
    return err;
}

static avs_error_t
persist_tree(avs_persistence_context_t *ctx,
             AVS_RBTREE(void) tree,
             avs_persistence_handler_custom_allocated_tree_element_t *handler,
             void *handler_user_ptr,
             avs_persistence_cleanup_collection_element_t *cleanup) {
    (void) cleanup;
    const size_t count = AVS_RBTREE_SIZE(tree);
    uint32_t count32 = (uint32_t) count;
    if (count != count32) {
        return avs_errno(AVS_EOVERFLOW);
    }
    avs_error_t err = persist_u32(ctx, &count32);
    if (avs_is_ok(err)) {
        AVS_RBTREE_ELEM(void) element;
        AVS_RBTREE_FOREACH(element, tree) {
            if (avs_is_err((err = handler(ctx, &element, handler_user_ptr)))) {
                break;
            }
        }
    }
    return err;
}

static const struct avs_persistence_context_vtable_struct STORE_VTABLE = {
    AVS_PERSISTENCE_STORE, persist_u16,    persist_u32,   persist_u64,
    persist_bool,          persist_bytes,  persist_float, persist_double,
    persist_sized_buffer,  persist_string, persist_list,  persist_tree
};

//// RESTORE ///////////////////////////////////////////////////////////////////

static avs_error_t restore_bool(avs_persistence_context_t *ctx, bool *out) {
    AVS_STATIC_ASSERT(sizeof(*out) == 1, bool_is_1byte);
    return avs_stream_read_reliably(ctx->stream, out, 1);
}

static avs_error_t restore_bytes(avs_persistence_context_t *ctx,
                                 void *buffer,
                                 size_t buffer_size) {
    return avs_stream_read_reliably(ctx->stream, buffer, buffer_size);
}

static avs_error_t restore_u16(avs_persistence_context_t *ctx, uint16_t *out) {
    uint16_t tmp;
    avs_error_t err = avs_stream_read_reliably(ctx->stream, &tmp, sizeof(tmp));
    if (avs_is_ok(err) && out) {
        *out = avs_convert_be16(tmp);
    }
    return err;
}

static avs_error_t restore_u32(avs_persistence_context_t *ctx, uint32_t *out) {
    uint32_t tmp;
    avs_error_t err = avs_stream_read_reliably(ctx->stream, &tmp, sizeof(tmp));
    if (avs_is_ok(err)) {
        *out = avs_convert_be32(tmp);
    }
    return err;
}

static avs_error_t restore_u64(avs_persistence_context_t *ctx, uint64_t *out) {
    uint64_t tmp;
    avs_error_t err = avs_stream_read_reliably(ctx->stream, &tmp, sizeof(tmp));
    if (avs_is_ok(err)) {
        *out = avs_convert_be64(tmp);
    }
    return err;
}

static avs_error_t restore_float(avs_persistence_context_t *ctx, float *out) {
    uint32_t tmp;
    AVS_STATIC_ASSERT(sizeof(*out) == sizeof(tmp), float_is_32);
    avs_error_t err = avs_stream_read_reliably(ctx->stream, &tmp, sizeof(tmp));
    if (avs_is_ok(err)) {
        *out = avs_ntohf(tmp);
    }
    return err;
}

static avs_error_t restore_double(avs_persistence_context_t *ctx, double *out) {
    uint64_t tmp;
    AVS_STATIC_ASSERT(sizeof(*out) == sizeof(tmp), double_is_64);
    avs_error_t err = avs_stream_read_reliably(ctx->stream, &tmp, sizeof(tmp));
    if (avs_is_ok(err)) {
        *out = avs_ntohd(tmp);
    }
    return err;
}

static avs_error_t restore_sized_buffer(avs_persistence_context_t *ctx,
                                        void **data_ptr,
                                        size_t *size_ptr) {
    assert(!*data_ptr);
    assert(!*size_ptr);
    uint32_t size32;
    avs_error_t err = restore_u32(ctx, &size32);
    if (avs_is_err(err)) {
        return err;
    }
    if (size32 == 0) {
        return AVS_OK;
    }
    if (!(*data_ptr = avs_malloc(size32))) {
        LOG(ERROR, _("Cannot allocate ") "%" PRIu32 _(" bytes"), size32);
        return avs_errno(AVS_ENOMEM);
    }
    if (avs_is_err((err = restore_bytes(ctx, *data_ptr, size32)))) {
        avs_free(*data_ptr);
        *data_ptr = NULL;
    } else {
        *size_ptr = size32;
    }
    return err;
}

static avs_error_t restore_string(avs_persistence_context_t *ctx,
                                  char **string_ptr) {
    size_t size = 0;
    avs_error_t err = restore_sized_buffer(ctx, (void **) string_ptr, &size);
    if (avs_is_err(err)) {
        return err;
    }
    if (size > 0 && (*string_ptr)[size - 1] != '\0') {
        LOG(ERROR, _("Invalid string"));
        avs_free(*string_ptr);
        *string_ptr = NULL;
        return avs_errno(AVS_EBADMSG);
    }
    return AVS_OK;
}

static avs_error_t
restore_list(avs_persistence_context_t *ctx,
             AVS_LIST(void) *list_ptr,
             avs_persistence_handler_custom_allocated_list_element_t *handler,
             void *handler_user_ptr,
             avs_persistence_cleanup_collection_element_t *cleanup) {
    assert(list_ptr && !*list_ptr);
    uint32_t count;
    avs_error_t err = restore_u32(ctx, &count);
    AVS_LIST(void) *insert_ptr = list_ptr;
    while (avs_is_ok(err) && count--) {
        AVS_LIST(void) element = NULL;
        err = handler(ctx, &element, handler_user_ptr);
        if (element) {
            AVS_LIST_INSERT(insert_ptr, element);
            insert_ptr = AVS_LIST_NEXT_PTR(insert_ptr);
        }
    }
    if (avs_is_err(err) && cleanup) {
        AVS_LIST_CLEAR(list_ptr) {
            cleanup(*list_ptr);
        }
    }
    return err;
}

static avs_error_t
restore_tree(avs_persistence_context_t *ctx,
             AVS_RBTREE(void) tree,
             avs_persistence_handler_custom_allocated_tree_element_t *handler,
             void *handler_user_ptr,
             avs_persistence_cleanup_collection_element_t *cleanup) {
    assert(AVS_RBTREE_SIZE(tree) == 0);
    assert(cleanup);
    uint32_t count;
    avs_error_t err = restore_u32(ctx, &count);
    while (avs_is_ok(err) && count--) {
        AVS_RBTREE_ELEM(void) element = NULL;
        if (avs_is_ok((err = handler(ctx, &element, handler_user_ptr)))
                && element && AVS_RBTREE_INSERT(tree, element) != element) {
            err = avs_errno(AVS_EBADMSG);
        }
        if (avs_is_err(err) && element) {
            cleanup(element);
            AVS_RBTREE_ELEM_DELETE_DETACHED(&element);
        }
    }
    if (avs_is_err(err)) {
        AVS_RBTREE_CLEAR(tree) {
            cleanup(*tree);
        }
    }
    return err;
}

static const struct avs_persistence_context_vtable_struct RESTORE_VTABLE = {
    AVS_PERSISTENCE_RESTORE,
    restore_u16,
    restore_u32,
    restore_u64,
    restore_bool,
    restore_bytes,
    restore_float,
    restore_double,
    restore_sized_buffer,
    restore_string,
    restore_list,
    restore_tree
};

avs_persistence_context_t
avs_persistence_store_context_create(avs_stream_t *stream) {
    return (avs_persistence_context_t) {
        .vtable = &STORE_VTABLE,
        .stream = stream
    };
}

avs_persistence_context_t
avs_persistence_restore_context_create(avs_stream_t *stream) {
    return (avs_persistence_context_t) {
        .vtable = &RESTORE_VTABLE,
        .stream = stream
    };
}

avs_persistence_direction_t
avs_persistence_direction(avs_persistence_context_t *ctx) {
    if (!ctx) {
        return AVS_PERSISTENCE_UNKNOWN;
    }
    return ctx->vtable->direction;
}

avs_error_t avs_persistence_u8(avs_persistence_context_t *ctx, uint8_t *value) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_bytes(ctx, value, sizeof(*value));
}

avs_error_t avs_persistence_u16(avs_persistence_context_t *ctx,
                                uint16_t *value) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_u16(ctx, value);
}

avs_error_t avs_persistence_u32(avs_persistence_context_t *ctx,
                                uint32_t *value) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_u32(ctx, value);
}

avs_error_t avs_persistence_u64(avs_persistence_context_t *ctx,
                                uint64_t *value) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_u64(ctx, value);
}

avs_error_t avs_persistence_i8(avs_persistence_context_t *ctx, int8_t *value) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_bytes(ctx, value, sizeof(*value));
}

avs_error_t avs_persistence_i16(avs_persistence_context_t *ctx,
                                int16_t *value) {
    return avs_persistence_u16(ctx, (uint16_t *) value);
}

avs_error_t avs_persistence_i32(avs_persistence_context_t *ctx,
                                int32_t *value) {
    return avs_persistence_u32(ctx, (uint32_t *) value);
}

avs_error_t avs_persistence_i64(avs_persistence_context_t *ctx,
                                int64_t *value) {
    return avs_persistence_u64(ctx, (uint64_t *) value);
}

avs_error_t avs_persistence_bool(avs_persistence_context_t *ctx, bool *value) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_bool(ctx, value);
}

avs_error_t avs_persistence_bytes(avs_persistence_context_t *ctx,
                                  void *buffer,
                                  size_t buffer_size) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_bytes(ctx, buffer, buffer_size);
}

avs_error_t avs_persistence_float(avs_persistence_context_t *ctx,
                                  float *value) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_float(ctx, value);
}

avs_error_t avs_persistence_double(avs_persistence_context_t *ctx,
                                   double *value) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_double(ctx, value);
}

avs_error_t avs_persistence_sized_buffer(avs_persistence_context_t *ctx,
                                         void **data_ptr,
                                         size_t *size_ptr) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_sized_buffer(ctx, data_ptr, size_ptr);
}

avs_error_t avs_persistence_string(avs_persistence_context_t *ctx,
                                   char **string_ptr) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_string(ctx, string_ptr);
}

avs_error_t avs_persistence_custom_allocated_list(
        avs_persistence_context_t *ctx,
        AVS_LIST(void) *list_ptr,
        avs_persistence_handler_custom_allocated_list_element_t *handler,
        void *handler_user_ptr,
        avs_persistence_cleanup_collection_element_t *cleanup) {
    if (!ctx || !list_ptr) {
        return avs_errno(AVS_EBADF);
    }
    if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_RESTORE
            && *list_ptr) {
        LOG(ERROR, "Cannot restore to a non-empty list");
        return avs_errno(AVS_EINVAL);
    }
    return ctx->vtable->handle_list(ctx, list_ptr, handler, handler_user_ptr,
                                    cleanup);
}

avs_error_t avs_persistence_custom_allocated_tree(
        avs_persistence_context_t *ctx,
        AVS_RBTREE(void) tree,
        avs_persistence_handler_custom_allocated_tree_element_t *handler,
        void *handler_user_ptr,
        avs_persistence_cleanup_collection_element_t *cleanup) {
    if (!ctx) {
        return avs_errno(AVS_EBADF);
    }
    return ctx->vtable->handle_tree(ctx, tree, handler, handler_user_ptr,
                                    cleanup);
}

typedef struct {
    size_t element_size;
    avs_persistence_handler_collection_element_t *handler;
    void *handler_user_ptr;
} persistence_collection_state_t;

#    define DEFINE_PERSISTENCE_COLLECTION_HANDLER(Name, ElementType)         \
        static avs_error_t Name(avs_persistence_context_t *ctx,              \
                                ElementType(void) * element, void *state_) { \
            persistence_collection_state_t *state =                          \
                    (persistence_collection_state_t *) state_;               \
            if (element && !*element) {                                      \
                *element = ElementType##_NEW_BUFFER(state->element_size);    \
                if (!element) {                                              \
                    LOG(ERROR, _("Out of memory"));                          \
                    return avs_errno(AVS_ENOMEM);                            \
                }                                                            \
            }                                                                \
            return state->handler(ctx, element ? *element : NULL,            \
                                  state->handler_user_ptr);                  \
        }

DEFINE_PERSISTENCE_COLLECTION_HANDLER(persistence_list_handler, AVS_LIST)

avs_error_t
avs_persistence_list(avs_persistence_context_t *ctx,
                     AVS_LIST(void) *list_ptr,
                     size_t element_size,
                     avs_persistence_handler_collection_element_t *handler,
                     void *handler_user_ptr,
                     avs_persistence_cleanup_collection_element_t *cleanup) {
    persistence_collection_state_t state = {
        .element_size = element_size,
        .handler = handler,
        .handler_user_ptr = handler_user_ptr
    };
    return avs_persistence_custom_allocated_list(
            ctx, list_ptr, persistence_list_handler, &state, cleanup);
}

DEFINE_PERSISTENCE_COLLECTION_HANDLER(persistence_tree_handler, AVS_RBTREE_ELEM)

avs_error_t
avs_persistence_tree(avs_persistence_context_t *ctx,
                     AVS_RBTREE(void) tree,
                     size_t element_size,
                     avs_persistence_handler_collection_element_t *handler,
                     void *handler_user_ptr,
                     avs_persistence_cleanup_collection_element_t *cleanup) {
    persistence_collection_state_t state = {
        .element_size = element_size,
        .handler = handler,
        .handler_user_ptr = handler_user_ptr
    };
    return avs_persistence_custom_allocated_tree(
            ctx, tree, persistence_tree_handler, &state, cleanup);
}

avs_error_t avs_persistence_magic(avs_persistence_context_t *ctx,
                                  const void *magic,
                                  size_t magic_size) {
    if (magic_size == 0) {
        return AVS_OK;
    } else if (avs_persistence_direction(ctx) == AVS_PERSISTENCE_STORE) {
        return avs_persistence_bytes(ctx, (void *) (intptr_t) magic,
                                     magic_size);
    } else {
        void *bytes = avs_malloc(magic_size);
        if (!bytes) {
            LOG(ERROR, _("Out of memory"));
            return avs_errno(AVS_ENOMEM);
        }
        avs_error_t err = avs_persistence_bytes(ctx, bytes, magic_size);
        if (avs_is_ok(err) && memcmp(bytes, magic, magic_size) != 0) {
            LOG(ERROR, _("Magic markers do not match"));
            err = avs_errno(AVS_EBADMSG);
        }
        avs_free(bytes);
        return err;
    }
}

avs_error_t avs_persistence_version(avs_persistence_context_t *ctx,
                                    uint8_t *version_number,
                                    const uint8_t *supported_versions,
                                    size_t supported_versions_count) {
    avs_error_t err = avs_persistence_u8(ctx, version_number);
    if (avs_is_err(err) || ctx->vtable != &RESTORE_VTABLE) {
        return err;
    }

    for (size_t i = 0; i < supported_versions_count; ++i) {
        if (*version_number == supported_versions[i]) {
            return AVS_OK;
        }
    }

    LOG(ERROR, _("Unsupported version number: ") "%u",
        (unsigned) *version_number);
    return avs_errno(AVS_EBADMSG);
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/persistence/persistence.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_PERSISTENCE
