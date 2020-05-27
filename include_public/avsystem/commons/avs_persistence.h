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

#ifndef AVS_COMMONS_PERSISTENCE_H
#define AVS_COMMONS_PERSISTENCE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <avsystem/commons/avs_list.h>
#include <avsystem/commons/avs_rbtree.h>
#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

struct avs_persistence_context_vtable_struct;

typedef struct avs_persistence_context_struct {
    const struct avs_persistence_context_vtable_struct *vtable;
    avs_stream_t *stream;
} avs_persistence_context_t;

typedef enum {
    AVS_PERSISTENCE_UNKNOWN = -1,
    AVS_PERSISTENCE_STORE = 0,
    AVS_PERSISTENCE_RESTORE
} avs_persistence_direction_t;

typedef avs_error_t avs_persistence_handler_collection_element_t(
        avs_persistence_context_t *ctx, void *element, void *user_data);

typedef avs_error_t avs_persistence_handler_custom_allocated_list_element_t(
        avs_persistence_context_t *ctx,
        AVS_LIST(void) *element,
        void *user_data);

typedef avs_error_t avs_persistence_handler_custom_allocated_tree_element_t(
        avs_persistence_context_t *ctx,
        AVS_RBTREE_ELEM(void) *element,
        void *user_data);

typedef void avs_persistence_cleanup_collection_element_t(void *element);

/**
 * Creates an initialized persistence context so that each underlying operation
 * writes passed value to the stream.
 *
 * @param out_context Pointer to a persistence context variable to initialize.
 * @param stream      Stream to operate on.
 */
avs_persistence_context_t
avs_persistence_store_context_create(avs_stream_t *stream);

/**
 * Creates an initialized persistence context so that each underlying operation
 * reads value from the stream and writes it under an address passed by the
 * user.
 *
 * @param out_context Pointer to a persistence context variable to initialize.
 * @param stream      Stream to operate on.
 */
avs_persistence_context_t
avs_persistence_restore_context_create(avs_stream_t *stream);

/**
 * Returns the direction of @p ctx operation.
 * @param ctx persistence context to inspect
 * @return AVS_PERSISTENCE_STORE if the context writes data to an external
 *         stream, AVS_PERSISTENCE_RESTORE if it it reads data from an external
 *         stream, or AVS_PERSISTENCE_UNKNOWN in case of error.
 */
avs_persistence_direction_t
avs_persistence_direction(avs_persistence_context_t *ctx);

/**
 * Performs operation (depending on the @p ctx) on bool.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_bool(avs_persistence_context_t *ctx, bool *value);

/**
 * Performs operation (depending on the @p ctx) on byte sequence.
 *
 * On restore context behavior:
 *  - @p buffer is a pointer to the user-allocated buffer.
 *  - @p buffer_size is a size of the user-allocated buffer.
 *  - If the data cannot be read, then an error is returned.
 *
 * On persist context behavior:
 *  - @p buffer is a pointer to the user-allocated buffer.
 *  - @p buffer_size is the amount of bytes to store.
 *  - If the data cannot be stored, then an error is returned.
 *
 * Example usage:
 * @code
 *  char buffer[1024];
 *  // Some logic that fills the buffer
 *  ...
 *  uint32_t buffer_size = ...;
 *
 *  // Store buffer size so that it can be restored later.
 *  avs_error_t err = avs_persistence_u32(persist_ctx, &buffer_size);
 *  if (avs_is_err(err)) {
 *      return err;
 *  }
 *
 *  // Store the buffer itself.
 *  return avs_persistence_bytes(persist_ctx, buffer, buffer_size);
 * @endcode
 *
 * @param ctx           Context that determines actual operation.
 * @param buffer        Pointer to the user-allocated buffer or NULL.
 * @param buffer_size   Size of the user-allocated buffer or 0.
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_bytes(avs_persistence_context_t *ctx,
                                  void *buffer,
                                  size_t buffer_size);

/**
 * Performs operation (depending on the @p ctx) on uint8_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_u8(avs_persistence_context_t *ctx, uint8_t *value);

/**
 * Performs operation (depending on the @p ctx) on uint16_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_u16(avs_persistence_context_t *ctx,
                                uint16_t *value);

/**
 * Performs operation (depending on the @p ctx) on uint32_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_u32(avs_persistence_context_t *ctx,
                                uint32_t *value);

/**
 * Performs operation (depending on the @p ctx) on uint64_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_u64(avs_persistence_context_t *ctx,
                                uint64_t *value);

/**
 * Performs operation (depending on the @p ctx) on int8_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_i8(avs_persistence_context_t *ctx, int8_t *value);

/**
 * Performs operation (depending on the @p ctx) on int16_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_i16(avs_persistence_context_t *ctx, int16_t *value);

/**
 * Performs operation (depending on the @p ctx) on int32_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_i32(avs_persistence_context_t *ctx, int32_t *value);

/**
 * Performs operation (depending on the @p ctx) on int64_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_i64(avs_persistence_context_t *ctx, int64_t *value);

/**
 * Performs operation (depending on the @p ctx) on float.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_float(avs_persistence_context_t *ctx, float *value);

/**
 * Performs operation (depending on the @p ctx) on double.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_double(avs_persistence_context_t *ctx,
                                   double *value);

/**
 * Performs an operation (depending on the @p ctx) on a pair of @p data_ptr and
 * @p size_ptr; in the restore case, a new buffer is allocated using
 * <c>avs_malloc()</c>.
 *
 * @param ctx      context that determines the actual operation
 * @param data_ptr pointer to a pointer containing the data
 * @param size_ptr pointer to a size variable for the buffer
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_sized_buffer(avs_persistence_context_t *ctx,
                                         void **data_ptr,
                                         size_t *size_ptr);

/**
 * Performs an operation (depending on the @p ctx) on a heap-allocated
 * null-terminated string variable.
 *
 * @param ctx        context that determines the actual operation
 * @param string_ptr pointer to a heap-allocated null-terminated string variable
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_string(avs_persistence_context_t *ctx,
                                   char **string_ptr);

/**
 * Performs a operation (depending on the @p ctx) on a @p list_ptr, using
 * @p handler for each element. In this variant, @p handler is responsible for
 * allocating the elements during a restore operation.
 *
 * If direction of @p ctx is @ref AVS_PERSISTENCE_RESTORE , @p list_ptr must be
 * a pointer to an \b empty list.
 *
 * If @p cleanup is NULL, the resulting list is NOT cleared in case of restore
 * error. Note that this may also mean that the last element is in a partially
 * restored, inconsistent state. If you want the list automatically cleared
 * without a cleanup routine, please use an empty function.
 *
 * NOTE: The intended usage for using NULL as @p cleanup is that the user will
 * clean up the partially restored data, possibly included nested containers, in
 * one routine, which may be simpler to implement than cleanup functions for
 * each stage. Note that for this to be possible, the @p handler needs to ensure
 * that in case of failure, the partially restored element MUST be in a state
 * consistent enough for cleanup, e.g. not containing any uninitialized memory
 * buffers.
 *
 * @param ctx              context that determines the actual operation
 * @param list_ptr         pointer to the list containing the data
 * @param element_size     size of single element in the list
 * @param handler          function called for each element of the list
 * @param handler_user_ptr opaque pointer passed to each call to @p handler
 * @param cleanup          function called on all completely or partially
 *                         restored elements in case of an error
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_custom_allocated_list(
        avs_persistence_context_t *ctx,
        AVS_LIST(void) *list_ptr,
        avs_persistence_handler_custom_allocated_list_element_t *handler,
        void *handler_user_ptr,
        avs_persistence_cleanup_collection_element_t *cleanup);

/**
 * Performs a operation (depending on the @p ctx) on a @p list_ptr, using
 * @p handler for each element.
 *
 * If direction of @p ctx is @ref AVS_PERSISTENCE_RESTORE , @p list_ptr must be
 * a pointer to an \b empty list.
 *
 * In this variant, the elements are allocated automatically. Note that this
 * function requires that all list elements have the same size; variable-length
 * elements (e.g. containing flexible array members) are not supported.
 *
 * If @p cleanup is NULL, the resulting list is NOT cleared in case of restore
 * error. Note that this may also mean that the last element is in a partially
 * restored, inconsistent state. If you want the list automatically cleared
 * without a cleanup routine, please use an empty function.
 *
 * @param ctx              context that determines the actual operation
 * @param list_ptr         pointer to the list containing the data
 * @param element_size     size of single element in the list
 * @param handler          function called for each element of the list
 * @param handler_user_ptr opaque pointer passed to each call to @p handler
 * @param cleanup          function called on all completely or partially
 *                         restored elements in case of an error
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t
avs_persistence_list(avs_persistence_context_t *ctx,
                     AVS_LIST(void) *list_ptr,
                     size_t element_size,
                     avs_persistence_handler_collection_element_t *handler,
                     void *handler_user_ptr,
                     avs_persistence_cleanup_collection_element_t *cleanup);

/**
 * Performs a operation (depending on the @p ctx) on a @p tree, using
 * @p handler for each element. In this variant, @p handler is responsible for
 * allocating the elements during a restore operation.
 *
 * In this variant, the elements are allocated automatically. Note that this
 * function requires that all tree elements have the same size; variable-length
 * elements (e.g. containing flexible array members) are not supported.
 *
 * Note that unlike @ref avs_persistence_list, @p cleanup MUST be non-NULL in
 * case of a restore operation. This is because inserting a restored element
 * onto a tree might fail (e.g. if a newly restored element compares as equal to
 * some previously restored element), so it is not always possible to leave the
 * cleanup to the user after the restore attempt.
 *
 * @param ctx              context that determines the actual operation
 * @param tree             tree containing the data
 * @param element_size     size of single element in the tree
 * @param handler          function called for each element of the tree
 * @param handler_user_ptr opaque pointer passed to each call to @p handler
 * @param cleanup          function called on all completely or partially
 *                         restored elements in case of an error
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_custom_allocated_tree(
        avs_persistence_context_t *ctx,
        AVS_RBTREE(void) tree,
        avs_persistence_handler_custom_allocated_tree_element_t *handler,
        void *handler_user_ptr,
        avs_persistence_cleanup_collection_element_t *cleanup);

/**
 * Performs a operation (depending on the @p ctx) on a @p tree, using
 * @p handler for each element.
 *
 * Note that this function requires that all tree elements have the same size;
 * variable-length elements (e.g. containing flexible array members) are not
 * supported.
 *
 * Note that unlike @ref avs_persistence_list, @p cleanup MUST be non-NULL in
 * case of a restore operation. This is because inserting a restored element
 * onto a tree might fail (e.g. if a newly restored element compares as equal to
 * some previously restored element), so it is not always possible to leave the
 * cleanup to the user after the restore attempt.
 *
 * @param ctx              context that determines the actual operation
 * @param tree             tree containing the data
 * @param element_size     size of single element in the tree
 * @param handler          function called for each element of the tree
 * @param handler_user_ptr opaque pointer passed to each call to @p handler
 * @param cleanup          function called on all completely or partially
 *                         restored elements in case of an error
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t
avs_persistence_tree(avs_persistence_context_t *ctx,
                     AVS_RBTREE(void) tree,
                     size_t element_size,
                     avs_persistence_handler_collection_element_t *handler,
                     void *handler_user_ptr,
                     avs_persistence_cleanup_collection_element_t *cleanup);

/**
 * Persists or restores (depending on the @p ctx) a magic marker.
 *
 * The persist operation is effectively equivalent to calling
 * @ref avs_persistence_bytes with the same arguments.
 *
 * On restore operation, the function attempts to read @p magic_size bytes and
 * compares it with @p magic. The operation is successful if, and only if, the
 * data read is byte-for-byte identical.
 *
 * @param ctx        Context that determines the actual operation.
 * @param magic      Pointer to the magic marker constant.
 * @param magic_size Size of the magic marker, in bytes.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_magic(avs_persistence_context_t *ctx,
                                  const void *magic,
                                  size_t magic_size);

/**
 * Persists or restores (depending on the @p ctx) a null-terminated magic
 * marker.
 *
 * This is a shorthand for @ref avs_persistence_magic when the magic marker is
 * a null-terminated string.
 *
 * @param ctx   Context that determines the actual operation.
 * @param magic Pointer to the null-terminated magic marker string constant.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
static inline avs_error_t
avs_persistence_magic_string(avs_persistence_context_t *ctx,
                             const char *magic) {
    return avs_persistence_magic(ctx, magic, strlen(magic));
}

/**
 * Persists or restores a format version number.
 *
 * This is mostly equivalent to:
 *
 * <code>
 * avs_persistence_u8(ctx, version_number);
 * </code>
 *
 * except on restore operation, the restored value is compared to the values
 * in the <c>supported_versions</c> array, and if it doesn't match any, an error
 * is returned.
 *
 * @param ctx                      Context that determines the actual operation.
 * @param version_number           Pointer to the value to be stored or
 *                                 restored.
 * @param supported_versions       Pointer to an array that contains all
 *                                 supported version numbers.
 * @param supported_versions_count Number of elements in the
 *                                 <c>supported_versions</c> array.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_persistence_version(avs_persistence_context_t *ctx,
                                    uint8_t *version_number,
                                    const uint8_t *supported_versions,
                                    size_t supported_versions_count);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_PERSISTENCE_H */
