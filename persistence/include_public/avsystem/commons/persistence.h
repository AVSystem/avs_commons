/*
 * Copyright 2018 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/list.h>
#include <avsystem/commons/rbtree.h>
#include <avsystem/commons/stream.h>

#ifdef __cplusplus
extern "C" {
#endif

struct avs_persistence_context_struct;
typedef struct avs_persistence_context_struct avs_persistence_context_t;

typedef int
avs_persistence_handler_collection_element_t(avs_persistence_context_t *ctx,
                                             void *element,
                                             void *user_data);

typedef int avs_persistence_cleanup_collection_element_t(void *element);

/**
 * Creates context where each underlying operation writes passed value to the
 * stream.
 * @param stream    stream to operate on
 * @return          NULL on error during context construction, valid pointer
 *                  otherwise
 */
avs_persistence_context_t *
avs_persistence_store_context_new(avs_stream_abstract_t *stream);

/**
 * Creates context where each underlying operation reads value from the stream
 * and writes it under an address passed by the user.
 * @param stream    stream to operate on
 * @return          NULL on error during context construction, valid pointer
 *                  otherwise
 */
avs_persistence_context_t *
avs_persistence_restore_context_new(avs_stream_abstract_t *stream);

/**
 * Creates context where each underlying operation skips value.
 * @param stream    stream to operate on
 * @return          NULL on error during context construction, valid pointer
 *                  otherwise
 */
avs_persistence_context_t *
avs_persistence_ignore_context_new(avs_stream_abstract_t *stream);

/**
 * Deletes @p ctx and frees memory associated with it.
 * Note: stream used to initialize context is not closed.
 * @param ctx       pointer to the context to be deleted
 */
void avs_persistence_context_delete(avs_persistence_context_t *ctx);

/**
 * Performs operation (depending on the @p ctx) on bool.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_bool(avs_persistence_context_t *ctx, bool *value);

/**
 * Performs operation (depending on the @p ctx) on byte sequence.
 *
 * On restore context behavior:
 *  - @p buffer is a pointer to the user-allocated buffer.
 *  - @p buffer_size is a size of the user-allocated buffer.
 *  - If the data cannot be fit into the @p buffer, then an error is returned.
 *
 * On persist context behavior:
 *  - @p buffer is a pointer to the user-allocated buffer.
 *  - @p buffer_size is the amount of bytes to store.
 *  - If the data cannot be stored, then an error is returned.
 *
 * On ignore context behavior:
 *  - @p buffer is optional, might be NULL.
 *  - @p buffer_size is the amount of bytes to be ignored.
 *
 * Example usage:
 * @code
 *  char buffer[1024];
 *  // Some logic that fills the buffer
 *  ...
 *  uint32_t buffer_size = ...;
 *
 *  // Store buffer size so that it can be restored later.
 *  int retval = avs_persistence_u32(persist_ctx, &buffer_size);
 *  if (retval) {
 *      return retval;
 *  }
 *
 *  // Store the buffer itself.
 *  return avs_persistence_bytes(persist_ctx, buffer, buffer_size);
 * @endcode
 *
 * @param ctx           Context that determines actual operation.
 * @param buffer        Pointer to the user-allocated buffer or NULL.
 * @param buffer_size   Size of the user-allocated buffer or 0.
 * @return 0 in case of success, negative value in case of failure.
 */
int avs_persistence_bytes(avs_persistence_context_t *ctx,
                          void *buffer,
                          size_t buffer_size);

/**
 * Performs operation (depending on the @p ctx) on uint8_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_u8(avs_persistence_context_t *ctx,
                       uint8_t *value);

/**
 * Performs operation (depending on the @p ctx) on uint16_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_u16(avs_persistence_context_t *ctx,
                        uint16_t *value);

/**
 * Performs operation (depending on the @p ctx) on uint32_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_u32(avs_persistence_context_t *ctx,
                        uint32_t *value);

/**
 * Performs operation (depending on the @p ctx) on uint64_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_u64(avs_persistence_context_t *ctx,
                        uint64_t *value);

/**
 * Performs operation (depending on the @p ctx) on int8_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_i8(avs_persistence_context_t *ctx,
                       int8_t *value);

/**
 * Performs operation (depending on the @p ctx) on int16_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_i16(avs_persistence_context_t *ctx,
                        int16_t *value);

/**
 * Performs operation (depending on the @p ctx) on int32_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_i32(avs_persistence_context_t *ctx,
                        int32_t *value);

/**
 * Performs operation (depending on the @p ctx) on int64_t.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_i64(avs_persistence_context_t *ctx,
                        int64_t *value);

/**
 * Performs operation (depending on the @p ctx) on float.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_float(avs_persistence_context_t *ctx,
                          float *value);

/**
 * Performs operation (depending on the @p ctx) on double.
 * @param ctx   context that determines the actual operation
 * @param value pointer of value passed to the underlying operation
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_double(avs_persistence_context_t *ctx,
                           double *value);

/**
 * Performs an operation (depending on the @p ctx) on a pair of @p data_ptr and
 * @p size_ptr; in the restore case, a new buffer is allocated using
 * <c>malloc()</c>.
 *
 * @param ctx      context that determines the actual operation
 * @param data_ptr pointer to a pointer containing the data
 * @param size_ptr pointer to a size variable for the buffer
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_sized_buffer(avs_persistence_context_t *ctx,
                                 void **data_ptr,
                                 size_t *size_ptr);

/**
 * Performs an operation (depending on the @p ctx) on a heap-allocated
 * null-terminated string variable.
 *
 * @param ctx        context that determines the actual operation
 * @param string_ptr pointer to a heap-allocated null-terminated string variable
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_string(avs_persistence_context_t *ctx,
                           char **string_ptr);

/**
 * Performs a operation (depending on the @p ctx) on a @p list_ptr, using
 * @p handler for each element.
 *
 * @param ctx              context that determines the actual operation
 * @param list_ptr         pointer to the list containing the data
 * @param element_size     size of single element in the list
 * @param handler          function called for each element of the list
 * @param handler_user_ptr opaque pointer passed to each call to @p handler
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_list(
        avs_persistence_context_t *ctx,
        AVS_LIST(void) *list_ptr,
        size_t element_size,
        avs_persistence_handler_collection_element_t *handler,
        void *handler_user_ptr);

/**
 * Performs a operation (depending on the @p ctx) on a @p tree, using
 * @p handler for each element.
 *
 * @param ctx              context that determines the actual operation
 * @param tree             tree containing the data
 * @param element_size     size of single element in the tree
 * @param handler          function called for each element of the tree
 * @param handler_user_ptr opaque pointer passed to each call to @p handler
 * @param cleanup          function called on an element if it could not be
 *                         restored in entirety
 * @return 0 in case of success, negative value in case of failure
 */
int avs_persistence_tree(
        avs_persistence_context_t *ctx,
        AVS_RBTREE(void) tree,
        size_t element_size,
        avs_persistence_handler_collection_element_t *handler,
        void *handler_user_ptr,
        avs_persistence_cleanup_collection_element_t *cleanup);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_PERSISTENCE_H */
