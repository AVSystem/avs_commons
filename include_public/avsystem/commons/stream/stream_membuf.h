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

#ifndef AVS_COMMONS_STREAM_MEMBUF_H
#define AVS_COMMONS_STREAM_MEMBUF_H

#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVS_STREAM_V_TABLE_EXTENSION_MEMBUF 0x4d454d42UL /* MEMB */

typedef avs_error_t (*avs_stream_membuf_ensure_free_bytes_t)(
        avs_stream_t *stream, size_t additional_size);

typedef avs_error_t (*avs_stream_membuf_fit_t)(avs_stream_t *stream);

typedef avs_error_t (*avs_stream_membuf_take_ownership_t)(avs_stream_t *stream,
                                                          void **out_ptr,
                                                          size_t *out_size);

typedef struct {
    avs_stream_membuf_ensure_free_bytes_t ensure_free_bytes;
    avs_stream_membuf_fit_t fit;
    avs_stream_membuf_take_ownership_t take_ownership;
} avs_stream_v_table_extension_membuf_t;

/**
 * Resizes stream internal buffer so that writing the next @p size bytes can be
 * performed without reallocations.
 *
 * @param stream          membuf stream pointer
 *
 * @param additional_size number of bytes to reserve
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_stream_membuf_ensure_free_bytes(avs_stream_t *stream,
                                                size_t additional_size);

/**
 * Resizes stream internal buffers to optimize memory usage.
 *
 * @param stream    membuf stream pointer
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_stream_membuf_fit(avs_stream_t *stream);

/**
 * Returns the stream's internal buffer (containing all the unread data), and
 * resets the original stream's state so that it contains no data.
 *
 * @ref avs_stream_membuf_fit is implicitly performed before this operation.
 *
 * @param out_ptr  Pointer to a variable which will be set to the address of the
 *                 stream's buffer.
 * @param out_size If not NULL, shall point to a variable that will be set to
 *                 the number of valid bytes in the buffer.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed. On error, @p out_ptr is guaranteed to not be
 *          changed.
 */
avs_error_t avs_stream_membuf_take_ownership(avs_stream_t *stream,
                                             void **out_ptr,
                                             size_t *out_size);

typedef struct avs_stream_membuf_struct avs_stream_membuf_t;

/**
 * Creates a new in-memory auto-resizable bidirectional stream.
 *
 * @return NULL in case of an error, pointer to the newly allocated
 *         stream otherwise
 */
avs_stream_t *avs_stream_membuf_create(void);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_MEMBUF_H */
