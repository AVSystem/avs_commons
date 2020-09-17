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

#ifndef AVS_COMMONS_STREAM_V_TABLE_H
#define AVS_COMMONS_STREAM_V_TABLE_H

#include <stdint.h>

#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ref avs_stream_write_some implementation callback type.
 *
 * Writes data to the stream. Implementation may support "short writes" - in
 * such case, it shall return success, but modify the value of
 * @p inout_data_length .
 *
 * @param stream            Stream to operate on.
 * @param buffer            Data to write, never NULL.
 * @param inout_data_length MUST NOT be NULL. Pointer to a variable that on
 *                          input, shall contain the number of bytes to write.
 *                          After successful return, it will contain the number
 *                          of bytes actually written.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
typedef avs_error_t (*avs_stream_write_some_t)(avs_stream_t *stream,
                                               const void *buffer,
                                               size_t *inout_data_length);

/**
 * @ref avs_stream_finish_message implementation callback type.
 *
 * There are no specific requirements on the implementation of this method.
 *
 * For example, on some kind of network stream, message finish may cause
 * packet serialization and issuing @ref send() .
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
typedef avs_error_t (*avs_stream_finish_message_t)(avs_stream_t *stream);

/**
 * @ref avs_stream_read implementation callback type.
 *
 * Reads up to @p buffer_length bytes from the stream. For more information
 * about meaning of @p out_message_finished please refer to @ref avs_stream_read
 * docstring.
 *
 * WARNING: it is NOT allowed for the implementation to read 0 bytes from the
 * underlying stream and at the same time set @p out_message_finished to 0 .
 * Instead, the implementation should block (waiting for the data) or return an
 * error immediately.
 *
 * Note: even if the final outcome of the read operation is an error, it is
 * still allowed for the implementation to write some data to the @p buffer .
 *
 * @param stream                Stream to operate on.
 * @param out_bytes_read        Pointer to a variable where amount of read bytes
 *                              will be written, or NULL.
 * @param out_message_finished  Pointer to a variable where information about
 *                              message state will be stored (0 if not finished,
 *                              1 otherwise), or NULL.
 * @param buffer                Pointer to a memory block where read bytes shall
 *                              be stored.
 * @param buffer_length         Available buffer storage.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
typedef avs_error_t (*avs_stream_read_t)(avs_stream_t *stream,
                                         size_t *out_bytes_read,
                                         bool *out_message_finished,
                                         void *buffer,
                                         size_t buffer_length);

/**
 * @ref avs_stream_peek implementation callback type.
 *
 * Peeks a single byte at specified offset (from the current stream position),
 * without consuming it.
 *
 * Note: this is an optional feature, and if implemented it is allowed to
 * set arbitrary limit on the maximum supported @p offset value.
 *
 * @param[in]  stream    Stream to operate on.
 * @param[in]  offset    Offset from the current stream position.
 * @param[out] out_value The variable that the peeked value shall be assigned
 *                       to.
 *
 * @returns @li @ref AVS_OK for success, in which case <c>*out_value</c> is
 *              set to an actual value,
 *          @li @ref AVS_EOF if @p offset has been reliably determined as
 *              pointing past end-of-stream,
 *          @li an error condition for which the operation failed; this includes
 *              the stream not having buffered enough data for peeking.
 */
typedef avs_error_t (*avs_stream_peek_t)(avs_stream_t *stream,
                                         size_t offset,
                                         char *out_value);

/**
 * @ref avs_stream_reset implementation callback type.
 *
 * Resets stream state - which, depending on the stream may have different
 * semantics, and no constraint is imposed on the implementation.
 *
 * @param stream    Stream to reset.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
typedef avs_error_t (*avs_stream_reset_t)(avs_stream_t *stream);

/**
 * Implementation of this method closes the stream, making it ready to be
 * freed.
 *
 * @param stream    Stream to operate on.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
typedef avs_error_t (*avs_stream_close_t)(avs_stream_t *stream);

typedef struct {
    uint32_t id;
    const void *data;
} avs_stream_v_table_extension_t;

#define AVS_STREAM_V_TABLE_NO_EXTENSIONS NULL
#define AVS_STREAM_V_TABLE_EXTENSION_NULL \
    { 0, NULL }

typedef struct {
    avs_stream_write_some_t write_some;
    avs_stream_finish_message_t finish_message;
    avs_stream_read_t read;
    avs_stream_peek_t peek;
    avs_stream_reset_t reset;
    avs_stream_close_t close;
    const avs_stream_v_table_extension_t *extension_list;
} avs_stream_v_table_t;

const void *avs_stream_v_table_find_extension(avs_stream_t *stream,
                                              uint32_t id);

#define AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK 0x4E424C4BUL /* "NBLK" */

/**
 * @ref avs_stream_nonblock_read_ready implementation callback type
 *
 * Checks whether the following call to @ref avs_stream_read can be performed in
 * a non-blocking manner, without performing external I/O.
 *
 * @param stream Stream to operate on.
 *
 * @returns Boolean value indicating whether non-blocking operation is possible.
 *          Any errors shall map to <c>false</c>.
 */
typedef bool (*avs_stream_nonblock_read_ready_t)(avs_stream_t *stream);

/**
 * @ref avs_stream_nonblock_write_ready implementation callback type
 *
 * Checks how much data can be passed to the stream with
 * @ref avs_stream_write_some in a non-blocking manner, without performing
 * external I/O.
 *
 * @param stream                   Stream to operate on.
 *
 * @returns Maximum number of bytes that can be written to the stream in a
 *          non-blocking manner. If non-blocking operation is not possible, 0 is
 *          returned. Any errors shall map to 0 as well.
 */
typedef size_t (*avs_stream_nonblock_write_ready_t)(avs_stream_t *stream);

typedef struct {
    avs_stream_nonblock_read_ready_t read_ready;
    avs_stream_nonblock_write_ready_t write_ready;
} avs_stream_v_table_extension_nonblock_t;

#define AVS_STREAM_V_TABLE_EXTENSION_OFFSET 0x4F464653UL /* "OFFS" */

/**
 * @ref avs_stream_offset implementation callback type.
 *
 * Writes stream cursor absolute position to @p out_offset. On error
 * @p out_offset remains unchanged.
 *
 * @param stream     Stream to operate on
 *
 * @param out_offset Stream cursor position, must not be NULL
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
typedef avs_error_t (*avs_stream_offset_t)(avs_stream_t *stream,
                                           avs_off_t *out_offset);

typedef struct {
    avs_stream_offset_t offset;
} avs_stream_v_table_extension_offset_t;

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_V_TABLE_H */
