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

#ifndef AVS_COMMONS_STREAM_FILE_H
#define AVS_COMMONS_STREAM_FILE_H

#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVS_STREAM_V_TABLE_EXTENSION_FILE 0x46494c45UL /* "FILE" */

typedef avs_error_t (*avs_stream_file_length_t)(avs_stream_t *stream,
                                                avs_off_t *out_length);
typedef avs_error_t (*avs_stream_file_seek_t)(avs_stream_t *stream,
                                              avs_off_t offset_from_start);

typedef struct {
    avs_stream_file_length_t length;
    avs_stream_file_seek_t seek;
} avs_stream_v_table_extension_file_t;

/**
 * Computes length of the file the stream operates on and writes it to
 * @p out_length. On error @p out_length remains unchanged.
 *
 * @param stream        file stream pointer
 * @param out_length    length of the file, must not be NULL
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_stream_file_length(avs_stream_t *stream, avs_off_t *out_length);

/**
 * Writes stream cursor absolute position to @p out_offset. On error
 * @p out_offset remains unchanged.
 *
 * Alias to @ref avs_stream_offset for backwards compatibility.
 *
 * @param stream        file stream pointer
 * @param out_offset    stream cursor position, must not be NULL
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
static inline avs_error_t avs_stream_file_offset(avs_stream_t *stream,
                                                 avs_off_t *out_offset) {
    return avs_stream_offset(stream, out_offset);
}

/**
 * Moves stream cursor to absolute position @p offset_from_start.
 *
 * @param stream            file stream pointer
 * @param offset_from_start absolute offset, must nonnegative
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_stream_file_seek(avs_stream_t *stream,
                                 avs_off_t offset_from_start);

#define AVS_STREAM_FILE_READ 0x01
#define AVS_STREAM_FILE_WRITE 0x02
typedef struct avs_file_stream_struct avs_stream_file_t;
/**
 * Creates a new file-stream. If file referred by @p path does not exist and
 * AVS_STREAM_FILE_WRITE flag is set in @p mode, then an attempt to create
 * a file is made.
 *
 * Function fails if any of the following is true:
 * 1. file referred in @p path does not exist and @ref AVS_STREAM_FILE_WRITE
 * flag is set, but the file cannot be created
 * 2. file referred in @p path does not exist and @ref AVS_STREAM_FILE_WRITE is
 *    not set
 * 3. there are no sufficient permissions to open file with given flag
 *    combination
 * 4. @p mode has invalid value (i.e. it is not a combination of allowed flags)
 * 5. there is not enough memory to initialize stream (in which case it is
 *    guaranteed that @p out_stream is untouched)
 *
 * Note: if @ref AVS_STREAM_FILE_WRITE flag is set and the file exists then
 * it is truncated.
 *
 * @param out_stream    pointer to the place where initialized stream pointer
 *                      is written
 * @param path          path to the file
 * @param mode          combination of @ref AVS_STREAM_FILE_READ,
 *                                     @ref AVS_STREAM_FILE_WRITE
 * @return pointer to the new file stream, NULL on error
 */
avs_stream_t *avs_stream_file_create(const char *path, uint8_t mode);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_FILE_H */
