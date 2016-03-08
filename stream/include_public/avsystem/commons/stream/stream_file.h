/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_FILE_H
#define	AVS_COMMONS_STREAM_FILE_H

#include <avsystem/commons/net.h>
#include <avsystem/commons/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define AVS_STREAM_V_TABLE_EXTENSION_FILE 0x46494c45UL /* "FILE" */

typedef int (*avs_stream_file_length_t)(avs_stream_abstract_t *stream,
                                        avs_off_t *out_length);
typedef int (*avs_stream_file_offset_t)(avs_stream_abstract_t *stream,
                                        avs_off_t *out_position);
typedef int (*avs_stream_file_seek_t)(avs_stream_abstract_t *stream,
                                      avs_off_t offset_from_start);

typedef struct {
    avs_stream_file_length_t length;
    avs_stream_file_offset_t offset;
    avs_stream_file_seek_t seek;
} avs_stream_v_table_extension_file_t;

/**
 * Computes length of the file the stream operates on and writes it to
 * @p out_length. On error @p out_length remains unchanged, and more information
 * can be obtained by calling @ref avs_stream_errno.
 *
 * @param stream        file stream pointer
 * @param out_length    length of the file, must not be NULL
 * @return 0 on success, negative value otherwise
 */
int avs_stream_file_length(avs_stream_abstract_t *stream,
                           avs_off_t *out_length);

/**
 * Writes stream cursor absolute position to @p out_offset. On error
 * @p out_offset remains unchanged, and more information can be obtained by
 * calling @ref avs_stream_errno.
 *
 * @param stream        file stream pointer
 * @param out_offset    stream cursor position, must not be NULL
 * @return 0 on success, negative value otherwise
 */
int avs_stream_file_offset(avs_stream_abstract_t *stream,
                           avs_off_t *out_offset);

/**
 * Moves stream cursor to absolute position @p offset_from_start, on error
 * more information can be obtained by calling @ref avs_stream_errno.
 *
 * @param stream            file stream pointer
 * @param offset_from_start absolute offset, must nonnegative
 * @return 0 on success, negative value otherwise
 */
int avs_stream_file_seek(avs_stream_abstract_t *stream,
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
 * 1. file referred in @p path does not exist and @ref AVS_STREAM_FILE_WRITE flag
 *    is set, but the file cannot be created
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
avs_stream_abstract_t *avs_stream_file_create(const char *path,
                                              uint8_t mode);

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_STREAM_FILE_H */
