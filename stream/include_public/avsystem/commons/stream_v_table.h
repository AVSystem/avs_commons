/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_V_TABLE_H
#define	AVS_COMMONS_STREAM_V_TABLE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <avsystem/commons/stream.h>

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
 * @returns 0 on success, negative value on error.
 */
typedef int (*avs_stream_write_some_t)(avs_stream_abstract_t *stream,
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
 * @param stream    Stream to operate on.
 */
typedef int (*avs_stream_finish_message_t)(avs_stream_abstract_t *stream);

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
 * Note: even if the final outcome of the read operation is an error, it is still
 * allowed for the implementation to write some data to the @p buffer .
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
 */
typedef int (*avs_stream_read_t)(avs_stream_abstract_t *stream,
                                 size_t *out_bytes_read,
                                 char *out_message_finished,
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
 * @param stream    Stream to operate on.
 * @param offset    Offset from the current stream position.
 * @returns 0 on success, EOF if a character cannot be read, negative value
 * (different than EOF) in case of error.
 */
typedef int (*avs_stream_peek_t)(avs_stream_abstract_t *stream,
                                 size_t offset);

/**
 * @ref avs_stream_reset implementation callback type.
 *
 * Resets stream state - which, depending on the stream may have different
 * semantics, and no constraint is imposed on the implementation.
 *
 * @param stream    Stream to reset.
 * @returns 0 on success, negative value on error.
 */
typedef int (*avs_stream_reset_t)(avs_stream_abstract_t *stream);

/**
 * Implementation of this method closes the stream, making it ready to be
 * freed.
 *
 * @param stream    Stream to operate on.
 * @returns 0 on success, negative value on error.
 */
typedef int (*avs_stream_close_t)(avs_stream_abstract_t *stream);

/**
 * @ref avs_stream_errno implementation callback type
 *
 * Obtains additional information about last stream error.
 *
 * @param stream    Stream to operate on.
 * @returns last error code or 0 if no error occurred.
 */
typedef int (*avs_stream_errno_t)(avs_stream_abstract_t *stream);

typedef struct {
    uint32_t id;
    const void *data;
} avs_stream_v_table_extension_t;

#define AVS_STREAM_V_TABLE_NO_EXTENSIONS NULL
#define AVS_STREAM_V_TABLE_EXTENSION_NULL { 0, NULL }

typedef struct {
    avs_stream_write_some_t write_some;
    avs_stream_finish_message_t finish_message;
    avs_stream_read_t read;
    avs_stream_peek_t peek;
    avs_stream_reset_t reset;
    avs_stream_close_t close;
    avs_stream_errno_t get_errno;
    const avs_stream_v_table_extension_t *extension_list;
} avs_stream_v_table_t;

const void *avs_stream_v_table_find_extension(avs_stream_abstract_t *stream,
                                              uint32_t id);

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_STREAM_V_TABLE_H */

