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

typedef int (*avs_stream_write_t)(avs_stream_abstract_t *stream,
                                  const void *buffer,
                                  size_t buffer_length);

typedef int (*avs_stream_finish_message_t)(avs_stream_abstract_t *stream);

typedef int (*avs_stream_read_t)(avs_stream_abstract_t *stream,
                                 size_t *out_bytes_read,
                                 char *out_message_finished,
                                 void *buffer,
                                 size_t buffer_length);

typedef int (*avs_stream_peek_t)(avs_stream_abstract_t *stream,
                                 size_t offset);

typedef int (*avs_stream_reset_t)(avs_stream_abstract_t *stream);

typedef int (*avs_stream_close_t)(avs_stream_abstract_t *stream);

typedef int (*avs_stream_errno_t)(avs_stream_abstract_t *stream);

typedef struct {
    uint32_t id;
    const void *data;
} avs_stream_v_table_extension_t;

#define AVS_STREAM_V_TABLE_NO_EXTENSIONS NULL
#define AVS_STREAM_V_TABLE_EXTENSION_NULL { 0, NULL }

typedef struct {
    avs_stream_write_t write;
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

