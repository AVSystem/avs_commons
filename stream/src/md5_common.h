/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef MD5_COMMON_H
#define	MD5_COMMON_H

#include <avsystem/commons/stream.h>
#include <avsystem/commons/stream_v_table.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

#define MD5_LENGTH 16

typedef struct {
    const avs_stream_v_table_t * const vtable;
    unsigned char result[MD5_LENGTH];
    size_t out_ptr;
} avs_stream_md5_common_t;

int _avs_stream_md5_common_read(avs_stream_abstract_t *stream,
                                size_t *out_bytes_read,
                                char *out_message_finished,
                                void *buffer,
                                size_t buffer_length);

char _avs_stream_md5_common_is_finalized(avs_stream_md5_common_t *stream);
void _avs_stream_md5_common_init(avs_stream_md5_common_t *stream,
                                 const avs_stream_v_table_t * const vtable);
void _avs_stream_md5_common_finalize(avs_stream_md5_common_t *stream);
void _avs_stream_md5_common_reset(avs_stream_md5_common_t *stream);

#ifdef HAVE_VISIBILITY
#pragma GCC visibility pop
#endif

#endif	/* MD5_COMMON_H */

