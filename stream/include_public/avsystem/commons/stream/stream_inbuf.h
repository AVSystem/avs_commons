/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_STREAM_INBUF_H
#define	AVS_COMMONS_STREAM_STREAM_INBUF_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include <avsystem/commons/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
    const void *const vtable;
    const char *buffer;
    size_t buffer_size;
    size_t buffer_offset;
} avs_stream_inbuf_t;

extern const avs_stream_inbuf_t AVS_STREAM_INBUF_STATIC_INITIALIZER;

void avs_stream_inbuf_set_buffer(avs_stream_inbuf_t *stream,
                                 const char *buffer,
                                 size_t buffer_size);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_STREAM_INBUF_H */
