/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_STREAM_OUTBUF_H
#define AVS_COMMONS_STREAM_STREAM_OUTBUF_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include <avsystem/commons/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
    const void *const vtable;
    char *buffer;
    size_t buffer_size;
    size_t buffer_offset;
    char message_finished;
} avs_stream_outbuf_t;

extern const avs_stream_outbuf_t AVS_STREAM_OUTBUF_STATIC_INITIALIZER;

size_t avs_stream_outbuf_offset(avs_stream_outbuf_t *stream);

int avs_stream_outbuf_set_offset(avs_stream_outbuf_t *stream, size_t offset);

void avs_stream_outbuf_set_buffer(avs_stream_outbuf_t *stream,
                                  char *buffer,
                                  size_t buffer_size);

#ifdef	__cplusplus
}
#endif
#endif /* STREAM_STREAM_OUTBUF_H */
