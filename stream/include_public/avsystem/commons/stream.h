/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_H
#define	AVS_COMMONS_STREAM_H

#include <stdarg.h>
#include <stddef.h>

#include <avsystem/commons/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct avs_stream_abstract_struct;
typedef struct avs_stream_abstract_struct avs_stream_abstract_t;

int avs_stream_write(avs_stream_abstract_t *stream,
                     const void *buffer,
                     size_t buffer_length);

int avs_stream_finish_message(avs_stream_abstract_t *stream);

int avs_stream_write_f(avs_stream_abstract_t *stream,
                       const char *msg, ...) AVS_F_PRINTF(2, 3);

int avs_stream_write_fv(avs_stream_abstract_t *stream,
                        const char *msg,
                        va_list args);

int avs_stream_read(avs_stream_abstract_t *stream,
                    size_t *out_bytes_read,
                    char *out_message_finished,
                    void *buffer,
                    size_t buffer_length);

int avs_stream_read_reliably(avs_stream_abstract_t *stream,
                             void *buffer,
                             size_t buffer_length);

int avs_stream_ignore_to_end(avs_stream_abstract_t *stream);

int avs_stream_peek(avs_stream_abstract_t *stream, size_t offset);

int avs_stream_getch(avs_stream_abstract_t *stream, char *message_finished);

int avs_stream_getline(avs_stream_abstract_t *stream,
                       size_t *out_bytes_read,
                       char *out_message_finished,
                       char *buffer,
                       size_t buffer_length);

int avs_stream_peekline(avs_stream_abstract_t *stream,
                        size_t offset,
                        size_t *out_bytes_peeked,
                        size_t *out_next_offset,
                        char *buffer,
                        size_t buffer_length);

int avs_stream_reset(avs_stream_abstract_t *stream);

void avs_stream_cleanup(avs_stream_abstract_t **stream);

int avs_stream_errno(avs_stream_abstract_t *stream);

typedef struct {
    const void * const vtable;
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

#endif	/* STREAM_H */

