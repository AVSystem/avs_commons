/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <avsystem/commons/stream/stream_inbuf.h>
#include <avsystem/commons/stream_v_table.h>

#include <assert.h>
#include <string.h>

#define MODULE_NAME avs_stream
#include <x_log_config.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

static int inbuf_stream_read(avs_stream_abstract_t *stream_,
                             size_t *out_bytes_read,
                             char *out_message_finished,
                             void *buffer,
                             size_t buffer_length) {
    avs_stream_inbuf_t *stream = (avs_stream_inbuf_t *) stream_;
    size_t bytes_left, bytes_read;
    if (!buffer) {
        return -1;
    }

    assert(stream->buffer_offset <= stream->buffer_size);

    bytes_left = stream->buffer_size - stream->buffer_offset;
    bytes_read = bytes_left < buffer_length ? bytes_left : buffer_length;
    memcpy(buffer, (const char *) stream->buffer + stream->buffer_offset,
           bytes_read);
    stream->buffer_offset += bytes_read;

    *out_message_finished = stream->buffer_offset >= stream->buffer_size;
    *out_bytes_read = bytes_read;
    return 0;
}

static int inbuf_stream_peek(avs_stream_abstract_t *stream_,
                             size_t offset) {
    avs_stream_inbuf_t *stream = (avs_stream_inbuf_t *) stream_;

    if (stream->buffer_offset + offset >= stream->buffer_size) {
        return EOF;
    }
    return (unsigned char) stream->buffer[stream->buffer_offset + offset];
}

static int inbuf_stream_close(avs_stream_abstract_t *stream_) {
    (void) stream_;
    return 0;
}

static const avs_stream_v_table_t inbuf_stream_vtable = {
    .close = inbuf_stream_close,
    .peek = inbuf_stream_peek,
    .read = inbuf_stream_read,
    .extension_list = AVS_STREAM_V_TABLE_NO_EXTENSIONS
};

const avs_stream_inbuf_t AVS_STREAM_INBUF_STATIC_INITIALIZER
        = {&inbuf_stream_vtable, NULL, 0, 0};

void avs_stream_inbuf_set_buffer(avs_stream_inbuf_t *stream,
                                 const char *buffer,
                                 size_t buffer_size) {
    stream->buffer = buffer;
    stream->buffer_size = buffer_size;
    stream->buffer_offset = 0;
}
