/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <avsystem/commons/stream/stream_outbuf.h>
#include <avsystem/commons/stream_v_table.h>

#include <assert.h>
#include <string.h>

#define MODULE_NAME avs_stream
#include <x_log_config.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

static int outbuf_stream_write_some(avs_stream_abstract_t *stream_,
                                    const void *buffer,
                                    size_t *inout_data_length) {
    avs_stream_outbuf_t *stream = (avs_stream_outbuf_t *) stream_;
    if (stream->message_finished) {
        return -1;
    }
    if (stream->buffer_offset + *inout_data_length > stream->buffer_size) {
        *inout_data_length = stream->buffer_size - stream->buffer_offset;
    }
    memcpy(stream->buffer + stream->buffer_offset, buffer, *inout_data_length);
    stream->buffer_offset += *inout_data_length;
    return 0;
}

static int outbuf_stream_finish(avs_stream_abstract_t *stream) {
    ((avs_stream_outbuf_t *) stream)->message_finished = 1;
    return 0;
}

static int outbuf_stream_reset(avs_stream_abstract_t *stream) {
    ((avs_stream_outbuf_t *) stream)->message_finished = 0;
    ((avs_stream_outbuf_t *) stream)->buffer_offset = 0;
    return 0;
}

static int outbuf_stream_close(avs_stream_abstract_t *stream) {
    (void) stream;
    return 0;
}

static const avs_stream_v_table_t outbuf_stream_vtable = {
    .close = outbuf_stream_close,
    .reset = outbuf_stream_reset,
    .write_some = outbuf_stream_write_some,
    .finish_message = outbuf_stream_finish,
    .extension_list = AVS_STREAM_V_TABLE_NO_EXTENSIONS
};

const avs_stream_outbuf_t AVS_STREAM_OUTBUF_STATIC_INITIALIZER
        = {&outbuf_stream_vtable, NULL, 0, 0, 0};

size_t avs_stream_outbuf_offset(avs_stream_outbuf_t *stream) {
    return stream->buffer_offset;
}

int avs_stream_outbuf_set_offset(avs_stream_outbuf_t *stream, size_t offset) {
    if (offset > stream->buffer_offset) {
        LOG(ERROR, "outbuf stream offset cannot be advanced");
        return -1;
    }
    stream->buffer_offset = offset;
    return 0;
}

void avs_stream_outbuf_set_buffer(avs_stream_outbuf_t *stream,
                                  char *buffer,
                                  size_t buffer_size) {
    stream->buffer = buffer;
    stream->buffer_size = buffer_size;
    stream->buffer_offset = 0;
}
