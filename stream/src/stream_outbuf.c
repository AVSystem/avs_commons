/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_config.h>

#include <avsystem/commons/stream/stream_outbuf.h>
#include <avsystem/commons/stream_v_table.h>

#include <assert.h>
#include <string.h>

#define MODULE_NAME avs_stream
#include <x_log_config.h>

VISIBILITY_SOURCE_BEGIN

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
