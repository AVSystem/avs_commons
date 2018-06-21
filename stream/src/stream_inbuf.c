/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/stream/stream_inbuf.h>
#include <avsystem/commons/stream_v_table.h>

#include <assert.h>
#include <string.h>

#define MODULE_NAME avs_stream
#include <x_log_config.h>

VISIBILITY_SOURCE_BEGIN

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
    return ((const unsigned char *) stream->buffer)[
            stream->buffer_offset + offset];
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
                                 const void *buffer,
                                 size_t buffer_size) {
    stream->buffer = buffer;
    stream->buffer_size = buffer_size;
    stream->buffer_offset = 0;
}
