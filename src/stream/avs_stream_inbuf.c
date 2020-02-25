/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_STREAM

#    include <avsystem/commons/avs_stream_inbuf.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    include <assert.h>
#    include <string.h>

#    define MODULE_NAME avs_stream
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static avs_error_t inbuf_stream_read(avs_stream_t *stream_,
                                     size_t *out_bytes_read,
                                     bool *out_message_finished,
                                     void *buffer,
                                     size_t buffer_length) {
    avs_stream_inbuf_t *stream = (avs_stream_inbuf_t *) stream_;
    size_t bytes_left, bytes_read;
    if (!buffer_length) {
        return AVS_OK;
    }
    if (!buffer) {
        return avs_errno(AVS_EINVAL);
    }

    assert(stream->buffer_offset <= stream->buffer_size);

    bytes_left = stream->buffer_size - stream->buffer_offset;
    bytes_read = bytes_left < buffer_length ? bytes_left : buffer_length;
    memcpy(buffer, (const char *) stream->buffer + stream->buffer_offset,
           bytes_read);
    stream->buffer_offset += bytes_read;

    if (out_message_finished) {
        *out_message_finished = stream->buffer_offset >= stream->buffer_size;
    }
    if (out_bytes_read) {
        *out_bytes_read = bytes_read;
    }

    return AVS_OK;
}

static avs_error_t
inbuf_stream_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    avs_stream_inbuf_t *stream = (avs_stream_inbuf_t *) stream_;

    if (stream->buffer_offset + offset >= stream->buffer_size) {
        return AVS_EOF;
    }
    *out_value =
            ((const char *) stream->buffer)[stream->buffer_offset + offset];
    return AVS_OK;
}

static const avs_stream_v_table_t inbuf_stream_vtable = {
    .peek = inbuf_stream_peek,
    .read = inbuf_stream_read,
    .extension_list = AVS_STREAM_V_TABLE_NO_EXTENSIONS
};

const avs_stream_inbuf_t AVS_STREAM_INBUF_STATIC_INITIALIZER = {
    &inbuf_stream_vtable, NULL, 0, 0
};

void avs_stream_inbuf_set_buffer(avs_stream_inbuf_t *stream,
                                 const void *buffer,
                                 size_t buffer_size) {
    stream->buffer = buffer;
    stream->buffer_size = buffer_size;
    stream->buffer_offset = 0;
}

#endif // AVS_COMMONS_WITH_AVS_STREAM
