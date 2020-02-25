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

#ifdef AVS_COMMONS_WITH_AVS_UNIT

#    include <stdint.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_v_table.h>
#    include <avsystem/commons/avs_unit_memstream.h>
#    include <avsystem/commons/avs_unit_test.h>

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const avs_stream_v_table_t *v_table;
    void *buffer;
    size_t buffer_size;
    size_t read_ptr;
    size_t write_ptr;
} memstream_t;

static avs_error_t memstream_write_some(avs_stream_t *_stream,
                                        const void *buffer,
                                        size_t *inout_data_length) {
    memstream_t *stream = (memstream_t *) _stream;

    if (stream->write_ptr + *inout_data_length > stream->buffer_size) {
        if (stream->write_ptr + *inout_data_length - stream->read_ptr
                > stream->buffer_size) {
            *inout_data_length =
                    stream->buffer_size - stream->write_ptr + stream->read_ptr;
        }
        memmove(stream->buffer, (char *) stream->buffer + stream->read_ptr,
                stream->write_ptr - stream->read_ptr);

        stream->write_ptr -= stream->read_ptr;
        stream->read_ptr = 0;
    }

    memcpy((char *) stream->buffer + stream->write_ptr, buffer,
           *inout_data_length);
    stream->write_ptr += *inout_data_length;
    return AVS_OK;
}

static avs_error_t memstream_read(avs_stream_t *_stream,
                                  size_t *out_bytes_read,
                                  bool *out_message_finished,
                                  void *buffer,
                                  size_t buffer_length) {
    memstream_t *stream = (memstream_t *) _stream;
    bool message_finished_placeholder;

    if (!out_message_finished) {
        out_message_finished = &message_finished_placeholder;
    }

    if (stream->write_ptr - stream->read_ptr <= buffer_length) {
        *out_bytes_read = stream->write_ptr - stream->read_ptr;
        *out_message_finished = true;
    } else {
        *out_bytes_read = buffer_length;
        *out_message_finished = false;
    }

    memcpy(buffer, (char *) stream->buffer + stream->read_ptr, *out_bytes_read);
    stream->read_ptr += *out_bytes_read;
    return AVS_OK;
}

static avs_error_t
memstream_peek(avs_stream_t *_stream, size_t offset, char *out_value) {
    memstream_t *stream = (memstream_t *) _stream;

    if (offset < stream->write_ptr - stream->read_ptr) {
        *out_value = ((char *) stream->buffer)[stream->read_ptr + offset];
        return AVS_OK;
    } else {
        return AVS_EOF;
    }
}

static avs_error_t memstream_close(avs_stream_t *stream) {
    avs_free(((memstream_t *) stream)->buffer);
    return AVS_OK;
}

static avs_error_t memstream_fail() {
    AVS_UNIT_ASSERT_TRUE(0);
    return AVS_OK;
}

int avs_unit_memstream_alloc(avs_stream_t **stream, size_t buffer_size) {
    static const avs_stream_v_table_t V_TABLE = {
        memstream_write_some,
        (avs_stream_finish_message_t) memstream_fail,
        memstream_read,
        memstream_peek,
        (avs_stream_reset_t) memstream_fail,
        memstream_close,
        AVS_STREAM_V_TABLE_NO_EXTENSIONS
    };

    memstream_t *ret = (memstream_t *) avs_calloc(1, sizeof(memstream_t));
    if (!ret) {
        return -1;
    }

    ret->v_table = &V_TABLE;
    ret->buffer = (char *) avs_malloc(buffer_size);
    ret->buffer_size = buffer_size;
    ret->read_ptr = 0;
    ret->write_ptr = 0;

    if (!ret->buffer) {
        avs_free(ret);
        return -1;
    }

    *stream = (avs_stream_t *) ret;
    return 0;
}

#endif // AVS_COMMONS_WITH_AVS_UNIT
