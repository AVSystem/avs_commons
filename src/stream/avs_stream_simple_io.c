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

#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_simple_io.h>
#    include <avsystem/commons/avs_stream_v_table.h>

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const void *const vtable;
    void *context;
    avs_simple_io_stream_writer_t *writer;
    avs_simple_io_stream_reader_t *reader;
    bool message_finished;
} simple_io_stream_t;

static avs_error_t stream_simple_io_write_some(avs_stream_t *stream_,
                                               const void *buffer,
                                               size_t *inout_data_length) {
    simple_io_stream_t *stream = (simple_io_stream_t *) stream_;
    if (!stream->writer) {
        return avs_errno(AVS_EBADF);
    }
    if (!inout_data_length) {
        return avs_errno(AVS_EINVAL);
    }

    if (*inout_data_length == 0) {
        return AVS_OK;
    }

    if (!buffer) {
        return avs_errno(AVS_EINVAL);
    }

    int retval = stream->writer(stream->context, buffer, inout_data_length);

    if (retval < 0) {
        return avs_errno(AVS_EIO);
    }
    return AVS_OK;
}

static avs_error_t stream_simple_io_read(avs_stream_t *stream_,
                                         size_t *out_bytes_read,
                                         bool *out_message_finished,
                                         void *buffer,
                                         size_t buffer_length) {
    simple_io_stream_t *stream = (simple_io_stream_t *) stream_;
    if (!stream->reader) {
        return avs_errno(AVS_EBADF);
    }

    if (buffer_length == 0) {
        if (out_message_finished) {
            *out_message_finished = stream->message_finished;
        }
        if (out_bytes_read) {
            *out_bytes_read = 0;
        }
        return AVS_OK;
    }

    if (!buffer) {
        return avs_errno(AVS_EINVAL);
    }

    size_t bytes_read = buffer_length;
    int retval = stream->reader(stream->context, buffer, &bytes_read);

    if (retval < 0) {
        return avs_errno(AVS_EIO);
    }

    stream->message_finished = (bytes_read < buffer_length);

    if (out_message_finished) {
        *out_message_finished = stream->message_finished;
    }
    if (out_bytes_read) {
        *out_bytes_read = bytes_read;
    }
    return AVS_OK;
}

static avs_error_t stream_simple_finish_message(avs_stream_t *stream) {
    (void) stream;
    return AVS_OK;
}

static const avs_stream_v_table_t simple_io_stream_vtable = {
    .write_some = stream_simple_io_write_some,
    .read = stream_simple_io_read,
    .finish_message = stream_simple_finish_message
};

static avs_stream_t *
avs_stream_simple_io_create(avs_simple_io_stream_writer_t *writer,
                            avs_simple_io_stream_reader_t *reader,
                            void *context) {
    simple_io_stream_t *stream =
            (simple_io_stream_t *) avs_calloc(1, sizeof(simple_io_stream_t));
    if (!stream) {
        return NULL;
    }

    const void *vtable = &simple_io_stream_vtable;
    memcpy((void *) (intptr_t) &stream->vtable, &vtable, sizeof(void *));
    stream->context = context;
    stream->writer = writer;
    stream->reader = reader;

    return (avs_stream_t *) stream;
}

avs_stream_t *
avs_stream_simple_output_create(avs_simple_io_stream_writer_t *writer,
                                void *context) {
    assert(writer);
    return avs_stream_simple_io_create(writer, NULL, context);
}

avs_stream_t *
avs_stream_simple_input_create(avs_simple_io_stream_reader_t *reader,
                               void *context) {
    assert(reader);
    return avs_stream_simple_io_create(NULL, reader, context);
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/stream/test_stream_simple_io.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_STREAM
