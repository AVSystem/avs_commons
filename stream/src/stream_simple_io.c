/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#include <string.h>

#include <avsystem/commons/memory.h>
#include <avsystem/commons/stream/stream_simple_io.h>
#include <avsystem/commons/stream_v_table.h>

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const void *const vtable;
    void *context;
    avs_simple_io_stream_writer_t *writer;
    avs_simple_io_stream_reader_t *reader;
    bool message_finished;
} simple_io_stream_t;

static int stream_simple_io_write_some(avs_stream_abstract_t *stream_,
                                       const void *buffer,
                                       size_t *inout_data_length) {
    simple_io_stream_t *stream = (simple_io_stream_t *) stream_;
    if (!stream->writer || !inout_data_length) {
        return -1;
    }

    if (*inout_data_length == 0) {
        return 0;
    }

    if (!buffer) {
        return -1;
    }

    int retval = stream->writer(stream->context, buffer, inout_data_length);

    if (retval < 0) {
        return retval;
    }
    return 0;
}

static int stream_simple_io_read(avs_stream_abstract_t *stream_,
                                 size_t *out_bytes_read,
                                 char *out_message_finished,
                                 void *buffer,
                                 size_t buffer_length) {
    simple_io_stream_t *stream = (simple_io_stream_t *) stream_;
    if (!stream->reader) {
        return -1;
    }

    if (buffer_length == 0) {
        if (out_message_finished) {
            *out_message_finished = stream->message_finished;
        }
        if (out_bytes_read) {
            *out_bytes_read = 0;
        }
        return 0;
    }

    if (!buffer) {
        return -1;
    }

    size_t bytes_read = buffer_length;
    int retval = stream->reader(stream->context, buffer, &bytes_read);

    if (retval < 0) {
        return retval;
    }

    stream->message_finished = (bytes_read < buffer_length);

    if (out_message_finished) {
        *out_message_finished = stream->message_finished;
    }
    if (out_bytes_read) {
        *out_bytes_read = bytes_read;
    }
    return 0;
}

static int stream_simple_finish_message(avs_stream_abstract_t *stream) {
    (void) stream;
    return 0;
}

static const avs_stream_v_table_t simple_io_stream_vtable = {
    .write_some = stream_simple_io_write_some,
    .read = stream_simple_io_read,
    .finish_message = stream_simple_finish_message
};

static avs_stream_abstract_t *
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

    return (avs_stream_abstract_t *) stream;
}

avs_stream_abstract_t *
avs_stream_simple_output_create(avs_simple_io_stream_writer_t *writer,
                                void *context) {
    assert(writer);
    return avs_stream_simple_io_create(writer, NULL, context);
}

avs_stream_abstract_t *
avs_stream_simple_input_create(avs_simple_io_stream_reader_t *reader,
                               void *context) {
    assert(reader);
    return avs_stream_simple_io_create(NULL, reader, context);
}

#ifdef AVS_UNIT_TESTING
#    include "test/test_stream_simple_io.c"
#endif
