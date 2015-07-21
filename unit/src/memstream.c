/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/stream_v_table.h>
#include <avsystem/commons/unit/memstream.h>

typedef struct {
    const avs_stream_v_table_t *v_table;
    void *buffer;
    size_t buffer_size;
    size_t read_ptr;
    size_t write_ptr;
} memstream_t;

static int memstream_write(avs_stream_abstract_t *_stream,
                           const void *buffer,
                           size_t buffer_length) {
    memstream_t *stream = (memstream_t*)_stream;

    if (stream->write_ptr + buffer_length > stream->buffer_size) {
        if (stream->write_ptr + buffer_length - stream->read_ptr
                <= stream->buffer_size) {
            memmove(stream->buffer, (char*)stream->buffer + stream->read_ptr,
                    stream->write_ptr - stream->read_ptr);

            stream->write_ptr -= stream->read_ptr;
            stream->read_ptr = 0;
        } else {
            return -1;
        }
    }

    memcpy((char*)stream->buffer + stream->write_ptr, buffer, buffer_length);
    stream->write_ptr += buffer_length;
    return 0;
}

static int memstream_read(avs_stream_abstract_t *_stream,
                          size_t *out_bytes_read,
                          char *out_message_finished,
                          void *buffer,
                          size_t buffer_length) {
    memstream_t *stream = (memstream_t*)_stream;
    char message_finished_placeholder;

    if (!out_message_finished) {
        out_message_finished = &message_finished_placeholder;
    }

    if (stream->write_ptr - stream->read_ptr <= buffer_length) {
        *out_bytes_read = stream->write_ptr - stream->read_ptr;
        *out_message_finished = 1;
    } else {
        *out_bytes_read = buffer_length;
        *out_message_finished = 0;
    }

    memcpy(buffer, (char*)stream->buffer + stream->read_ptr, *out_bytes_read);
    stream->read_ptr += *out_bytes_read;
    return 0;
}

static int memstream_peek(avs_stream_abstract_t *_stream,
                          size_t offset) {
    memstream_t *stream = (memstream_t*)_stream;

    if (offset < stream->write_ptr - stream->read_ptr) {
        return ((char*)stream->buffer)[stream->read_ptr + offset];
    } else {
        return EOF;
    }
}

int avs_unit_memstream_alloc(avs_stream_abstract_t** stream,
                             size_t buffer_size) {
    static const avs_stream_v_table_t V_TABLE = {
        memstream_write,
        NULL,
        memstream_read,
        memstream_peek,
        NULL,
        NULL,
        NULL,
        NULL
    };

    memstream_t *ret = (memstream_t*) calloc(1, sizeof(memstream_t));
    if (!ret) {
        return -1;
    }

    ret->v_table = &V_TABLE;
    ret->buffer = (char*) malloc(buffer_size);
    ret->buffer_size = buffer_size;
    ret->read_ptr = 0;
    ret->write_ptr = 0;

    if (!ret->buffer) {
        free(ret);
        return -1;
    }

    *stream = (avs_stream_abstract_t*)ret;
    return 0;
}

void avs_unit_memstream_free(avs_stream_abstract_t *stream) {
    free(((memstream_t*)stream)->buffer);
    free(stream);
}
