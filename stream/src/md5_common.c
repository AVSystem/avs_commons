/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <stdio.h>
#include <string.h>

#include "md5_common.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

int _avs_stream_md5_common_read(avs_stream_abstract_t *stream,
                                size_t *out_bytes_read,
                                char *out_message_finished,
                                void *buffer,
                                size_t buffer_length) {
    avs_stream_md5_common_t * str = (avs_stream_md5_common_t *) stream;

    size_t bytes_read;
    char message_finished;

    if (!out_bytes_read) {
        out_bytes_read = &bytes_read;
    }
    if (!out_message_finished) {
        out_message_finished = &message_finished;
    }

    *out_bytes_read = MD5_LENGTH - str->out_ptr;
    if (buffer_length < *out_bytes_read) {
        *out_bytes_read = buffer_length;
    }

    memcpy(buffer, str->result, *out_bytes_read);
    str->out_ptr += *out_bytes_read;

    if ((*out_message_finished = (str->out_ptr == MD5_LENGTH))) {
        return avs_stream_reset(stream);
    }

    return 0;
}

char _avs_stream_md5_common_is_finalized(avs_stream_md5_common_t *stream) {
    return stream->out_ptr == 0;
}

void _avs_stream_md5_common_init(avs_stream_md5_common_t *stream,
                                 const avs_stream_v_table_t * const vtable) {
    *(const avs_stream_v_table_t **) (intptr_t) &stream->vtable = vtable;
    stream->out_ptr = MD5_LENGTH;
}

void _avs_stream_md5_common_finalize(avs_stream_md5_common_t *stream) {
    stream->out_ptr = 0;
}

void _avs_stream_md5_common_reset(avs_stream_md5_common_t *stream) {
    stream->out_ptr = MD5_LENGTH;
}
