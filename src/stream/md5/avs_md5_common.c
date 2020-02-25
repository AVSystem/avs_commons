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

#    include <stdio.h>
#    include <string.h>

#    include "avs_md5_common.h"

VISIBILITY_SOURCE_BEGIN

avs_error_t _avs_stream_md5_common_read(avs_stream_t *stream,
                                        size_t *out_bytes_read,
                                        bool *out_message_finished,
                                        void *buffer,
                                        size_t buffer_length) {
    avs_stream_md5_common_t *str = (avs_stream_md5_common_t *) stream;

    size_t bytes_read;
    bool message_finished;

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

    return AVS_OK;
}

char _avs_stream_md5_common_is_finalized(avs_stream_md5_common_t *stream) {
    return stream->out_ptr == 0;
}

void _avs_stream_md5_common_init(avs_stream_md5_common_t *stream,
                                 const avs_stream_v_table_t *const vtable) {
    *(const avs_stream_v_table_t **) (intptr_t) &stream->vtable = vtable;
    stream->out_ptr = MD5_LENGTH;
}

void _avs_stream_md5_common_finalize(avs_stream_md5_common_t *stream) {
    stream->out_ptr = 0;
}

void _avs_stream_md5_common_reset(avs_stream_md5_common_t *stream) {
    stream->out_ptr = MD5_LENGTH;
}

#endif // AVS_COMMONS_WITH_AVS_STREAM
