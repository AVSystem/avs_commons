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

#include <config.h>

#include <avsystem/commons/stream/net.h>

#include "../body_receivers.h"
#include "../log.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

typedef struct {
    const avs_stream_v_table_t * const vtable;
    avs_stream_abstract_t *backend;
    size_t content_left;
} content_length_receiver_t;

static int content_length_read(avs_stream_abstract_t *stream_,
                               size_t *out_bytes_read,
                               char *out_message_finished,
                               void *buffer,
                               size_t buffer_length) {
    content_length_receiver_t *stream =
            (content_length_receiver_t *) stream_;
    size_t bytes_read = 0;
    char backend_message_finished = 0;
    int result = 0;
    size_t bytes_to_read = AVS_MIN(buffer_length, stream->content_left);
    if (!out_bytes_read) {
        out_bytes_read = &bytes_read;
    }
    if (bytes_to_read) {
        result = avs_stream_read(stream->backend, out_bytes_read,
                                 &backend_message_finished,
                                 buffer, bytes_to_read);
        stream->content_left -= *out_bytes_read;
    } else {
        *out_bytes_read = 0;
    }
    if (result == 0 && backend_message_finished && stream->content_left > 0) {
        LOG(ERROR, "remote connection closed unexpectedly");
        result = -1;
    }
    if (out_message_finished) {
        *out_message_finished = !stream->content_left;
    }
    if (result) {
        LOG(ERROR, "content_length_read: result == %d", result);
    }
    return result;
}

static int content_length_peek(avs_stream_abstract_t *stream_, size_t offset) {
    content_length_receiver_t *stream =
            (content_length_receiver_t *) stream_;
    int result;
    if (offset >= stream->content_left) {
        result = EOF;
    } else {
        result = avs_stream_peek(stream->backend, offset);
    }
    return result;
}

static int content_length_close(avs_stream_abstract_t *stream_) {
    content_length_receiver_t *stream = (content_length_receiver_t *) stream_;
    avs_stream_net_setsock(stream->backend, NULL); /* don't close the socket */
    avs_stream_cleanup(&stream->backend);
    return 0;
}

static int content_length_errno(avs_stream_abstract_t *stream) {
    return avs_stream_errno(((content_length_receiver_t *) stream)->backend);
}

static int unimplemented() {
    LOG(ERROR, "Vtable method unimplemented");
    return -1;
}

static const avs_stream_v_table_t content_length_receiver_vtable = {
    (avs_stream_write_some_t) unimplemented,
    (avs_stream_finish_message_t) unimplemented,
    content_length_read,
    content_length_peek,
    (avs_stream_reset_t) unimplemented,
    content_length_close,
    content_length_errno,
    NULL
};

avs_stream_abstract_t *_avs_http_body_receiver_content_length_create(
        avs_stream_abstract_t *backend, size_t content_length) {
    content_length_receiver_t *retval =
            (content_length_receiver_t *) malloc(sizeof(*retval));
    LOG(TRACE, "create_content_length_receiver");
    if (retval) {
        *(const avs_stream_v_table_t **) (intptr_t) &retval->vtable =
                &content_length_receiver_vtable;
        retval->backend = backend;
        retval->content_left = content_length;
    }
    return (avs_stream_abstract_t *) retval;
}
