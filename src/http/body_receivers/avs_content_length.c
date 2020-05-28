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

#ifdef AVS_COMMONS_WITH_AVS_HTTP

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_net.h>

#    include "../avs_body_receivers.h"

#    include "../avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const avs_stream_v_table_t *const vtable;
    avs_stream_t *backend;
    size_t content_left;
} content_length_receiver_t;

static avs_error_t content_length_read(avs_stream_t *stream_,
                                       size_t *out_bytes_read,
                                       bool *out_message_finished,
                                       void *buffer,
                                       size_t buffer_length) {
    content_length_receiver_t *stream = (content_length_receiver_t *) stream_;
    size_t bytes_read = 0;
    bool backend_message_finished = false;
    avs_error_t err = AVS_OK;
    size_t bytes_to_read = AVS_MIN(buffer_length, stream->content_left);
    if (!out_bytes_read) {
        out_bytes_read = &bytes_read;
    }
    if (bytes_to_read) {
        err = avs_stream_read(stream->backend, out_bytes_read,
                              &backend_message_finished, buffer, bytes_to_read);
        stream->content_left -= *out_bytes_read;
    } else {
        *out_bytes_read = 0;
    }
    if (avs_is_ok(err) && backend_message_finished
            && stream->content_left > 0) {
        LOG(ERROR, _("remote connection closed unexpectedly"));
        err = avs_errno(AVS_EIO);
    }
    if (out_message_finished) {
        *out_message_finished = !stream->content_left;
    }
    return err;
}

static bool content_length_nonblock_read_ready(avs_stream_t *stream_) {
    content_length_receiver_t *stream = (content_length_receiver_t *) stream_;
    if (stream->content_left) {
        return avs_stream_nonblock_read_ready(stream->backend);
    }
    return true;
}

static avs_error_t
content_length_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    content_length_receiver_t *stream = (content_length_receiver_t *) stream_;
    if (offset >= stream->content_left) {
        return AVS_EOF;
    } else {
        return avs_stream_peek(stream->backend, offset, out_value);
    }
}

static avs_error_t content_length_close(avs_stream_t *stream_) {
    content_length_receiver_t *stream = (content_length_receiver_t *) stream_;
    avs_stream_net_setsock(stream->backend, NULL); /* don't close the socket */
    return avs_stream_cleanup(&stream->backend);
}

static const avs_stream_v_table_t content_length_receiver_vtable = {
    .read = content_length_read,
    .peek = content_length_peek,
    .close = content_length_close,
    &(avs_stream_v_table_extension_t[]){
            { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
              &(avs_stream_v_table_extension_nonblock_t[])
                      {
                          {
                              .read_ready = content_length_nonblock_read_ready
                          }
                      }[0] },
            AVS_STREAM_V_TABLE_EXTENSION_NULL }[0]
};

avs_stream_t *
_avs_http_body_receiver_content_length_create(avs_stream_t *backend,
                                              size_t content_length) {
    content_length_receiver_t *retval =
            (content_length_receiver_t *) avs_malloc(sizeof(*retval));
    LOG(TRACE, _("create_content_length_receiver"));
    if (retval) {
        *(const avs_stream_v_table_t **) (intptr_t) &retval->vtable =
                &content_length_receiver_vtable;
        retval->backend = backend;
        retval->content_left = content_length;
    }
    return (avs_stream_t *) retval;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
