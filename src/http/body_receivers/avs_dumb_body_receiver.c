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
} dumb_proxy_receiver_t;

static avs_error_t dumb_proxy_read(avs_stream_t *stream,
                                   size_t *out_bytes_read,
                                   bool *out_message_finished,
                                   void *buffer,
                                   size_t buffer_length) {
    return avs_stream_read(((dumb_proxy_receiver_t *) stream)->backend,
                           out_bytes_read, out_message_finished, buffer,
                           buffer_length);
}

static bool dumb_proxy_nonblock_read_ready(avs_stream_t *stream) {
    return avs_stream_nonblock_read_ready(
            ((dumb_proxy_receiver_t *) stream)->backend);
}

static avs_error_t
dumb_proxy_peek(avs_stream_t *stream, size_t offset, char *out_value) {
    return avs_stream_peek(((dumb_proxy_receiver_t *) stream)->backend, offset,
                           out_value);
}

static avs_error_t dumb_close(avs_stream_t *stream_) {
    dumb_proxy_receiver_t *stream = (dumb_proxy_receiver_t *) stream_;
    avs_stream_net_setsock(stream->backend, NULL); /* don't close the socket */
    return avs_stream_cleanup(&stream->backend);
}

static const avs_stream_v_table_t dumb_body_receiver_vtable = {
    .read = dumb_proxy_read,
    .peek = dumb_proxy_peek,
    .close = dumb_close,
    &(avs_stream_v_table_extension_t[]){
            { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
              &(avs_stream_v_table_extension_nonblock_t[])
                      {
                          {
                              .read_ready = dumb_proxy_nonblock_read_ready
                          }
                      }[0] },
            AVS_STREAM_V_TABLE_EXTENSION_NULL }[0]
};

avs_stream_t *_avs_http_body_receiver_dumb_create(avs_stream_t *backend) {
    dumb_proxy_receiver_t *retval =
            (dumb_proxy_receiver_t *) avs_malloc(sizeof(*retval));
    LOG(TRACE, _("create_dumb_body_receiver"));
    if (retval) {
        *(const avs_stream_v_table_t **) (intptr_t) &retval->vtable =
                &dumb_body_receiver_vtable;
        retval->backend = backend;
    }
    return (avs_stream_t *) retval;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
