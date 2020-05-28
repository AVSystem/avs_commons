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

#    include <avsystem/commons/avs_stream_net.h>
#    include <avsystem/commons/avs_stream_netbuf.h>

#    include "avs_body_receivers.h"
#    include "avs_client.h"
#    include "avs_content_encoding.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

/******** Generic constructor */
static avs_stream_t *
create_body_receiver(avs_stream_t *backend,
                     const avs_http_buffer_sizes_t *buffer_sizes,
                     http_transfer_encoding_t transfer_encoding,
                     size_t content_length) {
    avs_stream_t *buffer = NULL;
    avs_stream_t *retval = NULL;
    avs_net_socket_t *backend_socket = NULL;
    LOG(TRACE,
        _("create_body_receiver, transfer_encoding == ") "%d" _(", ")
                _("content_length == ") "%lu",
        (int) transfer_encoding, (unsigned long) content_length);

    if (backend && (backend_socket = avs_stream_net_getsock(backend))) {
        avs_stream_netbuf_create(&buffer, backend_socket,
                                 buffer_sizes->body_recv, 0);
    }
    if (!buffer) {
        LOG(ERROR, _("could not create buffered netstream"));
        return NULL;
    }

    if (avs_stream_netbuf_transfer(buffer, backend)) {
        LOG(ERROR, _("could not transfer buffered data"));
        goto create_body_receiver_return;
    }

    switch (transfer_encoding) {
    case TRANSFER_IDENTITY:
        retval = _avs_http_body_receiver_dumb_create(buffer);
        break;

    case TRANSFER_LENGTH:
        retval = _avs_http_body_receiver_content_length_create(buffer,
                                                               content_length);
        break;

    case TRANSFER_CHUNKED:
        retval = _avs_http_body_receiver_chunked_create(buffer, buffer_sizes);
        break;
    }

create_body_receiver_return:
    if (!retval) {
        LOG(ERROR, _("could not create body receiver"));
        avs_stream_net_setsock(buffer, NULL); /* don't close the socket */
        avs_stream_cleanup(&buffer);
    }
    return retval;
}

int _avs_http_body_receiver_init(http_stream_t *stream,
                                 http_transfer_encoding_t transfer_encoding,
                                 avs_http_content_encoding_t content_encoding,
                                 size_t content_length) {
    avs_stream_t *decoder = NULL;
    int result = 0;
    LOG(TRACE,
        _("http_init_body_receiver, transfer_encoding == ") "%d" _(", ")
                _("content_encoding == ") "%d" _(
                        ", content_length == ") "%lu" _(", HTTP status == ") "%"
                                                                             "d",
        (int) transfer_encoding, (int) content_encoding,
        (unsigned long) content_length, stream->status);

    if (stream->body_receiver) {
        LOG(ERROR, _("body receiver already present"));
        return -1;
    }

    if (transfer_encoding == TRANSFER_IDENTITY
            && (stream->status == 204 || stream->status == 205)) {
        transfer_encoding = TRANSFER_LENGTH;
        content_length = 0;
    }

    if (transfer_encoding == TRANSFER_IDENTITY) {
        /* no content length, so end of content indicated by connection close */
        stream->flags.keep_connection = 0;
    }

    if (!(stream->body_receiver = create_body_receiver(
                  stream->backend, &stream->http->buffer_sizes,
                  transfer_encoding, content_length))) {
        return -1;
    }

    result = _avs_http_content_decoder_create(&decoder, content_encoding,
                                              &stream->http->buffer_sizes);
    if (!result && decoder) {
        avs_stream_t *filter_stream =
                _avs_http_decoding_stream_create(stream->body_receiver, decoder,
                                                 &stream->http->buffer_sizes);
        if (filter_stream) {
            stream->body_receiver = filter_stream;
        } else {
            avs_stream_cleanup(&decoder);
            result = -1;
        }
    }
    if (result) {
        avs_stream_cleanup(&stream->body_receiver);
    }
    return result;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/http/test_body_receivers.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_HTTP
