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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <avsystem/commons/stream/stream_net.h>
#include <avsystem/commons/stream/netbuf.h>

#include "client.h"
#include "content_encoding.h"
#include "http_log.h"
#include "stream.h"

VISIBILITY_SOURCE_BEGIN

/**
 * Here is a simplified explanation of inner workings of this function.
 *
 * Data flow diagram:
 *
 * <pre>
 *            http_send --->  encoder?
 *                |     <--- (gzip/NULL)
 *                v
 * _avs_http_send_via_buffer
 *                |
 *                v
 *   http_send_simple_request or
 *   _avs_http_chunked_send
 *                |
 *                v
 *             backend
 *         (buffered proxy)
 *                |
 *                v
 *             (socket)
 * </pre>
 *
 * The data passed to @ref http_send first may be passed through the
 * @ref http_stream_t.encoder - which is responsible for handling the HTTP
 * <em>Content-Encoding</em>. If the encoding is trivial (identity), the
 * <c>encoder</c> is <c>NULL</c> and bypassed altogether. Otherwise (i.e. when
 * zlib-based compression is used), <c>encoder</c> is stream directly created
 * with @ref _avs_http_create_compressor . Its semantics are described in more
 * detail in the documentation of that function, but the basic idea is that it
 * is a stream that you can write uncompressed data to, which then makes
 * eqiuvalent compressed data available for reading.
 *
 * Compression is performed before any other stages, because it <em>needs</em>
 * to be done so - for example, if a pre-buffered request is being sent, the
 * <em>Content-Length</em> header refers to the length of the
 * <em>compressed</em> payload, so the compressed body needs to be buffered
 * before sending the headers.
 *
 * The next stage is @ref _avs_http_send_via_buffer, called either
 * directly from here, or through @ref _avs_http_encoder_flush - it
 * appends the data to @ref http_stream_t.out_buffer and - when it is full -
 * sends a chunk of data (using @ref http_stream_t.backend, which itself is a
 * small "shaping" buffered stream using the socket underneath). If the entire
 * (possibly compressed) content fits in the buffer, it sends (at the time of
 * @ref http_finish) a simple request using the <em>Content-Length</em> header.
 * Otherwise <em>Transfer-Encoding: chunked</em>, with a single chunk sent each
 * time adding more data to the buffer would cause its overrun.
 *
 * Note that this flow is <strong>not at all</strong> symmetrical to what is
 * performed by @ref http_receive - this stems from the fact that many decisions
 * that can be made early during receiving, need to be made late (lazily) during
 * sending - such as the decision whether to use plain or chunked
 * <em>Transfer-Encoding</em>.
 */
static int http_send_some(avs_stream_abstract_t *stream_,
                          const void *data,
                          size_t *inout_data_length) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (!stream->encoder) {
        return _avs_http_send_via_buffer(stream, data, *inout_data_length);
    }

    size_t data_sent = 0;
    while (*inout_data_length > data_sent) {
        size_t chunk_size = *inout_data_length - data_sent;
        stream->encoder_touched = true;
        if (avs_stream_write_some(stream->encoder,
                                  (const char *) data + data_sent,
                                  &chunk_size)
                || _avs_http_encoder_flush(stream)) {
            return -1;
        }
        data_sent += chunk_size;
        if (chunk_size == 0) {
            // could not write anything, aborting
            break;
        }
    }
    *inout_data_length = data_sent;
    return 0;
}

static int http_nonblock_write_ready(avs_stream_abstract_t *stream_,
                                     size_t *out_ready_capacity_bytes) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (!stream->encoder) {
        *out_ready_capacity_bytes =
                stream->http->buffer_sizes.body_send - stream->out_buffer_pos;
        return 0;
    } else {
        // This is somewhat innacurate
        return avs_stream_nonblock_write_ready(stream->encoder,
                                               out_ready_capacity_bytes);
    }
    return 0;
}

static int http_finish(avs_stream_abstract_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (stream->encoder && stream->encoder_touched) {
        if (avs_stream_finish_message(stream->encoder)
                || _avs_http_encoder_flush(stream)
                || avs_stream_reset(stream->encoder)) {
            return -1;
        }
        stream->encoder_touched = false;
    }
    return _avs_http_buffer_flush(stream, 1);
}

/**
 * Here is a simplified explanation of inner workings of this function.
 *
 * Data flow diagram:
 *
 * <pre>
 *              http_receive
 *                   ^
 *                   |
 *             body_receiver
 * (chunked/length/dumb + possibly gzip)
 *                   ^
 *                   |
 *                backend
 *            (buffered proxy)
 *                   ^
 *                   |
 *                (socket)
 * </pre>
 *
 * Until the response content is finished, this function just delegates to
 * @ref http_stream_t.body_receiver - which is a delegate/decorator stream that
 * wraps @ref http_stream_t.backend, which itself wraps the socket.
 *
 * The primary function fo @ref http_stream_t.body_receiver is to abstract away
 * the HTTP <em>Transfer-Encoding</em> (identity, i.e. "read until connection
 * closes", <em>Content-Length</em>, or <em>chunked</em>). However, if
 * non-trivial <em>Content-Encoding</em> (i.e. compression) is used, another
 * layer of decoration is added, which transparently decompresses the data on
 * the fly.
 *
 * See @ref _avs_http_body_receiver_init and its documentation for details
 * on how the <c>body_receiver</c> is created.
 *
 * Note that this flow is <strong>not at all</strong> symmetrical to what is
 * performed by @ref http_send - this stems from the fact that many decisions
 * that can be made early during receiving, need to be made late (lazily) during
 * sending - such as the decision whether to use plain or chunked
 * <em>Transfer-Encoding</em>.
 */
static int http_receive(avs_stream_abstract_t *stream_,
                        size_t *out_bytes_read,
                        char *out_message_finished,
                        void *buffer,
                        size_t buffer_length) {
    http_stream_t *stream = (http_stream_t *) stream_;
    char message_finished;
    int result;

    if (!out_message_finished) {
        out_message_finished = &message_finished;
    }
    if (!stream->body_receiver) {
        *out_message_finished = 1;
        return -1;
    }

    result = avs_stream_read(stream->body_receiver,
                             out_bytes_read,
                             out_message_finished,
                             buffer,
                             buffer_length);
    if (*out_message_finished) {
        LOG(TRACE, "http_receive: clearing body receiver");
        avs_stream_cleanup(&stream->body_receiver);
    }
    return result;
}

static int http_nonblock_read_ready(avs_stream_abstract_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (!stream->body_receiver) {
        return -1;
    }
    return avs_stream_nonblock_read_ready(stream->body_receiver);
}

static int http_peek(avs_stream_abstract_t *stream_, size_t offset) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (!stream->body_receiver) {
        return EOF;
    }
    return avs_stream_peek(stream->body_receiver, offset);
}

static int http_reset(avs_stream_abstract_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    int result;
    LOG(TRACE, "http_reset");
    bool keep_connection =
            (stream->flags.keep_connection && !stream->flags.chunked_sending);
    if (keep_connection && stream->body_receiver) {
        if (avs_stream_ignore_to_end(stream->body_receiver) < 0) {
            LOG(WARNING, "Could not discard current message");
            keep_connection = 0;
        }
    }
    memset(&stream->flags, 0, sizeof(stream->flags));
    if (keep_connection) {
        /* if we haven't sent some partial data, don't close connection */
        stream->flags.keep_connection = 1;
    }
    avs_stream_cleanup(&stream->body_receiver);
    stream->out_buffer_pos = 0;
    stream->status = 0;
    stream->error_code = 0;
    AVS_LIST_CLEAR(&stream->user_headers);
    stream->encoder_touched = false;
    result = avs_stream_reset(stream->backend);
    if (stream->encoder) {
        result = avs_stream_reset(stream->encoder) || result;
    }
    return result ? -1 : 0;
}

static int http_close(avs_stream_abstract_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    http_reset(stream_);
    LOG(TRACE, "http_close");
    avs_stream_cleanup(&stream->backend);
    avs_stream_cleanup(&stream->encoder);
    _avs_http_auth_clear(&stream->auth);
    avs_url_free(stream->url);
    return 0;
}

static int http_errno(avs_stream_abstract_t *stream_) {
    http_stream_t *stream = (http_stream_t *)stream_;

    if (stream->error_code) {
        return stream->error_code;
    }

    /* don't return 1xx, 2xx, 3xx status codes */
    if (stream->status < 100 || stream->status >= 400) {
        return stream->status;
    } else if (stream->body_receiver) {
        return avs_stream_errno(stream->body_receiver);
    } else {
        return avs_stream_errno(stream->backend);
    }
}

static int http_getsock(avs_stream_abstract_t *stream,
                        avs_net_abstract_socket_t **out_socket) {
    return (*out_socket =
            avs_stream_net_getsock(((http_stream_t *) stream)->backend))
            ? 0 : -1;
}

static int http_setsock(avs_stream_abstract_t *stream,
                        avs_net_abstract_socket_t *socket) {
    return avs_stream_net_setsock(((http_stream_t *) stream)->backend, socket);
}

static const avs_stream_v_table_t http_vtable = {
    http_send_some,
    http_finish,
    http_receive,
    http_peek,
    http_reset,
    http_close,
    http_errno,
    &(avs_stream_v_table_extension_t[]) {
        {
            AVS_STREAM_V_TABLE_EXTENSION_NET,
            &(avs_stream_v_table_extension_net_t[]) {
                {
                    http_getsock,
                    http_setsock
                }
            }[0]
        },
        {
            AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
            &(avs_stream_v_table_extension_nonblock_t[]) {
                {
                    http_nonblock_read_ready,
                    http_nonblock_write_ready
                }
            }[0]
        },
        AVS_STREAM_V_TABLE_EXTENSION_NULL
    }[0]
};

int avs_http_add_header(avs_stream_abstract_t *stream_,
                        const char *key, const char *value) {
    http_stream_t *stream = (http_stream_t *) stream_;
    assert(stream->vtable == &http_vtable);
    LOG(TRACE, "http_add_header, %s: %s", key, value);
    AVS_LIST(http_header_t) new_header =
            AVS_LIST_APPEND_NEW(http_header_t, &stream->user_headers);
    if (!new_header) {
        return -1;
    }
    new_header->key = key;
    new_header->value = value;
    return 0;
}

int avs_http_should_retry(avs_stream_abstract_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (stream->vtable != &http_vtable) {
        LOG(ERROR, "Invalid stream passed to avs_http_should_retry");
        return 0;
    }

    return (int) stream->flags.should_retry;
}

int avs_http_open_stream(avs_stream_abstract_t **out,
                         avs_http_t *http,
                         avs_http_method_t method,
                         avs_http_content_encoding_t encoding,
                         const avs_url_t *url,
                         const char *auth_username,
                         const char *auth_password) {
    assert(!*out);
    avs_net_abstract_socket_t *socket = NULL;
    http_stream_t *stream = NULL;
    int result = 0;
    LOG(TRACE, "avs_http_open_stream, method == %d, encoding == %d, "
               "protocol == %s, host == %s, port == %s, path == %s, "
               "auth_username == %s, auth_password == %s",
             (int) method, (int) encoding, url->protocol, url->host, url->port,
             url->path, auth_username, auth_password);

    stream = (http_stream_t *) calloc(
            1,
            offsetof(http_stream_t, out_buffer) + http->buffer_sizes.body_send);
    if (!stream) {
        LOG(ERROR, "Could not allocate HTTP stream object");
        result = ENOMEM;
        goto http_open_stream_error;
    }

    *(const avs_stream_v_table_t **) (intptr_t) &stream->vtable = &http_vtable;
    *(avs_http_t **) (intptr_t) &stream->http = http;
    *(avs_http_method_t *) (intptr_t) &stream->method = method;
    if (!(stream->url = avs_url_copy(url))) {
        result = ENOMEM;
        goto http_open_stream_error;
    }

    if (_avs_http_auth_setup_stream(stream, url,
                                    auth_username, auth_password)) {
        result = ENOMEM;
        goto http_open_stream_error;
    }
    stream->encoding = encoding;
    if (_avs_http_encoding_init(stream)) {
        result = ENOMEM;
        goto http_open_stream_error;
    }

    if ((result = _avs_http_socket_new(&socket, http, url))) {
        goto http_open_stream_error;
    }

    avs_stream_netbuf_create(&stream->backend, socket,
                             http->buffer_sizes.recv_shaper,
                             http->buffer_sizes.send_shaper);
    if (!stream->backend) {
        LOG(ERROR, "error creating buffered netstream");
        result = ENOMEM;
        goto http_open_stream_error;
    }
    stream->flags.keep_connection = 1;
    stream->random_seed = (unsigned) time(NULL);
    if ((stream->auth.credentials.user || stream->auth.credentials.password)
            && strcmp(avs_url_protocol(url), "https") == 0) {
        stream->auth.state.flags.type = HTTP_AUTH_TYPE_BASIC;
    }

    *out = (avs_stream_abstract_t *) stream;
    return 0;

http_open_stream_error:
    if (stream && stream->backend) {
        avs_stream_cleanup(&stream->backend);
    } else if (socket) {
        avs_net_socket_cleanup(&socket);
    }
    if (stream && stream->encoder) {
        avs_stream_cleanup(&stream->encoder);
    }
    if (stream && stream->url) {
        avs_url_free(stream->url);
    }
    if (stream) {
        _avs_http_auth_clear(&stream->auth);
        free(stream);
    }
    return result;
}

int avs_http_status_code(avs_stream_abstract_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (stream->vtable != &http_vtable) {
        LOG(ERROR, "Invalid stream passed to avs_http_status_code");
        return 0;
    }

    return stream->status;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_stream.c"
#endif
