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

#include <assert.h>
#include <string.h>

#include <avsystem/commons/errno.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/stream/netbuf.h>
#include <avsystem/commons/stream/stream_net.h>
#include <avsystem/commons/time.h>

#include "client.h"
#include "content_encoding.h"
#include "http_log.h"
#include "http_stream.h"

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
static avs_error_t http_send_some(avs_stream_t *stream_,
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
        avs_error_t err;
        if (avs_is_err((
                    err = avs_stream_write_some(stream->encoder,
                                                (const char *) data + data_sent,
                                                &chunk_size)))
                || avs_is_err((err = _avs_http_encoder_flush(stream)))) {
            return err;
        }
        data_sent += chunk_size;
        if (chunk_size == 0) {
            // could not write anything, aborting
            break;
        }
    }
    *inout_data_length = data_sent;
    return AVS_OK;
}

static size_t http_nonblock_write_ready(avs_stream_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (!stream->encoder) {
        return stream->http->buffer_sizes.body_send - stream->out_buffer_pos;
    } else {
        // This is somewhat innacurate
        return avs_stream_nonblock_write_ready(stream->encoder);
    }
}

static avs_error_t http_finish(avs_stream_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (stream->encoder && stream->encoder_touched) {
        avs_error_t err;
        if (avs_is_err((err = avs_stream_finish_message(stream->encoder)))
                || avs_is_err((err = _avs_http_encoder_flush(stream)))
                || avs_is_err((err = avs_stream_reset(stream->encoder)))) {
            return err;
        }
        stream->encoder_touched = false;
    }
    return _avs_http_buffer_flush(stream, true);
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
 * The primary function of @ref http_stream_t.body_receiver is to abstract away
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
static avs_error_t http_receive(avs_stream_t *stream_,
                                size_t *out_bytes_read,
                                bool *out_message_finished,
                                void *buffer,
                                size_t buffer_length) {
    http_stream_t *stream = (http_stream_t *) stream_;
    bool message_finished;
    avs_error_t err;

    if (!out_message_finished) {
        out_message_finished = &message_finished;
    }
    if (!stream->body_receiver) {
        *out_message_finished = 1;
        return avs_errno(AVS_EBADF);
    }

    err = avs_stream_read(stream->body_receiver, out_bytes_read,
                          out_message_finished, buffer, buffer_length);
    if (*out_message_finished) {
        LOG(TRACE, _("http_receive: clearing body receiver"));
        stream->flags.close_handling_required = 1;
        avs_stream_cleanup(&stream->body_receiver);
    }
    return err;
}

static bool http_nonblock_read_ready(avs_stream_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (!stream->body_receiver) {
        return false;
    }
    return avs_stream_nonblock_read_ready(stream->body_receiver);
}

static avs_error_t
http_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (!stream->body_receiver) {
        return AVS_EOF;
    }
    return avs_stream_peek(stream->body_receiver, offset, out_value);
}

static avs_error_t http_reset(avs_stream_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    LOG(TRACE, _("http_reset"));
    bool keep_connection =
            (stream->flags.keep_connection && !stream->flags.chunked_sending);
    bool close_handling_required = false;
    if (keep_connection && stream->body_receiver) {
        if (avs_is_err(avs_stream_ignore_to_end(stream->body_receiver))) {
            LOG(WARNING, _("Could not discard current message"));
            keep_connection = false;
        } else {
            close_handling_required = true;
        }
    }
    memset(&stream->flags, 0, sizeof(stream->flags));
    if (keep_connection) {
        /* if we haven't sent some partial data, don't close connection */
        stream->flags.keep_connection = 1;
    }
    if (close_handling_required) {
        stream->flags.close_handling_required = 1;
    }
    avs_stream_cleanup(&stream->body_receiver);
    stream->out_buffer_pos = 0;
    stream->status = 0;
    AVS_LIST_CLEAR(&stream->user_headers);
    stream->encoder_touched = false;
    avs_error_t backend_err = avs_stream_reset(stream->backend);
    if (stream->encoder) {
        avs_error_t encoder_err = avs_stream_reset(stream->encoder);
        return avs_is_ok(backend_err) ? encoder_err : backend_err;
    }
    return backend_err;
}

static avs_error_t http_close(avs_stream_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    stream->flags.keep_connection = false;
    avs_error_t reset_err = http_reset(stream_);
    LOG(TRACE, _("http_close"));
    avs_error_t backend_cleanup_err = avs_stream_cleanup(&stream->backend);
    avs_error_t encoder_cleanup_err = avs_stream_cleanup(&stream->encoder);
    if (avs_is_err(encoder_cleanup_err)) {
        LOG(ERROR, _("failed to close encoder stream"));
    }
    _avs_http_auth_clear(&stream->auth);
    avs_url_free(stream->url);

    if (avs_is_err(reset_err)) {
        return reset_err;
    } else if (avs_is_err(backend_cleanup_err)) {
        return backend_cleanup_err;
    } else {
        return encoder_cleanup_err;
    }
}

static avs_net_socket_t *http_getsock(avs_stream_t *stream) {
    return avs_stream_net_getsock(((http_stream_t *) stream)->backend);
}

static avs_error_t http_setsock(avs_stream_t *stream,
                                avs_net_socket_t *socket) {
    return avs_stream_net_setsock(((http_stream_t *) stream)->backend, socket);
}

static const avs_stream_v_table_t http_vtable = {
    http_send_some,
    http_finish,
    http_receive,
    http_peek,
    http_reset,
    http_close,
    &(avs_stream_v_table_extension_t[]){
            { AVS_STREAM_V_TABLE_EXTENSION_NET,
              &(avs_stream_v_table_extension_net_t[]){
                      { http_getsock, http_setsock } }[0] },
            { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
              &(avs_stream_v_table_extension_nonblock_t[]){
                      { http_nonblock_read_ready,
                        http_nonblock_write_ready } }[0] },
            AVS_STREAM_V_TABLE_EXTENSION_NULL }[0]
};

int avs_http_add_header(avs_stream_t *stream_,
                        const char *key,
                        const char *value) {
    http_stream_t *stream = (http_stream_t *) stream_;
    assert(stream->vtable == &http_vtable);
    LOG(TRACE, _("http_add_header, ") "%s" _(": ") "%s", key ? key : "(null)",
        value ? value : "(null)");
    AVS_LIST(http_header_t) new_header =
            (AVS_LIST(http_header_t)) AVS_LIST_APPEND_NEW(
                    http_header_t, &stream->user_headers);
    if (!new_header) {
        return -1;
    }
    new_header->key = key;
    new_header->value = value;
    return 0;
}

void avs_http_set_header_storage(
        avs_stream_t *stream_,
        AVS_LIST(const avs_http_header_t) *header_storage_ptr) {
    http_stream_t *stream = (http_stream_t *) stream_;
    assert(stream->vtable == &http_vtable);
    LOG(TRACE, _("http_set_header_storage: ") "%p",
        (void *) header_storage_ptr);
    if (stream->incoming_header_storage) {
        AVS_LIST_CLEAR(stream->incoming_header_storage);
    }
    stream->incoming_header_storage = header_storage_ptr;
}

int avs_http_should_retry(avs_stream_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (stream->vtable != &http_vtable) {
        LOG(ERROR, _("Invalid stream passed to avs_http_should_retry"));
        return 0;
    }

    return (int) stream->flags.should_retry;
}

static inline const char *string_or_null(const char *str) {
    return str ? str : "(null)";
}

avs_error_t avs_http_open_stream(avs_stream_t **out,
                                 avs_http_t *http,
                                 avs_http_method_t method,
                                 avs_http_content_encoding_t encoding,
                                 const avs_url_t *url,
                                 const char *auth_username,
                                 const char *auth_password) {
    assert(!*out);
    assert(url);
    avs_net_socket_t *socket = NULL;
    http_stream_t *stream = NULL;
    avs_error_t err = AVS_OK;
    LOG(TRACE,
        _("avs_http_open_stream, method == ") "%d" _(", encoding == ") "%d" _(
                ", ")
                _("protocol == ") "%s" _(", host == ") "%s" _(
                        ", port == ") "%s" _(", path == ") "%s" _(", ")
                        _("auth_username == ") "%s" _(
                                ", auth_password == ") "%s",
        (int) method, (int) encoding, string_or_null(avs_url_protocol(url)),
        string_or_null(avs_url_host(url)), string_or_null(avs_url_port(url)),
        string_or_null(avs_url_path(url)), auth_username ? auth_username : "",
        auth_password ? auth_password : "");

    stream = (http_stream_t *) avs_calloc(
            1,
            offsetof(http_stream_t, out_buffer) + http->buffer_sizes.body_send);
    if (!stream) {
        LOG(ERROR, _("Could not allocate HTTP stream object"));
        err = avs_errno(AVS_ENOMEM);
        goto http_open_stream_error;
    }

    *(const avs_stream_v_table_t **) (intptr_t) &stream->vtable = &http_vtable;
    *(avs_http_t **) (intptr_t) &stream->http = http;
    *(avs_http_method_t *) (intptr_t) &stream->method = method;
    if (!(stream->url = avs_url_copy(url))) {
        err = avs_errno(AVS_ENOMEM);
        goto http_open_stream_error;
    }

    if (_avs_http_auth_setup_stream(stream, url, auth_username,
                                    auth_password)) {
        err = avs_errno(AVS_ENOMEM);
        goto http_open_stream_error;
    }
    stream->encoding = encoding;
    if (_avs_http_encoding_init(stream)) {
        err = avs_errno(AVS_ENOMEM);
        goto http_open_stream_error;
    }

    if (avs_is_err((err = _avs_http_socket_new(&socket, http, url)))) {
        goto http_open_stream_error;
    }

    avs_stream_netbuf_create(&stream->backend, socket,
                             http->buffer_sizes.recv_shaper,
                             http->buffer_sizes.send_shaper);
    if (!stream->backend) {
        LOG(ERROR, _("error creating buffered netstream"));
        err = avs_errno(AVS_ENOMEM);
        goto http_open_stream_error;
    }
    stream->flags.keep_connection = 1;
    stream->random_seed =
            (unsigned) avs_time_real_now().since_real_epoch.seconds;
    if ((stream->auth.credentials.user || stream->auth.credentials.password)
            && strcmp(avs_url_protocol(url), "https") == 0) {
        stream->auth.state.flags.type = HTTP_AUTH_TYPE_BASIC;
    }

    *out = (avs_stream_t *) stream;
    return AVS_OK;

http_open_stream_error:
    assert(avs_is_err(err));

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
        avs_free(stream);
    }

    return err;
}

int avs_http_status_code(avs_stream_t *stream_) {
    http_stream_t *stream = (http_stream_t *) stream_;
    if (stream->vtable != &http_vtable) {
        LOG(ERROR, _("Invalid stream passed to avs_http_status_code"));
        return 0;
    }

    return stream->status;
}

#ifdef AVS_UNIT_TESTING
#    include "tests/http/test_stream.c"
#endif
