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

#ifndef AVS_COMMONS_HTTP_STREAM_H
#define AVS_COMMONS_HTTP_STREAM_H

#include <avsystem/commons/avs_list.h>
#include <avsystem/commons/avs_stream.h>
#include <avsystem/commons/avs_stream_v_table.h>

#include "avs_auth.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef struct {
    /**
     * Set to true if in the sending state and using chunked encoding.
     */
    unsigned chunked_sending : 1;

    /**
     * Set to true if the TCP connection can safely be reused for another
     * request after finishing a response.
     *
     * True is the default. Will be set to false if one of the following:
     * - Response specifies neither Content-Length nor chunked encoding
     * - Connection: close header is received
     * - An error occurs while receiving the headers
     * - An error occurs while trying to ignore an error response body
     */
    unsigned keep_connection : 1;

    /**
     * Set to true after receiving 417 Expectation Failed. Expect: 100-continue
     * will not be sent even if using chunked encoding in such case.
     */
    unsigned no_expect : 1;

    /**
     * Set after receiving HTTP headers. Signifies whether a non-success
     * response can be automatically retried in a modified form that is likely
     * to work.
     */
    unsigned should_retry : 1;

    /**
     * Set after completing a request-response exchange. Cleared after
     * reconnecting or receiving any data from the server.
     *
     * After a completed request-response exchange, the server is free to close
     * the connection without any consequences; the client may be informed that
     * the connection has closed only at a later time. In that case, the request
     * needs to be retried.
     *
     * We need to consider two scenarios:
     *
     * A) After a completed exchange with the server, we try to issue another
     *    request on the same connection. During sending, a FIN packet arrives -
     *    in that case, we need to reconnect and try again.
     * B) After a completed exchange with the server, we issue another request
     *    and finish sending data to the server. Then, when we wait for the
     *    response, a FIN packet arrives - even though it was sent after the
     *    previous exchange, likely due to long round-trip time. Then again, we
     *    need to reconnect and try again.
     *
     * Scenario A is handled by the _avs_http_maybe_schedule_retry_after_send()
     * function. Scenario B - in http_receive_headers_internal() and
     * update_flags_after_receiving_headers() (an intermediate "fake" 399 status
     * code is used as a form of communication between the two functions).
     *
     * We also need to consider three cases:
     *
     * 1. The request is small enough to fit into a single bufer; chunked
     *    encoding is not used.
     * 2. Chunked encoding is used. The FIN packet arrives before we finish
     *    sending the first chunk.
     * 3. Chunked encoding is used. The server does not send a "100 Continue"
     *    intermediate response, and due to long round-trip time, the FIN packet
     *    arrives during processing of some later (not the first) chunk.
     *
     * Case 1 is handled in the http_send_simple_request() function. Case 2 in
     * _avs_http_chunked_send_first() and in http_send_simple_chunk().
     * http_send_simple_chunk() also handles case 3 - note that in this case, we
     * are not able to automatically retry the request, as it needs to be
     * rebuilt from the beginning. The error thus gets propagated to the user,
     * who can check avs_http_should_retry() and retry the request manually.
     */
    unsigned close_handling_required : 1;
} http_flags_t;

typedef struct {
    const char *key;
    const char *value;
} http_header_t;

struct http_stream_struct {
    const avs_stream_v_table_t *const vtable;
    avs_http_t *const http;
    const avs_http_method_t method;
    avs_url_t *url;

    /**
     * A netbuf stream that encapsulates a TCP socket and is used for almost-raw
     * communication.
     *
     * Uses small buffer sizes (<c>http->buffer_sizes->{recv,send}_shaper</c>,
     * 128 bytes by default) to avoid sending millions of packets of just few
     * bytes while sending headers, and switching to kernel mode for each tiny
     * read while receiving them.
     */
    avs_stream_t *backend;

    avs_http_content_encoding_t encoding;

    /**
     * An encoder stream (not a decorator - see @ref _avs_http_create_compressor
     * for details) used as an intermediate stage when compression (HTTP
     * <em>Content-Encoding</em>) is being used for sending of the request body.
     *
     * Note that it has <strong>NO</strong> relation to HTTP
     * <em>Transfer-Encoding</em> (e.g. <em>chunked</em>). It is
     * <strong>NOT</strong> symmetrical to @ref http_stream_t.body_receiver, see
     * also @ref http_send and @ref http_receive for details.
     */
    avs_stream_t *encoder;
    /**
     * Set to true if any write was performed to the <c>encoder</c>.
     *
     * If set to false, flushing the encoder will be skipped on
     * <c>avs_stream_finish_message()</c>. This optimizes sending of empty
     * requests and prevents sending unwanted header data that the encoder may
     * append even for empty content.
     */
    bool encoder_touched;

    http_flags_t flags;

    http_auth_t auth;
    /**
     * Number of redirections performed since last time a successful (2xx) reply
     * was received. A redirection attempt will first increment the
     * <c>redirect_count</c>. If the incremented value is greater than
     * <c>HTTP_MOVE_LIMIT</c> (5, as mandated by TR-069).
     */
    int redirect_count;

    /**
     * Last received HTTP status code.
     */
    int status;

    AVS_LIST(http_header_t) user_headers;
    AVS_LIST(const avs_http_header_t) *incoming_header_storage;

    unsigned random_seed;

    /**
     * A proxy stream for receiving response body. Will be non-NULL if, and only
     * if, the HTTP stream is in the receiving state.
     *
     * The body receiver may limit the number of bytes to receive based on
     * <em>Content-Length</em>, decode chunked encoding, and may optionally be
     * wrapped in a decompressing decorator if a compressed response body is
     * being received.
     *
     * This object's primary function is to handle the HTTP
     * <em>Transfer-Encoding</em> (e.g. <em>chunked</em>) and delegate it out of
     * the view. It <em>also</em> transparently handles any non-trivial
     * <em>Content-Encoding</em> (i.e. compression), if applicable. It is
     * <strong>NOT</strong> symmetrical to @ref http_stream_t.encoder, see also
     * @ref http_send and @ref http_receive in for details.
     */
    avs_stream_t *body_receiver;
    size_t out_buffer_pos;
    char out_buffer[];
};

typedef struct http_stream_struct http_stream_t;

avs_error_t _avs_http_socket_new(avs_net_socket_t **out,
                                 avs_http_t *client,
                                 const avs_url_t *url);

avs_error_t _avs_http_redirect(http_stream_t *stream, avs_url_t **url_move);

avs_error_t _avs_http_prepare_for_sending(http_stream_t *stream);

void _avs_http_maybe_schedule_retry_after_send(http_stream_t *stream,
                                               avs_error_t err);

avs_error_t _avs_http_buffer_flush(http_stream_t *stream,
                                   bool message_finished);

avs_error_t _avs_http_send_via_buffer(http_stream_t *stream,
                                      const void *data,
                                      size_t data_length);

avs_error_t _avs_http_encoder_flush(http_stream_t *stream);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_HTTP_STREAM_H */
