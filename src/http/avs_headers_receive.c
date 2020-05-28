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

#    include <assert.h>
#    include <ctype.h>
#    include <errno.h>
#    include <inttypes.h>
#    include <string.h>

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_body_receivers.h"
#    include "avs_client.h"
#    include "avs_headers.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    http_stream_t *stream;
    AVS_LIST(const avs_http_header_t) *header_storage_end_ptr;
    http_transfer_encoding_t transfer_encoding;
    avs_http_content_encoding_t content_encoding;
    size_t content_length;
    avs_url_t *redirect_url;
    size_t header_buf_size;
    char header_buf[];
} header_parser_state_t;

static int parse_size(size_t *out, const char *in) {
    char *endptr = NULL;
    while (*in && isspace((unsigned char) *in)) {
        ++in;
    }
    if (!(isdigit((unsigned char) *in) || *in == '+')) {
        return -1;
    }
    errno = 0;
    unsigned long long tmp = strtoull(in, &endptr, 0);
    if (errno || !endptr || *endptr || tmp > SIZE_MAX) {
        return -1;
    }
    *out = (size_t) tmp;
    return 0;
}

static int http_handle_header(const char *key,
                              const char *value,
                              header_parser_state_t *state,
                              bool *out_header_handled) {
    *out_header_handled = true;
    if (avs_strcasecmp(key, "WWW-Authenticate") == 0) {
        _avs_http_auth_setup(&state->stream->auth, value);
    } else if (avs_strcasecmp(key, "Set-Cookie") == 0) {
        if (_avs_http_set_cookie(state->stream->http, false, value) < 0) {
            return -1;
        }
    } else if (avs_strcasecmp(key, "Set-Cookie2") == 0) {
        if (_avs_http_set_cookie(state->stream->http, true, value) < 0) {
            return -1;
        }
    } else if (avs_strcasecmp(key, "Content-Length") == 0) {
        if (state->transfer_encoding != TRANSFER_IDENTITY
                || parse_size(&state->content_length, value)) {
            return -1;
        }
        state->transfer_encoding = TRANSFER_LENGTH;
    } else if (avs_strcasecmp(key, "Transfer-Encoding") == 0) {
        if (avs_strcasecmp(value, "identity")
                != 0) { /* see RFC 2616, sec. 4.4 */
            if (state->transfer_encoding != TRANSFER_IDENTITY) {
                return -1;
            }
            state->transfer_encoding = TRANSFER_CHUNKED;
        }
    } else if (avs_strcasecmp(key, "Content-Encoding") == 0) {
        if (avs_strcasecmp(value, "identity") != 0) {
            if (state->content_encoding != AVS_HTTP_CONTENT_IDENTITY) {
                return -1;
            }
            if (avs_strcasecmp(value, "gzip") == 0
                    || avs_strcasecmp(value, "x-gzip") == 0) {
                state->content_encoding = AVS_HTTP_CONTENT_GZIP;
            } else if (avs_strcasecmp(value, "deflate") == 0) {
                state->content_encoding = AVS_HTTP_CONTENT_DEFLATE;
            }
        }
    } else if (avs_strcasecmp(key, "Connection") == 0) {
        if (avs_strcasecmp(value, "close") == 0) {
            state->stream->flags.keep_connection = 0;
        }
    } else if (state->stream->status / 100 == 3
               && avs_strcasecmp(key, "Location") == 0) {
        avs_url_free(state->redirect_url);
        state->redirect_url = avs_url_parse(value);
    } else {
        *out_header_handled = false;
        LOG(DEBUG, _("Unhandled HTTP header: ") "%s" _(": ") "%s", key, value);
    }
    return 0;
}

static avs_error_t discard_line(avs_stream_t *stream) {
    char c;

    do {
        avs_error_t err = avs_stream_getch(stream, &c, NULL);
        if (avs_is_err(err)) {
            return err;
        }
    } while (c != '\n');

    return AVS_OK;
}

static avs_error_t get_http_header_line(avs_stream_t *stream,
                                        char *line_buf,
                                        size_t line_buf_size) {
    avs_error_t err;

    while (avs_is_err((err = avs_stream_getline(stream, NULL, NULL, line_buf,
                                                line_buf_size)))) {
        if (err.category == AVS_ERRNO_CATEGORY && err.code == AVS_ENOBUFS) {
            LOG(WARNING, _("HTTP header too long to handle: ") "%s", line_buf);
            if (avs_is_err((err = discard_line(stream)))) {
                LOG(ERROR,
                    _("Could not discard header line (category == ") "%" PRIu16
                            _(", code == ") "%" PRIu16 _(")"),
                    err.category, err.code);
                return err;
            }
        } else {
            LOG(ERROR,
                _("Could not read header line (category == ") "%" PRIu16 _(
                        ", code == ") "%" PRIu16 _(")"),
                err.category, err.code);
            return err;
        }
    }

    return AVS_OK;
}

static const char *http_header_split(char *line) {
    char *value = strchr(line, ':');
    if (value && *value) {
        *value++ = '\0';
        while (*value && isspace((unsigned char) *value)) {
            *value++ = '\0';
        }
    }
    return value;
}

static avs_error_t http_receive_headers_internal(header_parser_state_t *state) {
    while (true) {
        const char *value = NULL;
        avs_error_t err =
                get_http_header_line(state->stream->backend, state->header_buf,
                                     state->header_buf_size);
        if (avs_is_err(err)) {
            LOG(ERROR, _("Error receiving headers"));
            return err;
        }

        if (state->header_buf[0] == '\0') { /* empty line */
            return AVS_OK;
        }
        LOG(TRACE, _("HTTP header: ") "%s", state->header_buf);
        bool header_handled;
        if (!(value = http_header_split(state->header_buf))
                || http_handle_header(state->header_buf, value, state,
                                      &header_handled)) {
            LOG(ERROR, _("Error parsing or handling headers"));
            return avs_errno(AVS_EPROTO);
        }

        if (state->header_storage_end_ptr) {
            assert(!*state->header_storage_end_ptr);
            size_t key_len = strlen(state->header_buf);
            size_t value_len = strlen(value);
            avs_http_header_t *element =
                    (avs_http_header_t *) AVS_LIST_NEW_BUFFER(
                            sizeof(avs_http_header_t) + key_len + value_len
                            + 2);
            if (!element) {
                LOG(ERROR, _("Could not store received header"));
                return avs_errno(AVS_ENOMEM);
            }
            element->key = (char *) element + sizeof(avs_http_header_t);
            memcpy((char *) (intptr_t) element->key, state->header_buf,
                   key_len + 1);
            element->value = element->key + key_len + 1;
            memcpy((char *) (intptr_t) element->value, value, value_len + 1);
            element->handled = header_handled;
            *state->header_storage_end_ptr = element;
            AVS_LIST_ADVANCE_PTR(&state->header_storage_end_ptr);
        }
    }
}

static avs_error_t
http_receive_headline_and_headers(header_parser_state_t *state) {
    state->header_buf[0] = '\0';
    state->stream->flags.keep_connection = 1;
    state->stream->status = 0;
    /* read parse headline */
    size_t bytes_read;
    bool message_finished;
    avs_error_t err = avs_stream_getline(state->stream->backend, &bytes_read,
                                         &message_finished, state->header_buf,
                                         state->header_buf_size);
    if (avs_is_err(err)) {
        LOG(ERROR, _("Could not receive HTTP headline"));
        if (bytes_read == 0 && message_finished
                && state->stream->flags.close_handling_required) {
            // end-of-stream: likely a Reset from previous connection
            // issue a fake redirect so that the stream reconnects
            state->stream->status = 399;
        } else {
            /* default to 100 Continue if nothing received */
            state->stream->status = 100;
        }
        goto http_receive_headers_error;
    }
    state->stream->flags.close_handling_required = 0;
    if (sscanf(state->header_buf, "HTTP/%*s %d", &state->stream->status) != 1) {
        /* discard HTTP version
         * some weird servers return HTTP/1.0 to HTTP/1.1 */
        LOG(ERROR, _("Bad HTTP headline: ") "%s", state->header_buf);
        err = avs_errno(AVS_EPROTO);
        goto http_receive_headers_error;
    }
    LOG(TRACE, _("Received HTTP headline, status == ") "%d",
        state->stream->status);
    if (avs_is_err((err = http_receive_headers_internal(state)))) {
        goto http_receive_headers_error;
    }

    switch (state->stream->status / 100) {
    case 1: // 100 Continue - ignore and treat as success
        break;

    case 2: // 2xx - success
        state->stream->auth.state.flags.retried = 0;
        if (_avs_http_body_receiver_init(
                    state->stream, state->transfer_encoding,
                    state->content_encoding, state->content_length)) {
            err = avs_errno(AVS_EIO);
            goto http_receive_headers_error;
        }
        state->stream->redirect_count = 0;
        break;

    case 3: // 3xx - redirect
        state->stream->auth.state.flags.retried = 0;
        if (!state->redirect_url) {
            err = avs_errno(AVS_EINVAL);
        } else if (avs_is_ok((err = _avs_http_redirect(
                                      state->stream, &state->redirect_url)))) {
            /* redirect was a success;
             * still, receiving headers for _this particular_ response
             * didn't result in a success (i.e. a usable input stream),
             * so this function returns failure - without clearing the
             * keep connection flag, as we have already made the new
             * connection */
            return avs_errno(AVS_EPROTO);
        }
        goto http_receive_headers_error;

    default: // most likely 5xx - server error
        state->stream->auth.state.flags.retried = 0;
        // fall-through
    case 4: // 4xx - client error
        if (_avs_http_body_receiver_init(
                    state->stream, state->transfer_encoding,
                    state->content_encoding, state->content_length)) {
            err = avs_errno(AVS_EPROTO);
            goto http_receive_headers_error;
        }
        /* we MUST NOT close connection, as required by TR-069,
         * so we actually receive and discard the response */
        LOG(WARNING, _("http_receive_headers: error response"));
        if (avs_is_err((err = avs_stream_ignore_to_end(
                                state->stream->body_receiver)))) {
            LOG(WARNING, _("http_receive_headers: response read error"));
            state->stream->flags.keep_connection = 0;
        } else {
            err = (avs_error_t) {
                .category = AVS_HTTP_ERROR_CATEGORY,
                .code = (uint16_t) state->stream->status
            };
            state->stream->flags.close_handling_required = 1;
        }
        LOG(TRACE, _("http_receive_headers: clearing body receiver"));
        avs_stream_cleanup(&state->stream->body_receiver);
        return err; /* without clearing the keep connection flag */
    }

    LOG(TRACE, _("http_receive_headers: success"));
    return AVS_OK;

http_receive_headers_error:
    LOG(ERROR, _("http_receive_headers: failure"));
    state->stream->flags.keep_connection = 0;
    return err;
}

static void
update_flags_after_receiving_headers(http_stream_t *stream,
                                     avs_error_t receive_headers_err) {
    if (receive_headers_err.category == AVS_HTTP_ERROR_CATEGORY) {
        assert((uint16_t) stream->status == receive_headers_err.code);
        if (stream->status == 401
                && (stream->auth.credentials.user
                    || stream->auth.credentials.password)
                && stream->auth.state.flags.type != HTTP_AUTH_TYPE_NONE
                && !stream->auth.state.flags.retried) {
            /* retry authentication */
            stream->auth.state.flags.retried = 1;
            stream->flags.should_retry = 1;
        } else if (stream->status == 417 && !stream->flags.no_expect) {
            /* retry without Expect: 100-continue */
            stream->flags.no_expect = 1;
            stream->flags.should_retry = 1;
        }
    } else if (stream->status / 100 == 3) {
        // non-fatal redirect happened
        stream->flags.should_retry = 1;
    }
}

avs_error_t _avs_http_receive_headers(http_stream_t *stream) {
    avs_error_t err = AVS_OK;

    /* The only case where we don't want to ignore 100-Continue messages is
     * just after sending chunked message headers - in such case, we need to
     * return to the upper layer to prepare chunked message body. */
    bool skip_100_continue = !stream->flags.chunked_sending;

    LOG(TRACE, _("receiving headers, ") "%ssk" _("ipping 100 Continue"),
        skip_100_continue ? "" : "NOT ");

    if (stream->incoming_header_storage) {
        AVS_LIST_CLEAR(stream->incoming_header_storage);
    }

    header_parser_state_t *parser_state = (header_parser_state_t *) avs_malloc(
            offsetof(header_parser_state_t, header_buf)
            + stream->http->buffer_sizes.header_line);
    if (!parser_state) {
        LOG(ERROR, _("Out of memory"));
        stream->flags.keep_connection = 0;
        err = avs_errno(AVS_ENOMEM);
    }

    while (avs_is_ok(err)) {
        memset(parser_state, 0, sizeof(header_parser_state_t));
        parser_state->stream = stream;
        parser_state->header_storage_end_ptr =
                (AVS_LIST(const avs_http_header_t)
                         *) (stream->incoming_header_storage
                                     ? AVS_LIST_APPEND_PTR(
                                               stream->incoming_header_storage)
                                     : NULL);
        parser_state->header_buf_size = stream->http->buffer_sizes.header_line;
        err = http_receive_headline_and_headers(parser_state);
        avs_url_free(parser_state->redirect_url);
        if (!skip_100_continue || stream->status != 100) {
            break;
        }
    }

    avs_free(parser_state);
    if (avs_is_err(err) && stream->incoming_header_storage) {
        AVS_LIST_CLEAR(stream->incoming_header_storage);
    }

    update_flags_after_receiving_headers(stream, err);
    return err;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
