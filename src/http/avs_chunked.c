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

#    include <string.h>

#    include <avsystem/commons/avs_utils.h>

#    include "avs_chunked.h"
#    include "avs_headers.h"
#    include "avs_http_stream.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

static avs_error_t http_send_single_chunk(http_stream_t *stream,
                                          const void *buffer,
                                          size_t buffer_length) {
    char size_buf[sizeof(unsigned long) * 2 + 3];
    avs_error_t err;
    LOG(TRACE, _("http_send_single_chunk, buffer_length == ") "%lu",
        (unsigned long) buffer_length);
    if (avs_simple_snprintf(size_buf, sizeof(size_buf), "%lX\r\n",
                            (unsigned long) buffer_length)
            < 0) {
        AVS_UNREACHABLE();
    }
    (void) (avs_is_err((err = avs_stream_write(stream->backend, size_buf,
                                               strlen(size_buf))))
            || avs_is_err((err = avs_stream_write(stream->backend, buffer,
                                                  buffer_length)))
            || avs_is_err((err = avs_stream_write(stream->backend, "\r\n", 2)))
            || avs_is_err((err = avs_stream_finish_message(stream->backend))));
    _avs_http_maybe_schedule_retry_after_send(stream, err);
    return err;
}

avs_error_t _avs_http_chunked_send_first(http_stream_t *stream,
                                         const void *data,
                                         size_t data_length) {
    avs_error_t err;
    LOG(TRACE, _("http_chunked_send_first"));
    stream->flags.chunked_sending = 1;
    stream->auth.state.flags.retried = 0;
    do {
        if (avs_is_err((err = _avs_http_prepare_for_sending(stream)))
                || avs_is_err((err = _avs_http_send_headers(stream,
                                                            (size_t) -1)))) {
            _avs_http_maybe_schedule_retry_after_send(stream, err);
        } else if (stream->flags.no_expect
                   || avs_is_ok((err = _avs_http_receive_headers(stream)))
                   || stream->status / 100 == 1) {
            err = _avs_http_chunked_send(stream, 0, data, data_length);
        }
    } while (avs_is_err(err) && stream->flags.should_retry);
    if (avs_is_ok(err)) {
        AVS_LIST_CLEAR(&stream->user_headers);
    }
    return err;
}

avs_error_t _avs_http_chunked_send(http_stream_t *stream,
                                   bool message_finished,
                                   const void *data,
                                   size_t data_length) {
    avs_error_t err = AVS_OK;
    if (data_length) {
        err = http_send_single_chunk(stream, data, data_length);
    }
    if (avs_is_ok(err) && message_finished) {
        err = http_send_single_chunk(stream, NULL, 0);
        if (avs_is_ok(err)) {
            stream->flags.chunked_sending = 0;
            err = _avs_http_receive_headers(stream);
        }
    }
    return err;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/http/test_chunked.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_HTTP
