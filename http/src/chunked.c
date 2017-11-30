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

#include <avs_commons_config.h>

#include <string.h>

#include <avsystem/commons/utils.h>

#include "chunked.h"
#include "headers.h"
#include "http_log.h"
#include "http_stream.h"

VISIBILITY_SOURCE_BEGIN

#warning "TODO: If we fail with EPIPE, we need to ensure that avs_http_should_retry() == true"
static int http_send_single_chunk(http_stream_t *stream,
                                  const void *buffer,
                                  size_t buffer_length) {
    char size_buf[UINT_STR_BUF_SIZE(unsigned long)];
    int result;
    LOG(TRACE, "http_send_single_chunk, buffer_length == %lu",
        (unsigned long) buffer_length);
    result = (avs_simple_snprintf(size_buf, sizeof(size_buf), "%lX\r\n",
                                  (unsigned long) buffer_length) < 0
            || avs_stream_write(stream->backend, size_buf, strlen(size_buf))
            || avs_stream_write(stream->backend, buffer, buffer_length)
            || avs_stream_write(stream->backend, "\r\n", 2)
            || avs_stream_finish_message(stream->backend)) ? -1 : 0;
    LOG(TRACE, "result == %d", result);
    return result;
}

int _avs_http_chunked_send_first(http_stream_t *stream,
                                 const void *data,
                                 size_t data_length) {
    int result;
    LOG(TRACE, "http_chunked_send_first");
    stream->flags.chunked_sending = 1;
    stream->auth.state.flags.retried = 0;
    do {
#warning "TODO: In case sending returns EPIPE, reconnect and retry, but not indefinitely"
        result = (_avs_http_prepare_for_sending(stream)
                || _avs_http_send_headers(stream, (size_t) -1)
#warning "TODO: In case we receive unexpected EOF, reconnect and retry, but not indefinitely"
                || (!stream->flags.no_expect
                        && _avs_http_receive_headers(stream)
                        && stream->status / 100 != 1)
#warning "TODO: In case sending returns EPIPE, reconnect and retry, but not indefinitely"
                || _avs_http_chunked_send(stream, 0, data, data_length))
                ? -1 : 0;
    } while (result && stream->flags.should_retry);
    if (result == 0) {
        AVS_LIST_CLEAR(&stream->user_headers);
    }
    LOG(TRACE, "result == %d", result);
    return result;
}

int _avs_http_chunked_send(http_stream_t *stream,
                           char message_finished,
                           const void *data,
                           size_t data_length) {
    int result = 0;
    if (data_length) {
        result = http_send_single_chunk(stream, data, data_length);
    }
    if (!result && message_finished) {
        result = http_send_single_chunk(stream, NULL, 0);
        if (!result) {
            stream->flags.chunked_sending = 0;
            result = _avs_http_receive_headers(stream);
        }
    }
    return result;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_chunked.c"
#endif
