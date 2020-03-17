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

#ifndef AVS_COMMONS_HTTP_TEST_HTTP_H
#define AVS_COMMONS_HTTP_TEST_HTTP_H

#include <avsystem/commons/avs_net.h>

typedef struct expected_socket_struct {
    avs_net_socket_t *socket;
    avs_net_socket_type_t type;
} expected_socket_t;

extern expected_socket_t *avs_http_test_SOCKETS_TO_CREATE;

avs_error_t avs_net_tcp_socket_create_TEST_WRAPPER(avs_net_socket_t **socket,
                                                   ...);

avs_error_t avs_net_ssl_socket_create_TEST_WRAPPER(avs_net_socket_t **socket,
                                                   ...);

void avs_http_test_expect_create_socket(avs_net_socket_t *socket,
                                        avs_net_socket_type_t type);

static inline avs_error_t send_line_result(avs_stream_t *stream,
                                           const char **ptr) {
    const char *end = strchr(*ptr, '\n');
    if (end) {
        ++end; /* past the newline */
    } else {
        end = *ptr + strlen(*ptr);
    }
    avs_error_t err = avs_stream_write(stream, *ptr, (size_t) (end - *ptr));
    *ptr = end;
    return err;
}

static inline void send_line(avs_stream_t *stream, const char **ptr) {
    AVS_UNIT_ASSERT_SUCCESS(send_line_result(stream, ptr));
}

extern const char *const MONTY_PYTHON_RAW;
extern const char *const MONTY_PYTHON_PER_LINE_REQUEST;
extern const char *const MONTY_PYTHON_BIG_REQUEST;

#endif /* AVS_COMMONS_HTTP_TEST_HTTP_H */
