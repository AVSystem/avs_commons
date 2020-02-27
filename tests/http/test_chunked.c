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

#include <avsystem/commons/avs_stream_netbuf.h>
#include <avsystem/commons/avs_unit_mocksock.h>
#include <avsystem/commons/avs_unit_test.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#define EMPTY_HTTP_STREAM_INITIALIZER \
    { 0 }

AVS_UNIT_TEST(http, send_chunk) {
    const char *input_buffer = "poppipoppipoppoppipou\r\n"
                               "We are vegetarian.\r\n";
    const char *expected_output = "2B\r\n"
                                  "poppipoppipoppoppipou\r\n"
                                  "We are vegetarian.\r\n"
                                  "\r\n";
    avs_net_socket_t *socket = NULL;
    http_stream_t stream = EMPTY_HTTP_STREAM_INITIALIZER;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "cv", "02");
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "cv", "02"));
    avs_unit_mocksock_expect_output(socket, expected_output,
                                    strlen(expected_output));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_netbuf_create(&stream.backend, socket, 0, 0));
    AVS_UNIT_ASSERT_SUCCESS(http_send_single_chunk(&stream, input_buffer,
                                                   strlen(input_buffer)));
    avs_net_socket_close(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream.backend));

    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "CV", "zero-two");
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "CV", "zero-two"));
    avs_unit_mocksock_expect_output(socket, "0\r\n\r\n", 5);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_netbuf_create(&stream.backend, socket, 0, 0));
    AVS_UNIT_ASSERT_SUCCESS(http_send_single_chunk(&stream, NULL, 0));
    avs_net_socket_close(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream.backend));
}

#pragma GCC diagnostic pop
