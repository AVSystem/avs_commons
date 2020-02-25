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

#include <string.h>

#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_http.h>
#include <avsystem/commons/avs_unit_mocksock.h>
#include <avsystem/commons/avs_unit_test.h>

#include "test_http.h"

static void successful_request(avs_http_t *client,
                               avs_net_socket_t **socket_ptr,
                               avs_stream_t **stream_ptr) {
    const char *tmp_data = NULL;
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_url_t *url = avs_url_parse("http://example.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    avs_unit_mocksock_create(socket_ptr);
    avs_http_test_expect_create_socket(*socket_ptr, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(*socket_ptr, "example.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(
            avs_http_open_stream(stream_ptr, client, AVS_HTTP_POST,
                                 AVS_HTTP_CONTENT_IDENTITY, url, NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(*stream_ptr);
    avs_unit_mocksock_assert_io_clean(*socket_ptr);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: example.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(*socket_ptr, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Content-Length: 5\r\n"
               "\r\n";
    avs_unit_mocksock_input(*socket_ptr, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(*stream_ptr));
    avs_unit_mocksock_assert_io_clean(*socket_ptr);
    tmp_data = "Hello";
    avs_unit_mocksock_input(*socket_ptr, tmp_data, strlen(tmp_data));
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
                *stream_ptr, &bytes_read, &message_finished, buffer_ptr,
                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(tmp_data));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, tmp_data);
    avs_unit_mocksock_assert_io_clean(*socket_ptr);
}

AVS_UNIT_TEST(http_close, chunked_request) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    successful_request(client, &socket, &stream);

    // second request
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EPIPE));
    avs_unit_mocksock_expect_mid_close(socket);
    avs_unit_mocksock_expect_connect(socket, "example.com", "80");
    // second request retry
    const char *tmp_data = "POST / HTTP/1.1\r\n"
                           "Host: example.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
                           "Accept-Encoding: gzip, deflate\r\n"
#endif
                           "Expect: 100-continue\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 100 Continue\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    /* The text used in this test is 5119 bytes long.
     * This is to test writing more than buffer size, which is 4096. */
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http_close, chunked_request_twice) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    successful_request(client, &socket, &stream);

    // second request
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EPIPE));
    avs_unit_mocksock_expect_mid_close(socket);
    avs_unit_mocksock_expect_connect(socket, "example.com", "80");
    // second request retry
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EPIPE));
    const char *tmp_data = MONTY_PYTHON_RAW;
    avs_error_t err = AVS_OK;
    while (avs_is_ok(err) && *tmp_data) {
        err = send_line_result(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_FAILED(err);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http_close, chunked_request_error_in_first_chunk) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    successful_request(client, &socket, &stream);

    // second request
    const char *tmp_data = "POST / HTTP/1.1\r\n"
                           "Host: example.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
                           "Accept-Encoding: gzip, deflate\r\n"
#endif
                           "Expect: 100-continue\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_input_fail(socket, avs_errno(AVS_ETIMEDOUT));
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EPIPE));
    avs_unit_mocksock_expect_mid_close(socket);
    avs_unit_mocksock_expect_connect(socket, "example.com", "80");
    // second request retry
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 100 Continue\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    /* The text used in this test is 5119 bytes long.
     * This is to test writing more than buffer size, which is 4096. */
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http_close, chunked_request_close_when_receiving) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    successful_request(client, &socket, &stream);

    // second request
    const char *tmp_data = "POST / HTTP/1.1\r\n"
                           "Host: example.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
                           "Accept-Encoding: gzip, deflate\r\n"
#endif
                           "Expect: 100-continue\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_input(socket, NULL, 0); // EOF
    avs_unit_mocksock_expect_mid_close(socket);
    avs_unit_mocksock_expect_connect(socket, "example.com", "80");
    // second request retry
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 100 Continue\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    /* The text used in this test is 5119 bytes long.
     * This is to test writing more than buffer size, which is 4096. */
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http_close, chunked_request_error_in_second_chunk) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    successful_request(client, &socket, &stream);

    // second request
    const char *tmp_data = "POST / HTTP/1.1\r\n"
                           "Host: example.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
                           "Accept-Encoding: gzip, deflate\r\n"
#endif
                           "Expect: 100-continue\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_input_fail(socket, avs_errno(AVS_ETIMEDOUT));
    /* The text used in this test is 5119 bytes long.
     * This is to test writing more than buffer size, which is 4096. */
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    // first chunk only
    avs_unit_mocksock_expect_output(socket, tmp_data,
                                    strstr(tmp_data, "\n\r\n") + 3 - tmp_data);
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EPIPE));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    AVS_UNIT_ASSERT_TRUE(avs_http_should_retry(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}
