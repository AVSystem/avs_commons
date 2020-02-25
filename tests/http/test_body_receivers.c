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

#include <string.h>

#include <avsystem/commons/avs_unit_mocksock.h>
#include <avsystem/commons/avs_unit_test.h>

typedef struct {
    const avs_stream_v_table_t *const vtable;
    avs_stream_t *backend;
} fake_receiver_t;

const char *DUMB_INPUT_DATA = "Kansaijin nara yappari okonomiyaki & gohan!";

AVS_UNIT_TEST(http, dumb_receiver_read) {
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "host", "port");
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "host", "port"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, DUMB_INPUT_DATA, strlen(DUMB_INPUT_DATA));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_IDENTITY, 0);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(
                avs_stream_read(receiver,
                                &bytes_read,
                                &message_finished,
                                buffer_ptr,
                                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(DUMB_INPUT_DATA));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, DUMB_INPUT_DATA);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

AVS_UNIT_TEST(http, dumb_receiver_peek) {
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    size_t i = 0;
    size_t content_length = strlen(DUMB_INPUT_DATA);
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "t_s_o_h", "t_r_o_p");
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(socket, "t_s_o_h", "t_r_o_p"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, DUMB_INPUT_DATA, strlen(DUMB_INPUT_DATA));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_IDENTITY, 0);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    for (i = 0; i < content_length; ++i) {
        char value;
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_peek(receiver, i, &value));
        AVS_UNIT_ASSERT_EQUAL(value, DUMB_INPUT_DATA[i]);
    }
    for (i = content_length; i < 2 * content_length; ++i) {
        AVS_UNIT_ASSERT_TRUE(
                avs_is_eof(avs_stream_peek(receiver, i, &(char) { 0 })));
    }
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(
                avs_stream_read(receiver,
                                &bytes_read,
                                &message_finished,
                                buffer_ptr,
                                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(DUMB_INPUT_DATA));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, DUMB_INPUT_DATA);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

const char *LENGTH_INPUT_DATA = "Aa, Kami-sama, onegai, futari dake no\n"
                                "DREAM TIME kudasai";

AVS_UNIT_TEST(http, content_length_receiver_good) {
    size_t content_length = strchr(LENGTH_INPUT_DATA, '\n') - LENGTH_INPUT_DATA;
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "H057", "P0R7");
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "H057", "P0R7"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, LENGTH_INPUT_DATA,
                            strlen(LENGTH_INPUT_DATA));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_LENGTH, content_length);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(
                avs_stream_read(receiver,
                                &bytes_read,
                                &message_finished,
                                buffer_ptr,
                                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, content_length);
    AVS_UNIT_ASSERT_SUCCESS(memcmp(LENGTH_INPUT_DATA, buffer, content_length));
    buffer_ptr = buffer;
    message_finished = 0;
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(
                avs_stream_read(((fake_receiver_t *) receiver)->backend,
                                &bytes_read, &message_finished, buffer_ptr,
                                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer,
                          strlen(LENGTH_INPUT_DATA) - content_length);
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, LENGTH_INPUT_DATA + content_length);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

AVS_UNIT_TEST(http, content_length_receiver_not_enough) {
    const char input_data[] = "Azu-nyan!";
    size_t content_length = sizeof(input_data) * 2;
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_error_t err = AVS_OK;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "tosh", "trop");
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "tosh", "trop"));
    avs_unit_mocksock_input(socket, input_data, strlen(input_data));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_LENGTH, content_length);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    while (!message_finished && avs_is_ok(err)) {
        size_t bytes_read;
        err = avs_stream_read(receiver, &bytes_read, &message_finished,
                              buffer_ptr,
                              sizeof(buffer) - (buffer_ptr - buffer));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_EIO);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

AVS_UNIT_TEST(http, content_length_receiver_peek) {
    size_t i;
    size_t content_length = strchr(LENGTH_INPUT_DATA, '\n') - LENGTH_INPUT_DATA;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "h_o_s_t", "p_o_r_t");
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(socket, "h_o_s_t", "p_o_r_t"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, LENGTH_INPUT_DATA,
                            strlen(LENGTH_INPUT_DATA));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_LENGTH, content_length);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    for (i = 0; i < content_length; ++i) {
        char value;
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_peek(receiver, i, &value));
        AVS_UNIT_ASSERT_EQUAL(value, LENGTH_INPUT_DATA[i]);
    }
    for (i = content_length; LENGTH_INPUT_DATA[i]; ++i) {
        AVS_UNIT_ASSERT_TRUE(
                avs_is_eof(avs_stream_peek(receiver, i, &(char) { 0 })));
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

const char *CHUNKED_DATA = "3\r\n"
                           "0\r\n\r\n"
                           "3\r\n"
                           "to \r\n"
                           "1\r\n"
                           "1\r\n"
                           "11\r\n"
                           "\nshika wakaranai\n\r\n"
                           "0\r\n"
                           "-- Trailer\r\n"
                           "-- headers\r\n"
                           "\r\n"
                           "watashi ni \"I\" o oshiete kureta";
const char *UNCHUNKED_DATA = "0\r\nto 1\n"
                             "shika wakaranai\n";
const char *POST_CHUNKED_DATA = "watashi ni \"I\" o oshiete kureta";

AVS_UNIT_TEST(http, chunked_receiver_good) {
    char buffer[64];
    char *buffer_ptr = buffer;
    size_t bytes_read;
    bool message_finished = false;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "h.o.s.t", "p.o.r.t");
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(socket, "h.o.s.t", "p.o.r.t"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, CHUNKED_DATA, strlen(CHUNKED_DATA));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_CHUNKED, 0);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    while (!message_finished) {
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
                receiver, &bytes_read, &message_finished, buffer_ptr,
                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(UNCHUNKED_DATA));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, UNCHUNKED_DATA);
    message_finished = 0;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            receiver, &bytes_read, &message_finished, buffer, sizeof(buffer)));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 0);
    AVS_UNIT_ASSERT_TRUE(message_finished);
    buffer_ptr = buffer;
    message_finished = 0;
    while (!message_finished) {
        AVS_UNIT_ASSERT_SUCCESS(
                avs_stream_read(((fake_receiver_t *) receiver)->backend,
                                &bytes_read, &message_finished, buffer_ptr,
                                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(POST_CHUNKED_DATA));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, POST_CHUNKED_DATA);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

AVS_UNIT_TEST(http, chunked_receiver_not_enough) {
    const char *not_enough_chunked_data = "8\r\n"
                                          "Sekai de\r\n"
                                          "1a\r\n"
                                          "Ichiban Ohime-sama";
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_error_t err = AVS_OK;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "H.O.S.T", "P.O.R.T");
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(socket, "H.O.S.T", "P.O.R.T"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, not_enough_chunked_data,
                            strlen(not_enough_chunked_data));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_CHUNKED, 0);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    while (!message_finished && avs_is_ok(err)) {
        size_t bytes_read;
        err = avs_stream_read(receiver, &bytes_read, &message_finished,
                              buffer_ptr,
                              sizeof(buffer) - (buffer_ptr - buffer));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_EIO);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

AVS_UNIT_TEST(http, chunked_receiver_error) {
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "T.S.O.H", "T.R.O.P");
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(socket, "T.S.O.H", "T.R.O.P"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, NULL, 0);
    avs_stream_t *receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_CHUNKED, 0);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    size_t bytes_received;
    bool message_finished;
    char buffer[256];
    avs_error_t err =
            avs_stream_read(receiver, &bytes_received, &message_finished,
                            buffer, sizeof(buffer));
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_EPROTO);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

AVS_UNIT_TEST(http, chunked_receiver_no_zero) {
    const char *no_zero_enough_chunked_data = "8\r\n"
                                              "Sekai de\r\n"
                                              "12\r\n"
                                              "Ichiban Ohime-sama\r\n";
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = 0;
    avs_error_t err = AVS_OK;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "H.o.s.t", "P.o.r.t");
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(socket, "H.o.s.t", "P.o.r.t"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, no_zero_enough_chunked_data,
                            strlen(no_zero_enough_chunked_data));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_CHUNKED, 0);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    while (avs_is_ok(err) && !message_finished) {
        size_t bytes_read;
        err = avs_stream_read(receiver, &bytes_read, &message_finished,
                              buffer_ptr,
                              sizeof(buffer) - (buffer_ptr - buffer));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_EPROTO);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}

AVS_UNIT_TEST(http, chunked_receiver_peek) {
    size_t i;
    avs_net_socket_t *socket = NULL;
    avs_stream_t *helper_stream = NULL;
    avs_stream_t *receiver = NULL;
    avs_unit_mocksock_create(&socket);
    avs_unit_mocksock_expect_connect(socket, "www.www.www", "80");
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(socket, "www.www.www", "80"));
    avs_stream_netbuf_create(&helper_stream, socket, 0, 0);
    AVS_UNIT_ASSERT_NOT_NULL(helper_stream);
    avs_unit_mocksock_input(socket, CHUNKED_DATA, strlen(CHUNKED_DATA));
    receiver =
            create_body_receiver(helper_stream, &AVS_HTTP_DEFAULT_BUFFER_SIZES,
                                 TRANSFER_CHUNKED, 0);
    AVS_UNIT_ASSERT_NOT_NULL(receiver);
    for (i = 0; UNCHUNKED_DATA[i]; ++i) {
        char value;
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_peek(receiver, i, &value));
        AVS_UNIT_ASSERT_EQUAL(value, UNCHUNKED_DATA[i]);
    }
    for (; i < 128; ++i) {
        AVS_UNIT_ASSERT_TRUE(
                avs_is_eof(avs_stream_peek(receiver, i, &(char) { 0 })));
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&receiver));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&helper_stream));
}
