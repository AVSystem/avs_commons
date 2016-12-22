/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <avsystem/commons/unit/test.h>

AVS_UNIT_TEST(stream_membuf, write_read) {
    avs_stream_abstract_t *stream = avs_stream_membuf_create();
    static const char *str = "very stream";
    char buf[1024];
    size_t bytes_read;
    char message_finished;
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(stream, &bytes_read,
                                            &message_finished, buf, 1024));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 0);
    AVS_UNIT_ASSERT_EQUAL(message_finished, 1);

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(stream, str, strlen(str)+1));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(stream, &bytes_read,
                                            &message_finished, buf, 1024));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, strlen(str)+1);
    AVS_UNIT_ASSERT_EQUAL(message_finished, 1);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(stream, &bytes_read,
                                            &message_finished, buf, 1024));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 0);
    AVS_UNIT_ASSERT_EQUAL(message_finished, 1);
    AVS_UNIT_ASSERT_EQUAL_STRING(str, buf);
    avs_stream_cleanup(&stream);
}

AVS_UNIT_TEST(stream_membuf, peek) {
    avs_stream_abstract_t *stream = avs_stream_membuf_create();
    static const char *str = "very stream";
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_EQUAL(EOF, avs_stream_peek(stream, 9001));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(stream, str, strlen(str)+1));
    AVS_UNIT_ASSERT_EQUAL('v', avs_stream_peek(stream, 0));
    AVS_UNIT_ASSERT_EQUAL('m', avs_stream_peek(stream, strlen(str)-1));
    AVS_UNIT_ASSERT_EQUAL('\0', avs_stream_peek(stream, strlen(str)));
    avs_stream_cleanup(&stream);
}

AVS_UNIT_TEST(stream_membuf, reset) {
    avs_stream_abstract_t *stream = avs_stream_membuf_create();
    static const char *str = "very stream";
    char buf[1024] = { 0,0,0,0,0 };
    size_t bytes_read;
    char message_finished;
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(stream, str, strlen(str)+1));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(stream, &bytes_read,
                                            &message_finished, buf, 4));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 4);
    AVS_UNIT_ASSERT_EQUAL(message_finished, 0);
    AVS_UNIT_ASSERT_EQUAL_STRING("very", buf);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_reset(stream));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(stream, &bytes_read,
                                            &message_finished, buf, 4));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 0);
    AVS_UNIT_ASSERT_EQUAL(message_finished, 1);
    avs_stream_cleanup(&stream);
}

AVS_UNIT_TEST(stream_membuf, fit) {
    avs_stream_abstract_t *stream = avs_stream_membuf_create();
    avs_stream_membuf_t *internal = (avs_stream_membuf_t *) stream;
    static const char *str = "very stream";
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(stream, str, strlen(str)+1));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(stream, str, strlen(str)+1));
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_EQUAL(internal->buffer_size, 3 * (strlen(str) + 1));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_membuf_fit(stream));
    AVS_UNIT_ASSERT_EQUAL(internal->buffer_size, 2 * (strlen(str) + 1));
    avs_stream_cleanup(&stream);
}

AVS_UNIT_TEST(stream_getline, simple) {
    avs_stream_abstract_t *stream = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "HTTP/1.1 302 Found\r\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "Cache-Control: private\r\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "Content-Type: text/html; charset=UTF-8\r\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "Location: http://www.google.pl/?gfe_rd=cr&ei=sQlcWMSSJMSv8weajb2wAg\r\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "Content-Length: 79\r\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "Date: Thu, 22 Dec 2016 17:13:21 GMT\r\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "\r\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "</HEAD><BODY></BODY></HTML>"));

    char buf[80];
    char message_finished = 0;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "HTTP/1.1 302 Found");
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "Cache-Control: private");
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "Content-Type: text/html; charset=UTF-8");
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "Location: http://www.google.pl/?gfe_rd=cr&ei=sQlcWMSSJMSv8weajb2wAg");
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "Content-Length: 79");
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "Date: Thu, 22 Dec 2016 17:13:21 GMT");
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "");
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">");
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_EQUAL(avs_stream_getline(stream, NULL, &message_finished, buf, sizeof(buf)), -1);
    AVS_UNIT_ASSERT_EQUAL_STRING(buf, "</HEAD><BODY></BODY></HTML>");
    AVS_UNIT_ASSERT_TRUE(message_finished);
    avs_stream_cleanup(&stream);
}

AVS_UNIT_TEST(stream_getline, errors) {
    avs_stream_abstract_t *stream = avs_stream_membuf_create();
    static const char *str = "very stream";
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(stream, str, strlen(str)+1));

    char buf[32];
    size_t bytes_read;
    size_t next_offset;
    char msg_finished;

    buf[0] = -1;
    AVS_UNIT_ASSERT_FAILED(avs_stream_peekline(stream, 0, NULL, NULL, buf, 0));
    AVS_UNIT_ASSERT_FAILED(avs_stream_peekline(stream, 0, NULL, NULL, NULL, 0));
    AVS_UNIT_ASSERT_EQUAL(buf[0], -1);
    AVS_UNIT_ASSERT_EQUAL(1, avs_stream_peekline(stream, 0, &bytes_read,
                                                 &next_offset, buf, 1));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 0);
    AVS_UNIT_ASSERT_EQUAL(next_offset, 0);
    AVS_UNIT_ASSERT_EQUAL(buf[0], '\0');

    buf[0] = -1;
    AVS_UNIT_ASSERT_FAILED(avs_stream_getline(stream, NULL, NULL, buf, 0));
    AVS_UNIT_ASSERT_FAILED(avs_stream_getline(stream, NULL, NULL, NULL, 500));

    AVS_UNIT_ASSERT_EQUAL(buf[0], -1);
    AVS_UNIT_ASSERT_EQUAL(1, avs_stream_getline(stream, &bytes_read,
                                                &msg_finished, buf, 1));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 0);
    AVS_UNIT_ASSERT_EQUAL(buf[0], '\0');
    AVS_UNIT_ASSERT_EQUAL(msg_finished, 0);
    avs_stream_cleanup(&stream);
}

AVS_UNIT_TEST(stream_getline, exact) {
    avs_stream_abstract_t *stream = avs_stream_membuf_create();
    static const char *STREAM_DATA_LF = "1234567\n";
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(stream, STREAM_DATA_LF,
                                             strlen(STREAM_DATA_LF)));

    char buf[strlen(STREAM_DATA_LF)];
    size_t bytes_read;
    char msg_finished;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, &bytes_read,
                                               &msg_finished,
                                               buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 7);
    AVS_UNIT_ASSERT_TRUE(msg_finished);

    static const char *STREAM_DATA_CR_LF = "1234567\r\n";
    avs_stream_reset(stream);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(stream, STREAM_DATA_CR_LF,
                                             strlen(STREAM_DATA_CR_LF)));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, &bytes_read,
                                               &msg_finished,
                                               buf, sizeof(buf)));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 7);
    AVS_UNIT_ASSERT_TRUE(msg_finished);
    avs_stream_cleanup(&stream);
}
