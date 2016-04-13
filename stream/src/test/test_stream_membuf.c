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

