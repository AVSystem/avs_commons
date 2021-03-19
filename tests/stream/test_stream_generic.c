/*
 * Copyright 2021 AVSystem <avsystem@avsystem.com>
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

#include <unistd.h>

#include <avsystem/commons/avs_unit_test.h>

/* Underlying stream implementations used for tests */
#include <avsystem/commons/avs_stream_buffered.h>
#include <avsystem/commons/avs_stream_file.h>
#include <avsystem/commons/avs_stream_membuf.h>
#include <avsystem/commons/avs_stream_simple_io.h>

#include "test_stream_common.h"

/* For the file stream */
int mkstemp(char *filename_template);
const char FILENAME_TEMPLATE[] = "/tmp/test_stream_file-XXXXXX";

/**
 * Output streams
 */

typedef void _avs_test_stream_func(avs_stream_t *stream);

static avs_stream_t **setup_output_streams(stream_ctx_t ***ctx,
                                           size_t *stream_num) {
    AVS_UNIT_ASSERT_NOT_NULL(ctx);
#ifdef AVS_COMMONS_STREAM_WITH_FILE
    *stream_num = 4;
#else // AVS_COMMONS_STREAM_WITH_FILE
    *stream_num = 3;
#endif

    avs_stream_t **streams = (avs_stream_t **) avs_malloc(
            (*stream_num) * sizeof(avs_stream_t *));
    (*ctx) = (stream_ctx_t **) avs_malloc((*stream_num)
                                          * sizeof(stream_ctx_t *));

    // Add buffered output stream
    (*ctx)[0] = (stream_ctx_t *) avs_malloc(sizeof(stream_ctx_t));
    streams[0] = avs_stream_simple_output_create(writer, (*ctx)[0]);
    AVS_UNIT_ASSERT_NOT_NULL(streams[0]);
    (*ctx)[0]->data = (char *) avs_calloc(STREAM_SIZE, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL((*ctx)[0]->data);
    (*ctx)[0]->curr_offset = 0;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_buffered_create(&(streams[0]), 0, STREAM_BUFFER_SIZE));

    // Add simple output stream
    (*ctx)[1] = (stream_ctx_t *) avs_malloc(sizeof(stream_ctx_t));
    streams[1] = avs_stream_simple_output_create(writer, (*ctx)[1]);
    AVS_UNIT_ASSERT_NOT_NULL(streams[1]);
    (*ctx)[1]->data = (char *) avs_calloc(STREAM_SIZE, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL((*ctx)[1]->data);
    (*ctx)[1]->curr_offset = 0;

    // Add membuf stream
    streams[2] = avs_stream_membuf_create();
    (*ctx)[2] = NULL;

#ifdef AVS_COMMONS_STREAM_WITH_FILE
    // Add filestream
    char *path = (char *) avs_malloc(sizeof(FILENAME_TEMPLATE));
    memcpy(path, FILENAME_TEMPLATE, sizeof(FILENAME_TEMPLATE));
    mkstemp(path);
    streams[3] = avs_stream_file_create(path, AVS_STREAM_FILE_WRITE);
    unlink(path);
    avs_free(path);
    (*ctx)[3] = NULL;
#endif // AVS_COMMONS_STREAM_WITH_FILE

    return streams;
}

static void cleanup_output_streams(avs_stream_t **streams,
                                   stream_ctx_t **ctx,
                                   size_t stream_num) {

    for (size_t stream_ptr = 0; stream_ptr < stream_num; stream_ptr++) {
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&(streams[stream_ptr])));

        if (ctx[stream_ptr] != NULL) {
            avs_free(ctx[stream_ptr]->data);
            avs_free(ctx[stream_ptr]);
        }
    }

    avs_free(ctx);
    avs_free(streams);
}

static void test_output_streams(_avs_test_stream_func test_f) {
    size_t stream_num;
    stream_ctx_t **ctx;
    avs_stream_t **streams = setup_output_streams(&ctx, &stream_num);
    for (size_t stream_ptr = 0; stream_ptr < stream_num; stream_ptr++) {
        test_f(streams[stream_ptr]);
    }
    cleanup_output_streams(streams, ctx, stream_num);
}

static void write_some_less_than_memory_size(avs_stream_t *stream) {
    size_t bytes_to_write = STREAM_SIZE - 1;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_SIZE - 1);
}

AVS_UNIT_TEST(stream_generic, write_some_less_than_memory_size) {
    test_output_streams(write_some_less_than_memory_size);
}

static void write_some_zero_bytes_test(avs_stream_t *stream) {
    size_t bytes_to_write = 0;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, 0);
}

AVS_UNIT_TEST(stream_generic, write_some_zero_bytes) {
    test_output_streams(write_some_zero_bytes_test);
}

static void write_some_equal_to_memory_size(avs_stream_t *stream) {
    size_t bytes_to_write = STREAM_SIZE;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_SIZE);
}

AVS_UNIT_TEST(stream_generic, write_some_equal_to_memory_size) {
    test_output_streams(write_some_equal_to_memory_size);
}

static void write_some_unequally_split_data(avs_stream_t *stream) {
    const size_t first_part = 19;
    const size_t second_part = 41;

    size_t bytes_to_write = first_part;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, first_part);

    bytes_to_write = second_part;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, second_part);
}

AVS_UNIT_TEST(stream_generic, write_some_unequally_split_data) {
    test_output_streams(write_some_unequally_split_data);
}

static void finalize_message_test(avs_stream_t *stream) {
    size_t amount_of_data = 37;
    size_t bytes_to_write = amount_of_data;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, amount_of_data);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
}

AVS_UNIT_TEST(stream_generic, finalize_message) {
    test_output_streams(finalize_message_test);
}

static void write_test(avs_stream_t *stream) {
    size_t bytes_to_write = 29;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write(stream, TEST_DATA, bytes_to_write));

    // Test if the second write also works
    bytes_to_write = 27;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write(stream, TEST_DATA, bytes_to_write));

    // Test if an empty write also works
    bytes_to_write = 0;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write(stream, TEST_DATA, bytes_to_write));
}

AVS_UNIT_TEST(stream_generic, write) {
    test_output_streams(write_test);
}

/**
 * Tests two consecutive formatted writes
 * As we cannot reach the data when we dont know
 * Which type of stream we test it only checks
 * If there is no failure
 */
static void write_f_test(avs_stream_t *stream) {
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_f(stream, "Alice has %d teeth", 17));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_f(stream, "The cat has %d tail", 1));
}

AVS_UNIT_TEST(stream_generic, write_f) {
    test_output_streams(write_f_test);
}

/**
 * Input streams
 */

static avs_stream_t **setup_input_streams(stream_ctx_t ***ctx,
                                          size_t *stream_num) {
    AVS_UNIT_ASSERT_NOT_NULL(ctx);
#ifdef AVS_COMMONS_STREAM_WITH_FILE
    *stream_num = 4;
#else // AVS_COMMONS_STREAM_WITH_FILE
    *stream_num = 3;
#endif

    avs_stream_t **streams = (avs_stream_t **) avs_malloc(
            (*stream_num) * sizeof(avs_stream_t *));
    (*ctx) = (stream_ctx_t **) avs_malloc((*stream_num)
                                          * sizeof(stream_ctx_t *));

    // Add buffered input stream
    (*ctx)[0] = (stream_ctx_t *) avs_malloc(sizeof(stream_ctx_t));
    streams[0] = avs_stream_simple_input_create(reader, (*ctx)[0]);
    AVS_UNIT_ASSERT_NOT_NULL(streams[0]);
    (*ctx)[0]->data = (char *) avs_malloc(STREAM_SIZE);
    AVS_UNIT_ASSERT_NOT_NULL((*ctx)[0]->data);
    memcpy((*ctx)[0]->data, TEST_DATA, STREAM_SIZE);
    (*ctx)[0]->curr_offset = 0;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_buffered_create(&(streams[0]), 0, STREAM_BUFFER_SIZE));

    // Add simple output stream
    (*ctx)[1] = (stream_ctx_t *) avs_malloc(sizeof(stream_ctx_t));
    streams[1] = avs_stream_simple_input_create(reader, (*ctx)[1]);
    AVS_UNIT_ASSERT_NOT_NULL(streams[1]);
    (*ctx)[1]->data = (char *) avs_malloc(STREAM_SIZE);
    AVS_UNIT_ASSERT_NOT_NULL((*ctx)[1]->data);
    memcpy((*ctx)[1]->data, TEST_DATA, STREAM_SIZE);
    (*ctx)[1]->curr_offset = 0;

    // Add membuf stream
    streams[2] = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write(streams[2], TEST_DATA, STREAM_SIZE));
    (*ctx)[2] = NULL;

#ifdef AVS_COMMONS_STREAM_WITH_FILE
    // Add filestream
    char *path = (char *) avs_malloc(sizeof(FILENAME_TEMPLATE));
    memcpy(path, FILENAME_TEMPLATE, sizeof(FILENAME_TEMPLATE));
    mkstemp(path);
    FILE *f = fopen(path, "w");
    AVS_UNIT_ASSERT_NOT_NULL(f);
    AVS_UNIT_ASSERT_EQUAL(fwrite(TEST_DATA, STREAM_SIZE, 1, f), 1);
    AVS_UNIT_ASSERT_SUCCESS(fclose(f));
    streams[3] = avs_stream_file_create(path, AVS_STREAM_FILE_READ);
    unlink(path);
    avs_free(path);
    (*ctx)[3] = NULL;
#endif // AVS_COMMONS_STREAM_WITH_FILE

    return streams;
}

static void cleanup_input_streams(avs_stream_t **streams,
                                  stream_ctx_t **ctx,
                                  size_t stream_num) {

    for (size_t stream_ptr = 0; stream_ptr < stream_num; stream_ptr++) {
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&(streams[stream_ptr])));

        if (ctx[stream_ptr] != NULL) {
            avs_free(ctx[stream_ptr]->data);
            avs_free(ctx[stream_ptr]);
        }
    }

    avs_free(ctx);
    avs_free(streams);
}

static void test_input_streams(_avs_test_stream_func test_f) {
    size_t stream_num;
    stream_ctx_t **ctx;
    avs_stream_t **streams = setup_input_streams(&ctx, &stream_num);
    for (size_t stream_ptr = 0; stream_ptr < stream_num; stream_ptr++) {
        test_f(streams[stream_ptr]);
    }
    cleanup_input_streams(streams, ctx, stream_num);
}

static void read_some_less_than_memory_size(avs_stream_t *stream) {
    char buffer[STREAM_SIZE];
    size_t bytes_to_read = STREAM_SIZE - 1;
    size_t bytes_read = 0;
    bool message_finished = false;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));

    AVS_UNIT_ASSERT_EQUAL(bytes_read, STREAM_SIZE - 1);
    AVS_UNIT_ASSERT_EQUAL(strncmp(buffer, TEST_DATA, bytes_to_read), 0);
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
}

AVS_UNIT_TEST(stream_generic, read_some_less_than_memory_size) {
    test_input_streams(read_some_less_than_memory_size);
}

static void read_some_zero_bytes_test(avs_stream_t *stream) {
    char buffer[STREAM_SIZE];
    size_t bytes_to_read = 0;
    size_t bytes_read = 1;
    bool message_finished = false;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 0);
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
}

AVS_UNIT_TEST(stream_generic, read_some_zero_bytes) {
    test_input_streams(read_some_zero_bytes_test);
}

static void read_some_equal_to_memory_size(avs_stream_t *stream) {
    char buffer[STREAM_SIZE];
    size_t bytes_to_read = STREAM_SIZE;
    size_t bytes_read = 1;
    bool message_finished = false;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, STREAM_SIZE);
    AVS_UNIT_ASSERT_EQUAL(strncmp(buffer, TEST_DATA, bytes_to_read), 0);
}

AVS_UNIT_TEST(stream_generic, read_some_equal_to_memory_size) {
    test_input_streams(read_some_equal_to_memory_size);
}

static void read_some_greater_than_memory_size(avs_stream_t *stream) {
    char buffer[STREAM_SIZE + 1];
    size_t bytes_to_read = STREAM_SIZE + 1;
    size_t bytes_read = 1;
    bool message_finished = false;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));

    AVS_UNIT_ASSERT_EQUAL(bytes_read, STREAM_SIZE);
    AVS_UNIT_ASSERT_EQUAL(message_finished, true);
    AVS_UNIT_ASSERT_EQUAL(strncmp(buffer, TEST_DATA, bytes_read), 0);
}

AVS_UNIT_TEST(stream_generic, read_some_greater_than_memory_size) {
    test_input_streams(read_some_greater_than_memory_size);
}

static void multiple_reads_test(avs_stream_t *stream) {
    char buffer[STREAM_SIZE + 1];
    bool message_finished = false;
    size_t bytes_read;

    size_t already_read_bytes = 0;
    size_t bytes_to_read = 29;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, bytes_to_read);
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(
            strncmp(buffer, TEST_DATA + already_read_bytes, bytes_to_read), 0);
    already_read_bytes += bytes_to_read;

    // Test if the second write also works
    bytes_to_read = 27;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, bytes_to_read);
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(
            strncmp(buffer, TEST_DATA + already_read_bytes, bytes_to_read), 0);
    already_read_bytes += bytes_to_read;

    // Test if an empty write also works
    bytes_to_read = 0;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, bytes_to_read);
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(
            strncmp(buffer, TEST_DATA + already_read_bytes, bytes_to_read), 0);
    already_read_bytes += bytes_to_read;

    // And a read after an empty read
    bytes_to_read = 19;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, bytes_to_read);
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(
            strncmp(buffer, TEST_DATA + already_read_bytes, bytes_to_read), 0);
}

AVS_UNIT_TEST(stream_generic, multiple_reads) {
    test_input_streams(multiple_reads_test);
}

static void read_reliably_success_test(avs_stream_t *stream) {
    char buffer[STREAM_SIZE];
    size_t bytes_to_read = STREAM_SIZE;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(strncmp(buffer, TEST_DATA, bytes_to_read), 0);
}

AVS_UNIT_TEST(stream_generic, read_reliably_success) {
    test_input_streams(read_reliably_success_test);
}

static void read_reliably_fail_test(avs_stream_t *stream) {
    char buffer[STREAM_SIZE];
    size_t bytes_to_read = STREAM_SIZE + 1;
    AVS_UNIT_ASSERT_FAILED(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));
}

AVS_UNIT_TEST(stream_generic, read_reliably_fail) {
    test_input_streams(read_reliably_fail_test);
}

static void read_reliably_multiple_test(avs_stream_t *stream) {
    char buffer[STREAM_SIZE];
    size_t bytes_to_read = STREAM_SIZE / 2;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(strncmp(buffer, TEST_DATA, bytes_to_read), 0);

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(
            strncmp(buffer, TEST_DATA + bytes_to_read, bytes_to_read), 0);

    // And now we'll read too much
    AVS_UNIT_ASSERT_FAILED(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));
}

AVS_UNIT_TEST(stream_generic, read_reliably_multiple) {
    test_input_streams(read_reliably_multiple_test);
}

static void ignore_to_end_test(avs_stream_t *stream) {
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_ignore_to_end(stream));

    char buffer[STREAM_SIZE];
    size_t bytes_read;
    size_t bytes_to_read = 7;
    bool message_finished;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, 0);
    AVS_UNIT_ASSERT_EQUAL(message_finished, true);
}

AVS_UNIT_TEST(stream_generic, ignore_to_end) {
    test_input_streams(ignore_to_end_test);
}

static void getch_test(avs_stream_t *stream) {
    char c;
    bool message_finished;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getch(stream, &c, &message_finished));
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(c, TEST_DATA[0]);

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getch(stream, &c, &message_finished));
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(c, TEST_DATA[1]);

    char buffer[STREAM_SIZE];
    size_t bytes_read;
    size_t offset = 19;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, offset));

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getch(stream, &c, &message_finished));
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(c, TEST_DATA[offset + 2]);

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getch(stream, &c, &message_finished));
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(c, TEST_DATA[offset + 3]);

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_ignore_to_end(stream));

    AVS_UNIT_ASSERT_FAILED(avs_stream_getch(stream, &c, &message_finished));
    AVS_UNIT_ASSERT_EQUAL(message_finished, true);
}

AVS_UNIT_TEST(stream_generic, getch) {
    test_input_streams(getch_test);
}

static void getline_test(avs_stream_t *stream) {
    size_t bytes_read;
    bool message_finished;
    const size_t buffer_size = 256;
    char buffer[buffer_size];

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(
            stream, &bytes_read, &message_finished, buffer, buffer_size));
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(bytes_read, sizeof(FIRST_LINE) - 1);
    AVS_UNIT_ASSERT_EQUAL(strcmp(buffer, FIRST_LINE), 0);

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(
            stream, &bytes_read, &message_finished, buffer, buffer_size));
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(bytes_read, sizeof(SECOND_LINE) - 1);
    AVS_UNIT_ASSERT_EQUAL(strcmp(buffer, SECOND_LINE), 0);

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(
            stream, &bytes_read, &message_finished, buffer, buffer_size));
    AVS_UNIT_ASSERT_EQUAL(message_finished, false);
    AVS_UNIT_ASSERT_EQUAL(bytes_read, sizeof(THIRD_LINE) - 1);
    AVS_UNIT_ASSERT_EQUAL(strcmp(buffer, THIRD_LINE), 0);

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(
            stream, &bytes_read, &message_finished, buffer, buffer_size));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, sizeof(FOURTH_LINE) - 1);
    AVS_UNIT_ASSERT_EQUAL(strcmp(buffer, FOURTH_LINE), 0);

    AVS_UNIT_ASSERT_FAILED(avs_stream_getline(
            stream, &bytes_read, &message_finished, buffer, buffer_size));
}

AVS_UNIT_TEST(stream_generic, getline) {
    test_input_streams(getline_test);
}

static void getline_errors_test(avs_stream_t *stream) {
    size_t bytes_read;
    bool message_finished;

    const size_t buffer_size = 256;
    char buffer[buffer_size];

    const size_t short_buffer_size = 64;
    char short_buffer[short_buffer_size];

    // Buffer too short
    AVS_UNIT_ASSERT_FAILED(avs_stream_getline(stream,
                                              &bytes_read,
                                              &message_finished,
                                              short_buffer,
                                              short_buffer_size));

    // NULL buffer
    AVS_UNIT_ASSERT_FAILED(avs_stream_getline(
            stream, &bytes_read, &message_finished, NULL, buffer_size));

    // Buffer size = 0
    AVS_UNIT_ASSERT_FAILED(avs_stream_getline(
            stream, &bytes_read, &message_finished, buffer, 0));

    // Stream end
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_ignore_to_end(stream));
    AVS_UNIT_ASSERT_FAILED(avs_stream_getline(stream,
                                              &bytes_read,
                                              &message_finished,
                                              short_buffer,
                                              short_buffer_size));
}

AVS_UNIT_TEST(stream_generic, getline_errors) {
    test_input_streams(getline_errors_test);
}

//
// Input + output
//

AVS_UNIT_TEST(stream_generic, copy_stream) {
    size_t istream_num;
    stream_ctx_t **ictx;
    avs_stream_t **istreams = setup_input_streams(&ictx, &istream_num);

    size_t ostream_num;
    stream_ctx_t **octx;
    avs_stream_t **ostreams = setup_output_streams(&octx, &ostream_num);

    size_t itr_num = istream_num < ostream_num ? istream_num : ostream_num;
    for (size_t stream_ptr = 0; stream_ptr < itr_num; stream_ptr++) {
        AVS_UNIT_ASSERT_SUCCESS(
                avs_stream_copy(ostreams[stream_ptr], istreams[stream_ptr]));
    }

    cleanup_output_streams(istreams, ictx, istream_num);
    cleanup_output_streams(ostreams, octx, ostream_num);
}
