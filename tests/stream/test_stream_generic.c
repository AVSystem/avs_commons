/*
 * Copyright 2020 AVSystem <avsystem@avsystem.com>
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

static const size_t STREAM_BUFFER_SIZE = 32;
static const size_t STREAM_SIZE = 64;

/* 256 bytes with null-byte */
static const char TEST_DATA[] =
        "Bacon ipsum dolor amet buffalo burgdoggen pancetta salami tenderloin, "
        "cupim kevin ham chicken. Beef ribs hamburger venison, pig swine "
        "kielbasa tri-tip buffalo. Porchetta andouille flank, picanha boudin "
        "swine brisket shank bresaola pastrami sirloin lambada";

/* For the file stream */
int mkstemp(char *filename_template);
const char FILENAME_TEMPLATE[] = "/tmp/test_stream_file-XXXXXX";

/* Example data holding structure */
typedef struct {
    char *data;
    size_t curr_offset;
} stream_ctx_t;

/**
 * Example writer implementation, writing as much data as possible and never
 * failing.
 */
static int writer(void *context_, const void *buffer, size_t *inout_size) {
    stream_ctx_t *context = (stream_ctx_t *) context_;
    size_t curr_offset = context->curr_offset;

    size_t bytes_to_write = AVS_MIN(*inout_size, STREAM_SIZE - curr_offset);
    memcpy(context->data + curr_offset, buffer, bytes_to_write);
    context->curr_offset += bytes_to_write;
    *inout_size = bytes_to_write;
    return 0;
}

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

static void write_some_unequally_splitted_data(avs_stream_t *stream) {
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

AVS_UNIT_TEST(stream_generic, write_some_unequally_splitted_data) {
    test_output_streams(write_some_unequally_splitted_data);
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
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, 29);

    // Test if the second write also works
    bytes_to_write = 27;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, 27);

    // Test if an empty write also works
    bytes_to_write = 0;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, 0);
}

AVS_UNIT_TEST(stream_generic, write) {
    test_output_streams(write_test);
}

// Tests two consecutive formatted writes
// As we cannot reach the data when we dont know
// Which type of stream we test it only checks
// If there is no failure
static void write_f_test(avs_stream_t *stream) {
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_f(stream, "Alice has %d teeth", 17));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_f(stream, "The cat has %d tail", 1));
}

AVS_UNIT_TEST(stream_generic, write_f) {
    test_output_streams(write_f_test);
}
