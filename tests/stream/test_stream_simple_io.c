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

#include <avsystem/commons/avs_unit_test.h>

/* Amount of memory in stream in bytes */
#define STREAM_SIZE 128

/* 256 bytes with null-byte */
static const char TEST_DATA[] =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum "
        "iaculis nec est a accumsan. Morbi eros augue, maximus id hendrerit ut,"
        " sodales a orci. Suspendisse cursus pulvinar arcu, et faucibus nulla "
        "tincidunt et. Nunc vehicula nunc vel ni cwiercz.";

AVS_STATIC_ASSERT(sizeof(TEST_DATA) > STREAM_SIZE, test_string_too_small);

/* Example data holding structure */
typedef struct {
    char *data;
    size_t curr_offset;
} stream_ctx_t;

/**
 * Example reader implementation, reading as much data as possible and never
 * failing.
 */
static int reader(void *context_, void *buffer, size_t *inout_size) {
    stream_ctx_t *context = (stream_ctx_t *) context_;
    size_t curr_offset = context->curr_offset;

    size_t bytes_to_read = AVS_MIN(STREAM_SIZE - curr_offset, *inout_size);
    memcpy(buffer, context->data + curr_offset, bytes_to_read);
    context->curr_offset += bytes_to_read;
    *inout_size = bytes_to_read;
    return 0;
}

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

static avs_stream_t *setup_output_stream(stream_ctx_t *ctx) {
    avs_stream_t *stream = avs_stream_simple_output_create(writer, ctx);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    if (ctx) {
        ctx->data = (char *) avs_calloc(STREAM_SIZE, sizeof(char));
        AVS_UNIT_ASSERT_NOT_NULL(ctx->data);
        ctx->curr_offset = 0;
    }
    return stream;
}

static avs_stream_t *setup_input_stream(stream_ctx_t *ctx) {
    avs_stream_t *stream = avs_stream_simple_input_create(reader, ctx);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    if (ctx) {
        ctx->data = (char *) avs_malloc(STREAM_SIZE);
        AVS_UNIT_ASSERT_NOT_NULL(ctx->data);
        memcpy(ctx->data, TEST_DATA, STREAM_SIZE);
        ctx->curr_offset = 0;
    }
    return stream;
}

static void teardown_stream(avs_stream_t **stream, stream_ctx_t *ctx) {
    if (ctx) {
        avs_free(ctx->data);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(stream));
}

AVS_UNIT_TEST(stream_simple_io, init) {
    avs_stream_t *stream;
    stream_ctx_t ctx;

    AVS_UNIT_ASSERT_NOT_NULL(
            (stream = avs_stream_simple_output_create(writer, &ctx)));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));

    AVS_UNIT_ASSERT_NOT_NULL(
            (stream = avs_stream_simple_input_create(reader, &ctx)));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
}

AVS_UNIT_TEST(stream_simple_io, write_some_equal_to_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = STREAM_SIZE;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_SIZE);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA, bytes_to_write);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_simple_io, write_some_less_than_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = STREAM_SIZE - 1;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_SIZE - 1);
    AVS_UNIT_ASSERT_EQUAL(strlen(ctx.data), bytes_to_write);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA, bytes_to_write);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_simple_io, try_write_some_more_than_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = STREAM_SIZE + 1;

    // This behavior depends on user-implemented writer(). In this case writer()
    // writes as much data as possible and returns 0.
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_SIZE);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA, STREAM_SIZE);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_simple_io, write_some_zero_bytes) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = 0;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, 0);
    AVS_UNIT_ASSERT_EQUAL(strlen(ctx.data), bytes_to_write);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_simple_io, try_write_more_than_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);

    AVS_UNIT_ASSERT_FAILED(
            avs_stream_write(stream, TEST_DATA, STREAM_SIZE + 1));

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_simple_io, read_zero_bytes) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = 0;
    char *buffer = NULL;
    size_t bytes_read = 0;
    bool message_finished = true;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, bytes_to_read);
    AVS_UNIT_ASSERT_FALSE(message_finished);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_simple_io, read_equal_to_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = STREAM_SIZE;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);
    size_t bytes_read = 0;
    bool message_finished = true;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, bytes_to_read);
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, TEST_DATA, bytes_to_read);

    teardown_stream(&stream, &ctx);
    avs_free(buffer);
}

AVS_UNIT_TEST(stream_simple_io, read_less_than_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = STREAM_SIZE - 1;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);
    size_t bytes_read = 0;
    bool message_finished = true;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, bytes_to_read);
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, ctx.data, bytes_read);

    teardown_stream(&stream, &ctx);
    avs_free(buffer);
}

AVS_UNIT_TEST(stream_simple_io, try_read_more_than_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = STREAM_SIZE + 1;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);
    size_t bytes_read = 0;
    bool message_finished = false;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL(bytes_read, STREAM_SIZE);
    AVS_UNIT_ASSERT_TRUE(message_finished);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, ctx.data, bytes_read);

    // Check if message_finished is properly cached inside stream.
    message_finished = false;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_read(stream, &bytes_read, &message_finished, NULL, 0));
    AVS_UNIT_ASSERT_TRUE(message_finished);

    teardown_stream(&stream, &ctx);
    avs_free(buffer);
}

AVS_UNIT_TEST(stream_simple_io, read_reliably_equal_to_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = STREAM_SIZE;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, ctx.data, bytes_to_read);

    teardown_stream(&stream, &ctx);
    avs_free(buffer);
}

AVS_UNIT_TEST(stream_simple_io, read_reliably_less_than_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    const size_t bytes_to_read = STREAM_SIZE - 1;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, ctx.data, bytes_to_read);

    teardown_stream(&stream, &ctx);
    avs_free(buffer);
}

AVS_UNIT_TEST(stream_simple_io, try_read_reliably_more_than_memory_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    const size_t bytes_to_read = STREAM_SIZE + 1;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);

    AVS_UNIT_ASSERT_FAILED(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));

    teardown_stream(&stream, &ctx);
    avs_free(buffer);
}

/**
 * Not implemented functions.
 */

AVS_UNIT_TEST(stream_simple_io, finish_message) {
    avs_stream_t *stream = setup_input_stream(NULL);

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));

    teardown_stream(&stream, NULL);
}

AVS_UNIT_TEST(stream_simple_io, reset) {
    avs_stream_t *stream = setup_input_stream(NULL);

    AVS_UNIT_ASSERT_FAILED(avs_stream_reset(stream));

    teardown_stream(&stream, NULL);
}
