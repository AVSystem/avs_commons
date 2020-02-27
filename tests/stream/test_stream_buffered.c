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

/* Underlying stream implementation used for tests */
#include <avsystem/commons/avs_stream_simple_io.h>

#define STREAM_BUFFER_SIZE 64
#define STREAM_SIZE 128

// Used for disabling writing in writer()
bool WRITER_WRITE_ZERO;

/* 256 bytes with null-byte */
static const char TEST_DATA[] =
        "Bacon ipsum dolor amet buffalo burgdoggen pancetta salami tenderloin, "
        "cupim kevin ham chicken. Beef ribs hamburger venison, pig swine "
        "kielbasa tri-tip buffalo. Porchetta andouille flank, picanha boudin "
        "swine brisket shank bresaola pastrami sirloin lambada";

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
    unsigned long curr_offset = context->curr_offset;

    uint16_t bytes_to_read =
            (uint16_t) AVS_MIN(STREAM_SIZE - curr_offset, *inout_size);
    if (bytes_to_read) {
        memcpy(buffer, context->data + curr_offset, bytes_to_read);
        context->curr_offset += bytes_to_read;
    }

    *inout_size = bytes_to_read;
    return 0;
}

/**
 * Example writer implementation, writing as much data as possible and never
 * failing.
 */
static int writer(void *context_, const void *buffer, size_t *inout_size) {
    stream_ctx_t *context = (stream_ctx_t *) context_;

    if (WRITER_WRITE_ZERO) {
        *inout_size = 0;
        return 0;
    }

    unsigned long curr_offset = context->curr_offset;

    uint16_t bytes_to_write =
            (uint16_t) AVS_MIN(STREAM_SIZE - curr_offset, *inout_size);

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
    WRITER_WRITE_ZERO = false;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_buffered_create(&stream, 0, STREAM_BUFFER_SIZE));
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

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_buffered_create(&stream, STREAM_BUFFER_SIZE, 0));
    return stream;
}

static void teardown_stream(avs_stream_t **stream, stream_ctx_t *ctx) {
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(stream));
    if (ctx) {
        avs_free(ctx->data);
    }
}

AVS_UNIT_TEST(stream_buffered, write_some_buffer_sized_bytes) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = STREAM_BUFFER_SIZE;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_BUFFER_SIZE);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA, bytes_to_write);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, writer_fail_then_success) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    WRITER_WRITE_ZERO = true;
    size_t bytes_to_write = STREAM_BUFFER_SIZE + 1;
    size_t total_written = 0;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_BUFFER_SIZE);
    AVS_UNIT_ASSERT_EQUAL(ctx.curr_offset, 0);
    total_written += bytes_to_write;

    WRITER_WRITE_ZERO = false;
    bytes_to_write = STREAM_BUFFER_SIZE;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_some(
            stream, TEST_DATA + total_written, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_BUFFER_SIZE);
    total_written += bytes_to_write;
    AVS_UNIT_ASSERT_EQUAL(ctx.curr_offset, total_written);

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA, total_written);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, write_some_less_than_buffer_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = STREAM_BUFFER_SIZE - 1;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));

    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_BUFFER_SIZE - 1);

    // Buffer is not completely filled, so nothing should be written yet...
    AVS_UNIT_ASSERT_EQUAL(strlen(ctx.data), 0);

    // ...and cleanup should write remaining data.
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));

    AVS_UNIT_ASSERT_EQUAL(strlen(ctx.data), bytes_to_write);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA, bytes_to_write);
    avs_free(ctx.data);
}

AVS_UNIT_TEST(stream_buffered, write_some_more_than_buffer_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = STREAM_BUFFER_SIZE + 1;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_BUFFER_SIZE + 1);

    // Not all bytes are written yet
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA, STREAM_BUFFER_SIZE);
    AVS_UNIT_ASSERT_EQUAL(ctx.curr_offset, STREAM_BUFFER_SIZE);

    // Buffer can be also flushed manually using avs_stream_finish_message()
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA, bytes_to_write);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, try_write_some_more_than_stream_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = STREAM_SIZE + 1;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));

    // Multiply of STREAM_BUFFER_SIZE bytes should be written
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(ctx.data, TEST_DATA,
                                      (bytes_to_write / STREAM_BUFFER_SIZE)
                                              * STREAM_BUFFER_SIZE);

    // Not enough space in stream
    AVS_UNIT_ASSERT_FAILED(avs_stream_cleanup(&stream));
    avs_free(ctx.data);
}

AVS_UNIT_TEST(stream_buffered, write_some_zero_bytes) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = 0;
    avs_stream_write_some(stream, TEST_DATA, &bytes_to_write);

    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, 0);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, try_write_more_than_stream_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write(stream, TEST_DATA, STREAM_SIZE + 1));

    AVS_UNIT_ASSERT_FAILED(avs_stream_cleanup(&stream));
    avs_free(ctx.data);
}

AVS_UNIT_TEST(stream_buffered, try_read_more_than_stream_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = STREAM_SIZE + 1;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);
    size_t bytes_read = 0;
    size_t total_read = 0;
    bool message_finished = false;

    while (!message_finished) {
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
                stream, &bytes_read, &message_finished, buffer + total_read,
                bytes_to_read - total_read));
        total_read += bytes_read;
    }

    AVS_UNIT_ASSERT_EQUAL(total_read, STREAM_SIZE);
    AVS_UNIT_ASSERT_TRUE(message_finished);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, TEST_DATA, STREAM_SIZE);

    avs_free(buffer);
    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, read_less_than_buffer_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = STREAM_BUFFER_SIZE - 1;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);
    size_t bytes_read = 0;
    bool message_finished = true;

    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
            stream, &bytes_read, &message_finished, buffer, bytes_to_read));

    AVS_UNIT_ASSERT_EQUAL(bytes_read, bytes_to_read);
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, ctx.data, bytes_read);
    AVS_UNIT_ASSERT_EQUAL(ctx.curr_offset, STREAM_BUFFER_SIZE);

    avs_free(buffer);
    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, read_less_than_stream_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = STREAM_SIZE - 1;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);
    size_t bytes_read = 0;
    size_t total_read = 0;
    bool message_finished = true;

    while (total_read < bytes_to_read) {
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
                stream, &bytes_read, &message_finished, buffer + total_read,
                bytes_to_read - total_read));
        total_read += bytes_read;
    }

    AVS_UNIT_ASSERT_EQUAL(total_read, bytes_to_read);
    AVS_UNIT_ASSERT_FALSE(message_finished);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, ctx.data, total_read);

    avs_free(buffer);
    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, read_reliably_equal_to_stream_size) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);
    size_t bytes_to_read = STREAM_SIZE;
    char *buffer = (char *) avs_calloc(bytes_to_read, sizeof(char));
    AVS_UNIT_ASSERT_NOT_NULL(buffer);

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_read_reliably(stream, buffer, bytes_to_read));
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer, ctx.data, bytes_to_read);

    avs_free(buffer);
    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, read_reliably_less_than_stream_size) {
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

AVS_UNIT_TEST(stream_buffered, try_read_reliably_more_than_stream_size) {
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

AVS_UNIT_TEST(stream_buffered, reset) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_output_stream(&ctx);
    size_t bytes_to_write = STREAM_BUFFER_SIZE - 1;

    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write_some(stream, TEST_DATA, &bytes_to_write));
    AVS_UNIT_ASSERT_EQUAL(bytes_to_write, STREAM_BUFFER_SIZE - 1);
    // Reset on buffered stream suceeded, but because of unimplemented reset
    // in underlying stream, the entire operation fails.
    AVS_UNIT_ASSERT_FAILED(avs_stream_reset(stream));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    AVS_UNIT_ASSERT_EQUAL(ctx.curr_offset, 0);

    teardown_stream(&stream, &ctx);
}

AVS_UNIT_TEST(stream_buffered, peek) {
    stream_ctx_t ctx;
    avs_stream_t *stream = setup_input_stream(&ctx);

    char value;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_peek(stream, 0, &value));
    AVS_UNIT_ASSERT_EQUAL(value, TEST_DATA[0]);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_peek(stream, STREAM_BUFFER_SIZE - 1, &value));
    AVS_UNIT_ASSERT_EQUAL(value, TEST_DATA[STREAM_BUFFER_SIZE - 1]);

    avs_error_t err = avs_stream_peek(stream, STREAM_BUFFER_SIZE, &value);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_ENOBUFS);

    teardown_stream(&stream, &ctx);
}
