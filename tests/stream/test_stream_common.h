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

/**
 * In the case of input streams, we need to prepare some content
 * before the testing - because it would be nice to test the functions
 * for reading lines we replaced some spaces in the standard text data
 * with a new lines.
 */
static const char TEST_DATA[] =
        "Bacon ipsum dolor amet buffalo burgdoggen pancetta salami "
        "tenderloin,\n"
        "cupim kevin ham chicken. Beef ribs hamburger venison, pig swine\n"
        "kielbasa tri-tip buffalo. Porchetta andouille flank, picanha boudin\n"
        "swine brisket shank bresaola pastrami sirloin lambada\n";

/**
 * Separate lines might be handy for testing
 */
static const char FIRST_LINE[] =
        "Bacon ipsum dolor amet buffalo burgdoggen pancetta salami tenderloin,";
static const char SECOND_LINE[] =
        "cupim kevin ham chicken. Beef ribs hamburger venison, pig swine";
static const char THIRD_LINE[] =
        "kielbasa tri-tip buffalo. Porchetta andouille flank, picanha boudin";
static const char FOURTH_LINE[] =
        "swine brisket shank bresaola pastrami sirloin lambada";

#define STREAM_BUFFER_SIZE 32
#define STREAM_SIZE (sizeof(TEST_DATA)-1)

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
