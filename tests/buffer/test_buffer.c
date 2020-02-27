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

#include <avsystem/commons/avs_buffer.h>
#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_GLOBAL_INIT(verbose) {
    if (!verbose) {
        avs_log_set_default_level(AVS_LOG_QUIET);
    }
}

AVS_UNIT_TEST(byte_buffer, buffer_free) {
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, 16));
    avs_buffer_free(&buffer);
    AVS_UNIT_ASSERT_EQUAL((intptr_t) buffer, (intptr_t) NULL);
}

AVS_UNIT_TEST(byte_buffer, reset) {
    const char DATA[] = "data";
    const size_t BUFFER_SIZE = 16;
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_buffer_append_bytes(buffer, DATA, sizeof(DATA)));

    AVS_UNIT_ASSERT_NOT_EQUAL(avs_buffer_space_left(buffer), BUFFER_SIZE);
    avs_buffer_reset(buffer);
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_space_left(buffer), BUFFER_SIZE);

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, full_data) {
    static const size_t BUFFER_SIZE = 16;
    const char DATA[16] = "";
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_append_bytes(buffer, DATA, BUFFER_SIZE));
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_space_left(buffer), 0);

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, full_fill) {
    static const size_t BUFFER_SIZE = 16;
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, 0, BUFFER_SIZE));
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_space_left(buffer), 0);

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, data_size) {
    static const int BUFFER_SIZE = 4;
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data_size(buffer), 0);
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, 0, 4));
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data_size(buffer), 4);
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_consume_bytes(buffer, 2));
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data_size(buffer), 2);

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, defragment) {
    static const int BUFFER_SIZE = 4;
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, 0, 2));
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_consume_bytes(buffer, 2));
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, 0xFF, 2));
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data_size(buffer), 2);
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data(buffer)[0], 0xFF);
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data(buffer)[1], 0xFF);
    AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t) buffer->begin,
                              (intptr_t) buffer->data.data);

    defragment_buffer(buffer);
    AVS_UNIT_ASSERT_EQUAL((intptr_t) buffer->begin,
                          (intptr_t) buffer->data.data);
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data_size(buffer), 2);
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data(buffer)[0], 0xFF);
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data(buffer)[1], 0xFF);

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, raw_insert_ptr) {
    static const int BUFFER_SIZE = 4;
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, 0, 2));
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_consume_bytes(buffer, 2));
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data_size(buffer), 0);
    AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t) buffer->end,
                              (intptr_t) buffer->data.data);

    AVS_UNIT_ASSERT_NOT_EQUAL(avs_buffer_space_left(buffer),
                              space_left_without_moving(buffer));

    AVS_UNIT_ASSERT_EQUAL((intptr_t) avs_buffer_raw_insert_ptr(buffer),
                          (intptr_t) buffer->data.data);

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, consume_bytes) {
    static const int BUFFER_SIZE = 4;
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, 0, BUFFER_SIZE));
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_consume_bytes(buffer, BUFFER_SIZE));

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, consume_bytes_fail) {
    static const int BUFFER_SIZE = 4;
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, 0, BUFFER_SIZE));
    AVS_UNIT_ASSERT_FAILED(avs_buffer_consume_bytes(buffer, BUFFER_SIZE + 1));

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, append_bytes) {
    static const int BUFFER_SIZE = 4;
    static const char DATA[4] = "";
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_buffer_append_bytes(buffer, DATA, sizeof(DATA)));
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_append_bytes(buffer, NULL, 0));

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, append_bytes_fail) {
    static const int BUFFER_SIZE = 4;
    static const char DATA[5] = "";
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_FAILED(avs_buffer_append_bytes(buffer, DATA, sizeof(DATA)));

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, advance_ptr) {
    static const int BUFFER_SIZE = 4;
    avs_buffer_t *buffer;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_advance_ptr(buffer, 2));
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data_size(buffer), 2);
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_advance_ptr(buffer, 2));
    AVS_UNIT_ASSERT_EQUAL(avs_buffer_data_size(buffer), 4);
    AVS_UNIT_ASSERT_FAILED(avs_buffer_advance_ptr(buffer, 1));
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_advance_ptr(buffer, 0));

    avs_buffer_free(&buffer);
}

AVS_UNIT_TEST(byte_buffer, fill_bytes) {
    static const int BUFFER_SIZE = 4;
    avs_buffer_t *buffer;
    int fill = 0;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_create(&buffer, BUFFER_SIZE));

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, fill, BUFFER_SIZE));
    {
        unsigned i;
        size_t data_size = avs_buffer_data_size(buffer);
        const char *data = avs_buffer_data(buffer);
        for (i = 0; i < data_size; ++i) {
            AVS_UNIT_ASSERT_EQUAL(data[i], fill);
        }
    }

    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_consume_bytes(buffer, BUFFER_SIZE));
    fill = 0xFF;
    AVS_UNIT_ASSERT_SUCCESS(avs_buffer_fill_bytes(buffer, fill, BUFFER_SIZE));
    {
        unsigned i;
        size_t data_size = avs_buffer_data_size(buffer);
        const char *data = avs_buffer_data(buffer);
        for (i = 0; i < data_size; ++i) {
            AVS_UNIT_ASSERT_EQUAL(data[i], fill);
        }
    }

    avs_buffer_free(&buffer);
}
