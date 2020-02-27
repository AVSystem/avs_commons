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

#include <avsystem/commons/avs_shared_buffer.h>

#define AVS_UNIT_ENABLE_SHORT_ASSERTS
#include <avsystem/commons/avs_unit_test.h>

#ifndef NDEBUG
static inline void assert_acquired(avs_shared_buffer_t *buf) {
    ASSERT_NOT_NULL(buf->avs_shared_buffer_private_data.func);
    ASSERT_NOT_NULL(buf->avs_shared_buffer_private_data.file);
    ASSERT_NE(buf->avs_shared_buffer_private_data.line, 0);
}

static inline void assert_not_acquired(avs_shared_buffer_t *buf) {
    ASSERT_NULL(buf->avs_shared_buffer_private_data.func);
    ASSERT_NULL(buf->avs_shared_buffer_private_data.file);
    ASSERT_EQ(buf->avs_shared_buffer_private_data.line, 0);
}
#else
static inline void assert_acquired(avs_shared_buffer_t *buf) {
    (void) buf;
}

static inline void assert_not_acquired(avs_shared_buffer_t *buf) {
    (void) buf;
}
#endif

AVS_UNIT_TEST(shared_buffer, heap_allocated) {
    enum { BUF_SIZE = 4096 };
    avs_shared_buffer_t *buf = avs_shared_buffer_new(BUF_SIZE);

    ASSERT_NOT_NULL(buf);
    ASSERT_EQ(buf->capacity, BUF_SIZE);
    assert_not_acquired(buf);

    // make sure returned pointer has appropriate type
    uint8_t *buf_data = avs_shared_buffer_acquire(buf);
    assert_acquired(buf);

    // use valgrind/ASAN to check for out-of-bounds accesses
    memset(buf_data, 0xDD, BUF_SIZE);

    avs_shared_buffer_release(buf);
    assert_not_acquired(buf);

    avs_free(buf);
}
