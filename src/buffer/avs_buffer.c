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

#ifdef AVS_COMMONS_WITH_AVS_BUFFER

#    include <stddef.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_buffer.h>
#    include <avsystem/commons/avs_defs.h>
#    include <avsystem/commons/avs_memory.h>

#    define MODULE_NAME avs_buffer
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

struct avs_buffer_struct {
    size_t capacity;
    char *begin;
    char *end;
    union {
        char data[1]; /* variable length */
        avs_max_align_t align;
    } data;
};

size_t avs_buffer_space_left(const avs_buffer_t *buffer) {
    return buffer->capacity - avs_buffer_data_size(buffer);
}

static size_t space_left_without_moving(const avs_buffer_t *buffer) {
    return buffer->capacity - (size_t) (buffer->end - buffer->data.data);
}

void avs_buffer_reset(avs_buffer_t *buffer) {
    buffer->begin = buffer->data.data;
    buffer->end = buffer->data.data;
}

int avs_buffer_create(avs_buffer_t **buffer_ptr, size_t capacity) {
    *buffer_ptr = (avs_buffer_t *) avs_malloc(offsetof(avs_buffer_t, data)
                                              + capacity);
    if (*buffer_ptr) {
        (*buffer_ptr)->capacity = capacity;
        avs_buffer_reset(*buffer_ptr);
        return 0;
    } else {
        LOG(ERROR, _("cannot allocate buffer"));
        return -1;
    }
}

void avs_buffer_free(avs_buffer_t **buffer) {
    avs_free(*buffer);
    *buffer = NULL;
}

size_t avs_buffer_data_size(const avs_buffer_t *buffer) {
    return (size_t) (buffer->end - buffer->begin);
}

size_t avs_buffer_capacity(const avs_buffer_t *buffer) {
    return buffer->capacity;
}

const char *avs_buffer_data(const avs_buffer_t *buffer) {
    return buffer->begin;
}

static void defragment_buffer(avs_buffer_t *buffer) {
    if (buffer->begin != buffer->data.data) {
        size_t used = avs_buffer_data_size(buffer);
        memmove(buffer->data.data, buffer->begin, used);
        buffer->end = buffer->data.data + used;
        buffer->begin = buffer->data.data;
    }
}

char *avs_buffer_raw_insert_ptr(avs_buffer_t *buffer) {
    defragment_buffer(buffer);
    return buffer->end;
}

int avs_buffer_consume_bytes(avs_buffer_t *buffer, size_t bytes_count) {
    if (bytes_count > avs_buffer_data_size(buffer)) {
        LOG(ERROR, _("not enough data"));
        return -1;
    }
    buffer->begin += bytes_count;

    return 0;
}

int avs_buffer_append_bytes(avs_buffer_t *buffer,
                            const void *data,
                            size_t data_length) {
    if (data_length > avs_buffer_space_left(buffer)) {
        LOG(ERROR, _("buffer too small"));
        return -1;
    } else {
        if (data_length > space_left_without_moving(buffer)) {
            defragment_buffer(buffer);
        }
        memcpy(buffer->end, data, data_length);
        buffer->end += data_length;
        return 0;
    }
}

int avs_buffer_advance_ptr(avs_buffer_t *buffer, size_t n) {
    if (n > avs_buffer_space_left(buffer)) {
        LOG(ERROR, _("position out of bounds"));
        return -1;
    } else {
        if (n > space_left_without_moving(buffer)) {
            defragment_buffer(buffer);
        }
        buffer->end += n;
        return 0;
    }
}

int avs_buffer_fill_bytes(avs_buffer_t *buffer, int value, size_t bytes_count) {
    if (bytes_count > avs_buffer_space_left(buffer)) {
        return -1;
    } else {
        if (bytes_count > space_left_without_moving(buffer)) {
            defragment_buffer(buffer);
        }
        memset(buffer->end, value, bytes_count);
        buffer->end += bytes_count;
        return 0;
    }
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/buffer/test_buffer.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_BUFFER
