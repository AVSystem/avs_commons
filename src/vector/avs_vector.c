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

#ifdef AVS_COMMONS_WITH_AVS_VECTOR

#    include <assert.h>
#    include <stddef.h>
#    include <stdint.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_vector.h>

VISIBILITY_SOURCE_BEGIN

struct avs_vector_desc_struct {
    uint64_t magic;
    size_t size;
    size_t capacity;
    size_t elem_size;
    void *data;
};
static const uint64_t magic = 0xb5e4189902ba0aaULL;

#    define AVS_VECTOR_DESC__(vec)           \
        ((avs_vector_desc_t *) (intptr_t) (( \
                const char *) (vec) -offsetof(avs_vector_desc_t, data)))

static avs_vector_desc_t *get_desc(void **ptr) {
    avs_vector_desc_t *desc;
    AVS_ASSERT(ptr, "NULL vector pointer");
    desc = AVS_VECTOR_DESC__(ptr);
    AVS_ASSERT(desc->magic == magic, "invalid vector pointer");
    return desc;
}

/* Helper functions that do not perform pointer validity checks */
static void *vector_at_internal(avs_vector_desc_t *desc, size_t index) {
    if (index >= desc->size) {
        return NULL;
    }
    return (char *) desc->data + index * desc->elem_size;
}

static size_t vector_size_internal(avs_vector_desc_t *desc) {
    return desc->size;
}

static void *vector_back_internal(avs_vector_desc_t *desc) {
    if (desc->size == 0) {
        return NULL;
    }
    return (char *) desc->data + (desc->size - 1) * desc->elem_size;
}

static void *vector_pop_internal(avs_vector_desc_t *desc) {
    void *retval = vector_back_internal(desc);
    desc->size = desc->size == 0 ? 0 : desc->size - 1;
    return retval;
}

static void vector_swap_internal(avs_vector_desc_t *desc, size_t i, size_t j) {
    assert(i < desc->size && j < desc->size);
    if (i == j) {
        return;
    } else {
        size_t k;
        uint8_t tmp;
        uint8_t *first = (uint8_t *) desc->data + i * desc->elem_size;
        uint8_t *second = (uint8_t *) desc->data + j * desc->elem_size;
        for (k = 0; k < desc->elem_size; ++k) {
            tmp = *first;
            *first++ = *second;
            *second++ = tmp;
        }
    }
}

static void
vector_reverse_range_internal(avs_vector_desc_t *desc, size_t beg, size_t end) {
    if (beg >= end) {
        return;
    }
    while ((beg != end) && (beg != --end)) {
        vector_swap_internal(desc, beg, end);
        ++beg;
    }
}

/* API methods implementation */
void **avs_vector_new__(size_t elem_size) {
    avs_vector_desc_t *desc =
            (avs_vector_desc_t *) avs_calloc(1, sizeof(avs_vector_desc_t));
    if (!desc) {
        return NULL;
    }
    desc->magic = magic;
    desc->elem_size = elem_size;
    return (void **) &desc->data;
}

void avs_vector_delete__(void ***ptr) {
    avs_vector_desc_t *desc;
    if (*ptr == NULL) {
        return;
    }
    desc = get_desc(*ptr);
    avs_free(desc->data);
    avs_free(desc);
    *ptr = NULL;
}

int avs_vector_push__(void ***ptr, const void *elemptr) {
    avs_vector_desc_t *desc = get_desc(*ptr);
    if (desc->capacity - desc->size == 0
            && avs_vector_reserve__(ptr,
                                    desc->size == 0 ? 1 : 2 * desc->size)) {
        return -1;
    }
    memcpy((char *) desc->data + desc->size * desc->elem_size, elemptr,
           desc->elem_size);
    ++desc->size;
    return 0;
}

void *avs_vector_pop__(void ***ptr) {
    return vector_pop_internal(get_desc(*ptr));
}

void *avs_vector_remove__(void ***ptr, size_t index) {
    size_t size, i;
    void *tmp;
    avs_vector_desc_t *desc = get_desc(*ptr);
    size = vector_size_internal(desc);
    if (size == 0) {
        return NULL;
    }
    tmp = avs_malloc(desc->elem_size);
    if (tmp) {
        memcpy(tmp, vector_at_internal(desc, index), desc->elem_size);
        memmove(vector_at_internal(desc, index),
                vector_at_internal(desc, index + 1),
                desc->elem_size * (size - index - 1));
        memcpy(vector_at_internal(desc, size - 1), tmp, desc->elem_size);
        avs_free(tmp);
    } else {
        for (i = index; i < size - 1; i++) {
            vector_swap_internal(desc, i, i + 1);
        }
    }
    return vector_pop_internal(desc);
}

size_t avs_vector_size__(void **ptr) {
    return vector_size_internal(get_desc(ptr));
}

size_t avs_vector_capacity__(void **ptr) {
    return get_desc(ptr)->capacity;
}

void *avs_vector_at__(void **ptr, size_t index) {
    return vector_at_internal(get_desc(ptr), index);
}

void *avs_vector_back__(void **ptr) {
    return vector_back_internal(get_desc(ptr));
}

void avs_vector_sort_range__(void ***ptr,
                             size_t beg,
                             size_t end,
                             avs_vector_comparator_func_t cmp) {
    avs_vector_desc_t *desc = get_desc(*ptr);
    assert(end > beg);
    qsort((char *) desc->data + beg * desc->elem_size, end - beg,
          desc->elem_size, cmp);
}

void avs_vector_sort__(void ***ptr, avs_vector_comparator_func_t cmp) {
    avs_vector_desc_t *desc = get_desc(*ptr);
    qsort((char *) desc->data, desc->size, desc->elem_size, cmp);
}

void avs_vector_swap__(void ***ptr, size_t i, size_t j) {
    vector_swap_internal(get_desc(*ptr), i, j);
}

void avs_vector_reverse__(void ***ptr) {
    avs_vector_reverse_range__(ptr, 0, avs_vector_size__(*ptr));
}

void avs_vector_reverse_range__(void ***ptr, size_t beg, size_t end) {
    vector_reverse_range_internal(get_desc(*ptr), beg, end);
}

int avs_vector_fit__(void ***ptr) {
    void *new_data;
    avs_vector_desc_t *desc = get_desc(*ptr);
    if (*ptr == NULL) {
        return 0;
    }
    if (desc->size == 0 || desc->size == desc->capacity) {
        return 0;
    }
    new_data = avs_malloc(desc->size * desc->elem_size);
    if (!new_data) {
        return -1;
    }
    memcpy(new_data, desc->data, desc->size * desc->elem_size);
    avs_free(desc->data);
    desc->data = new_data;
    desc->capacity = desc->size;
    return 0;
}

static int ensure_capacity(avs_vector_desc_t *desc, size_t num_elements) {
    uint64_t new_capacity = (uint64_t) num_elements * desc->elem_size;
    void *new_data;
    if (new_capacity != (size_t) new_capacity) {
        return -1;
    }
    new_data = avs_realloc(desc->data, (size_t) new_capacity);
    if (!new_data) {
        return -1;
    }
    desc->capacity = num_elements;
    desc->data = new_data;
    return 0;
}

int avs_vector_reserve__(void ***ptr, size_t num_elements) {
    if (ensure_capacity(get_desc(*ptr), num_elements)) {
        return -1;
    }
    return 0;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/vector/test_vector.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_VECTOR
