/*
 * Copyright 2025 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_unit_test.h>
#include <avsystem/commons/avs_utils.h>

#include <stdlib.h>

AVS_UNIT_TEST(align_pointer, correct_alignment) {
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 510, 4),
            512);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 511, 4),
            512);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 512, 4),
            512);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 513, 4),
            516);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 514, 4),
            516);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 515, 4),
            516);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 516, 4),
            516);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 517, 4),
            520);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 518, 4),
            520);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 519, 4),
            520);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 520, 4),
            520);
}

AVS_UNIT_TEST(aligned_stack_allocation, correct_alignment) {
    AVS_ALIGNED_STACK_BUF(A, 42);
    AVS_UNIT_ASSERT_TRUE(((unsigned long) A) % AVS_ALIGNOF(avs_max_align_t)
                         == 0);

    AVS_ALIGNED_VLA(long, B, 11, long);
    AVS_UNIT_ASSERT_TRUE((unsigned long) B % AVS_ALIGNOF(long) == 0);

    AVS_ALIGNED_VLA(char, C, 15, long);
    AVS_UNIT_ASSERT_TRUE((unsigned long) C % AVS_ALIGNOF(long) == 0);

    AVS_ALIGNED_VLA(char, D, 16, long double);
    AVS_UNIT_ASSERT_TRUE((unsigned long) D % AVS_ALIGNOF(long double) == 0);
}

#if SIZE_MAX > UINT32_MAX
// Valgrind complains about malloc(SIZE_MAX) on 64-bit platforms
#    define INVALID_MALLOC_SIZE_INNER (SIZE_MAX / 2)
#else
#    define INVALID_MALLOC_SIZE_INNER SIZE_MAX
#endif

#if defined(AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST)

typedef struct {
    size_t offset;
    char *buffer;
} heap_entry_t;

static heap_entry_t HEAP[128];
static avs_rand_seed_t HEAP_SEED;

// NOTE: calloc is kept unimplemented.
// This is intentional, avs_memory_alignfix.c is not supposed to use it

extern __typeof__(malloc) _avs_alignfix_test_malloc;
void *_avs_alignfix_test_malloc(size_t size) {
    assert(size);

    for (size_t i = 0; i < AVS_ARRAY_SIZE(HEAP); ++i) {
        if (!HEAP[i].buffer) {
            HEAP[i].offset =
                    avs_rand32_r(&HEAP_SEED) % AVS_ALIGNOF(avs_max_align_t);
            if (!(HEAP[i].buffer = (char *) malloc(size + HEAP[i].offset))) {
                return NULL;
            }
            return HEAP[i].buffer + HEAP[i].offset;
        }
    }

    return NULL;
}

extern __typeof__(realloc) _avs_alignfix_test_realloc;
void *_avs_alignfix_test_realloc(void *ptr, size_t size) {
    assert(size);
    if (!ptr) {
        return _avs_alignfix_test_malloc(size);
    }

    for (size_t i = 0; i < AVS_ARRAY_SIZE(HEAP); ++i) {
        if (ptr == HEAP[i].buffer + HEAP[i].offset) {
            size_t newoffset = HEAP[i].offset;
            if (avs_rand_r(&HEAP_SEED) % (2 * AVS_ALIGNOF(avs_max_align_t))
                    == 0) {
                newoffset =
                        avs_rand32_r(&HEAP_SEED) % AVS_ALIGNOF(avs_max_align_t);
            }
            char *newptr =
                    (char *) realloc(HEAP[i].buffer,
                                     size + AVS_MAX(HEAP[i].offset, newoffset));
            if (!newptr) {
                return NULL;
            }
            HEAP[i].buffer = newptr;
            if (newoffset != HEAP[i].offset) {
                memmove(HEAP[i].buffer + newoffset,
                        HEAP[i].buffer + HEAP[i].offset,
                        size);
                HEAP[i].offset = newoffset;
            }
            return HEAP[i].buffer + HEAP[i].offset;
        }
    }
    AVS_UNIT_ASSERT_FALSE(!!"Invalid realloc()");
    return NULL;
}

extern __typeof__(free) _avs_alignfix_test_free;
void _avs_alignfix_test_free(void *ptr) {
    if (!ptr) {
        return;
    }
    for (size_t i = 0; i < AVS_ARRAY_SIZE(HEAP); ++i) {
        if (ptr == HEAP[i].buffer + HEAP[i].offset) {
            free(HEAP[i].buffer);
            HEAP[i].buffer = NULL;
            return;
        }
    }
    AVS_UNIT_ASSERT_FALSE(!!"Invalid free()");
}

#    define INVALID_MALLOC_SIZE \
        (INVALID_MALLOC_SIZE_INNER - (2 * AVS_ALIGNOF(avs_max_align_t)))

#elif defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR)

#    define INVALID_MALLOC_SIZE \
        (INVALID_MALLOC_SIZE_INNER - AVS_ALIGNOF(avs_max_align_t))

#else // defined(AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST) ||
      // defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR)

#    define INVALID_MALLOC_SIZE INVALID_MALLOC_SIZE_INNER

#endif // defined(AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST) ||
       // defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR)

#if defined(AVS_COMMONS_UTILS_WITH_STANDARD_ALLOCATOR)        \
        || defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR) \
        || defined(AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST)
AVS_UNIT_TEST(heap_allocation, avs_malloc) {
#    ifdef AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST
    HEAP_SEED = 69420;
#    endif // AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST
    avs_rand_seed_t seed = 2137;
    AVS_LIST(void *) allocated = NULL;

    bool visited_sizes[16] = { 0 };
    size_t visited_sizes_count = 0;

    // Loop until we tried all the sizes from 0 to 15, inclusive
    while (visited_sizes_count < AVS_ARRAY_SIZE(visited_sizes)) {
        size_t size = avs_rand_r(&seed) % AVS_ARRAY_SIZE(visited_sizes);

        visited_sizes[size] = true;

        AVS_UNIT_ASSERT_NOT_NULL(AVS_LIST_INSERT_NEW(void *, &allocated));
        *allocated = avs_malloc(size);
        AVS_UNIT_ASSERT_TRUE(!size || *allocated);
        AVS_UNIT_ASSERT_TRUE(
                (uintptr_t) *allocated % AVS_ALIGNOF(avs_max_align_t) == 0);

        // Calculate how many entries in the visited_sizes array are true
        visited_sizes_count = 0;
        for (size_t i = 0; i < AVS_ARRAY_SIZE(visited_sizes); ++i) {
            if (visited_sizes[i]) {
                ++visited_sizes_count;
            }
        }
    }

    AVS_LIST_CLEAR(&allocated) {
        avs_free(*allocated);
    }

    AVS_UNIT_ASSERT_NULL(avs_malloc(INVALID_MALLOC_SIZE));
}
#endif // defined(AVS_COMMONS_UTILS_WITH_STANDARD_ALLOCATOR) ||
       // defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR) ||
       // defined(AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST)

#if defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR) \
        || defined(AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST)
AVS_UNIT_TEST(heap_allocation, avs_calloc) {
#    ifdef AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST
    HEAP_SEED = 69420;
#    endif // AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST
    AVS_UNIT_ASSERT_NULL(avs_calloc(0, 0));
    AVS_UNIT_ASSERT_NULL(avs_calloc(0, 21));
    AVS_UNIT_ASSERT_NULL(avs_calloc(37, 0));
    AVS_UNIT_ASSERT_NULL(avs_calloc(SIZE_MAX / 4 + 1, 4));
    AVS_UNIT_ASSERT_NULL(avs_calloc(4, SIZE_MAX / 4 + 1));
    AVS_UNIT_ASSERT_NULL(avs_calloc(1, INVALID_MALLOC_SIZE));
    AVS_UNIT_ASSERT_NULL(avs_calloc(INVALID_MALLOC_SIZE, 1));

    char *data = (char *) avs_calloc(21, 37);
    AVS_UNIT_ASSERT_NOT_NULL(data);
    for (size_t i = 0; i < 21 * 37; ++i) {
        AVS_UNIT_ASSERT_EQUAL(data[i], 0);
    }
    avs_free(data);
}

AVS_UNIT_TEST(heap_allocation, avs_realloc) {
#    ifdef AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST
    HEAP_SEED = 69420;
#    endif // AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST
    avs_rand_seed_t seed = 2137;
    uint8_t *ptr = (uint8_t *) avs_realloc(NULL, 2137);
    AVS_UNIT_ASSERT_NOT_NULL(ptr);
    // This shall work as avs_free()
    AVS_UNIT_ASSERT_NULL(avs_realloc(ptr, 0));
    AVS_UNIT_ASSERT_NULL(avs_realloc(NULL, SIZE_MAX));

    for (size_t i = 0; i < 1000; ++i) {
        ptr = (uint8_t *) avs_realloc(NULL, 21);
        AVS_UNIT_ASSERT_NOT_NULL(ptr);
        AVS_UNIT_ASSERT_TRUE((uintptr_t) ptr % AVS_ALIGNOF(avs_max_align_t)
                             == 0);
        avs_rand_seed_t seed_copy = seed;
        for (size_t j = 0; j < 21; ++j) {
            ptr[j] = (uint8_t) (avs_rand_r(&seed) % UINT8_MAX);
        }
        AVS_UNIT_ASSERT_NULL(avs_realloc(ptr, INVALID_MALLOC_SIZE));
        ptr = (uint8_t *) avs_realloc(ptr, 37);
        AVS_UNIT_ASSERT_NOT_NULL(ptr);
        AVS_UNIT_ASSERT_TRUE((uintptr_t) ptr % AVS_ALIGNOF(avs_max_align_t)
                             == 0);
        for (size_t j = 0; j < 21; ++j) {
            AVS_UNIT_ASSERT_EQUAL(
                    ptr[j], (uint8_t) (avs_rand_r(&seed_copy) % UINT8_MAX));
        }
        AVS_UNIT_ASSERT_NULL(avs_realloc(ptr, 0));
    }
}
#endif // defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR) ||
       // defined(AVS_COMMONS_ALIGNFIX_ALLOCATOR_TEST)
