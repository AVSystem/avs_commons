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

#ifndef AVS_COMMONS_UTILS_MEMORY_H
#define AVS_COMMONS_UTILS_MEMORY_H

#include <avsystem/commons/avs_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocates @p size bytes and returns a pointer to the allocated memory aligned
 * for storage of any type. The returned memory is not initialized.
 *
 * If @p size is 0, the avs_malloc() returns a pointer hat can later be
 * successfully passed to @ref avs_free(), which, depending on the
 * implementation, may be NULL or not.
 *
 * NOTE: If in doubt, refer to standard C malloc() documentation.
 *
 * @param size  Number of bytes to allocate.
 * @returns either NULL or a unique pointer value than can later be successfully
 *          passed to avs_free().
 */
void *avs_malloc(size_t size);

/**
 * Frees the memory space pointed to by @p ptr. The @ptr must have been
 * previously returned by @ref avs_malloc(), @ref avs_calloc(), or @ref
 * avs_realloc(). The @p ptr must not be freed twice or otherwise the behavior
 * is undefined.
 *
 * The @p avs_free(NULL) is a no-op.
 *
 * NOTE: If in doubt, refer to standard C free() documentation.
 *
 * @param ptr   A pointer previously returned by @ref avs_malloc(), @ref
 *              avs_calloc(), or @ref avs_realloc().
 */
void avs_free(void *ptr);

/**
 * Allocates memory for an array of @p nmemb elements of @p size bytes each
 * and returns a pointer to the allocated memory. The memory is set to zero.
 *
 * The avs_calloc(0, n) call is equivalent to avs_malloc(0).
 *
 * NOTE: If in doubt, refer to standard C calloc() documentation.
 *
 * @param nmemb Number of elements to allocate.
 * @param size  Size of each element to allocate.
 * @returns either NULL or a unique pointer value than can later be successfully
 *          passed to @ref avs_free().
 */
void *avs_calloc(size_t nmemb, size_t size);

/**
 * Changes the size of the memory block pointed to by @p ptr to @p size bytes.
 * The contents in the range [ptr, ptr + min(size, oldsize)] will remain
 * unchanged.
 *
 * - If the new size is larger than the old size, the added memory will not be
 *   initialized.
 * - If the new size is smaller than the old size, the memory area
 *   will be reduced.
 * - If the @p size is 0, the call is equivalent to avs_free(ptr).
 * - If the @p ptr is NULL, the call is equivalent to avs_malloc(size).
 *
 * Also note that, if the block pointed to by @p ptr could not be extended
 * in place, the function allocates a new block of memory, copies data from
 * an old block to a new block, and finally it avs_free()s the old block.
 *
 * NOTE: If in doubt, refer to standard C realloc() documentation.
 *
 * @param ptr   Pointer to operate on.
 * @param size  New size.
 * @returns either NULL or a unique pointer value (not necessarily equal in
 *          value to the @p ptr) that can later be successfully passed to @ref
 *          avs_free(). On failure NULL is returned, and the @p ptr remains
 *          untouched.
 */
void *avs_realloc(void *ptr, size_t size);

/**
 * Swaps <c>[memptr1, memptr1+n)</c> and <c>[memptr2, memptr2+n)</c> memory
 * fragments. Contains assertion that the fragments do not intersect.
 */
void avs_memswap(void *memptr1, void *memptr2, size_t n);

#define AVS_SWAP(a, b)                                                  \
    do {                                                                \
        AVS_STATIC_ASSERT(sizeof(a) == sizeof(b),                       \
                          attempt_to_swap_variables_of_different_size); \
        (void) (sizeof(&(a) - &(b)));                                   \
        avs_memswap(&(a), &(b), sizeof(a));                             \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_UTILS_MEMORY_H
