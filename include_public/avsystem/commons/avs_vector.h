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

#ifndef AVS_COMMONS_VECTOR_H
#define AVS_COMMONS_VECTOR_H

#include <stddef.h>
#include <stdint.h>

#include <avsystem/commons/avs_defs.h>

/**
 * @file avs_vector.h
 *
 * A generic vector implementation.
 *
 * Vector is an automatically growing container, similar to the list, except it
 * provides random access to the elements in constant time. Additionally adding
 * new elements at the end of the vector is realized in amortized O(1) time.
 *
 * Elements held by the vector MUST be trivially moveable. (via memmove)
 *
 * In the documentation of the later functions, following definitions will apply
 * to the vector. We consider vectors to be in states:
 *
 * - "initialized" vector, if it is a valid pointer allocated by AVS_VECTOR_NEW,
 *
 * - "not initialized" if it is not "initialized"
 *
 * - "empty" if it is "initialized" and calling @ref AVS_VECTOR_SIZE on it
 *   returns 0
 *
 * The testing code (<c>test_vector.c</c>) may be a good starting point for
 * usage examples.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct avs_vector_desc_struct avs_vector_desc_t;

/**
 * Comparator type for @ref AVS_VECTOR_SORT_RANGE, AVS_VECTOR_SORT.
 *
 * @param a         The left element of comparison.
 * @param b         The right element of comparison.
 *
 * @return A negative value if <c>a &lt; b</c>, zero if <c>a == b</c> or
 *         a positive value if <c>a &gt; b</c>.
 */
typedef int (*avs_vector_comparator_func_t)(const void *a, const void *b);

/**
 * @name Internal functions
 *
 * These functions contain actual implementation of some of the vector
 * functionality.
 *
 * They are wrapped in macros that offer additional layer of type safety if
 * <c>typeof</c> is available, so it is preferable to use them instead of these
 * functions directly.
 */
/**@{*/
void **avs_vector_new__(size_t elem_size);
void avs_vector_delete__(void ***ptr);
int avs_vector_push__(void ***ptr, const void *elemptr);
void *avs_vector_pop__(void ***ptr);
void *avs_vector_remove__(void ***ptr, size_t index);

size_t avs_vector_size__(void **ptr);
size_t avs_vector_capacity__(void **ptr);
void *avs_vector_at__(void **vec, size_t index);
void *avs_vector_back__(void **vec);

void avs_vector_sort_range__(void ***ptr,
                             size_t beg,
                             size_t end,
                             avs_vector_comparator_func_t cmp);
void avs_vector_sort__(void ***ptr, avs_vector_comparator_func_t cmp);
void avs_vector_swap__(void ***ptr, size_t i, size_t j);
void avs_vector_reverse__(void ***ptr);
void avs_vector_reverse_range__(void ***ptr, size_t beg, size_t end);
int avs_vector_fit__(void ***ptr);
int avs_vector_reserve__(void ***ptr, size_t num_elements);
/**@}*/

#ifdef __cplusplus
}
#endif

/**
 * Vector type for a given element type. In fact it is a pointer to the vector
 * internal data pointer, which allows dereferencing the vector to access its
 * elements. See @ref AVS_VECTOR_AT for more details.
 *
 * @param element_type Type of the list element.
 */
#define AVS_VECTOR(element_type) element_type **

/**
 * Initializes vector pointed by @p vecptr.
 *
 * @param element_type Type of the data contained by the vector.
 * @return  NULL on failure, non-NULL value otherwise.
 */
#define AVS_VECTOR_NEW(element_type) \
    ((AVS_VECTOR(element_type)) avs_vector_new__(sizeof(element_type)))

/**
 * Frees internal storage associated with vector, and sets @p *vecptr to NULL.
 *
 * @param vecptr    Pointer to the initialized AVS_VECTOR
 */
#define AVS_VECTOR_DELETE(vecptr) (avs_vector_delete__((void ***) (vecptr)))

/**
 * Copies an element pointed by @p elemptr and places it at the end of the
 * vector if it is possible.
 *
 * Note: If this operation fails then the vector pointed by @p vecptr remains
 *       unchanged.
 *
 * Note: @p vecptr and @p elemptr are evaluated only once.
 *
 * @param vecptr    Pointer to the AVS_VECTOR, might be NULL, in which case
 *                  vector will be initialized if possible.
 *
 * @param elemptr   Pointer to the element
 * @return 0 if adding an element was successful, negative value in case of an
 *         error (for example when there is not enough memory)
 *
 * Time complexity: amortized O(1)
 */
#define AVS_VECTOR_PUSH(vecptr, elemptr)      \
    ((void) (sizeof((elemptr) < **(vecptr))), \
     avs_vector_push__((void ***) (vecptr), (const void *) (elemptr)))
/**
 * Returns number of elements in the AVS_VECTOR @p vec.
 *
 * @param vec   Initialized AVS_VECTOR
 * @return Number of elements
 */
#define AVS_VECTOR_SIZE(vec) (avs_vector_size__((void **) (vec)))

/**
 * Returns number of elements that AVS_VECTOR has currently allocated space for.
 *
 * @param vec   Initialized AVS_VECTOR
 * @return Number of elements that AVS_VECTOR has currently allocated space for
 */
#define AVS_VECTOR_CAPACITY(vec) (avs_vector_capacity__((void **) (vec)))

/**
 * Retrieves pointer to the element at position @p index. If @p index is out of
 * vector range (i.e. index >= AVS_VECTOR_SIZE(vec)), then the NULL is returned.
 *
 * @param vec   Initialized AVS_VECTOR, must not be NULL
 * @param index Position of the element
 * @return Pointer to the element, or NULL
 *
 * Time complexity: O(1)
 */
#ifdef __cplusplus
template <typename T>
static inline T *avs_vector_at_impl__(AVS_VECTOR(T) vec, size_t index) {
    return (T *) avs_vector_at__((void **) vec, index);
}
#    define AVS_VECTOR_AT(vec, index) (avs_vector_at_impl__((vec), (index)))
#else
#    define AVS_VECTOR_AT(vec, index) \
        ((AVS_TYPEOF_PTR(*(vec))) avs_vector_at__((void **) (vec), (index)))
#endif

/**
 * Retrieves pointer to the first element in the vector, or NULL if the vector
 * is empty.
 *
 * @param vec   Initialized AVS_VECTOR
 * @return Pointer to the first element in the vector or NULL
 *
 * Time complexity: O(1)
 */
#define AVS_VECTOR_FRONT(vec) AVS_VECTOR_AT((vec), 0)

/**
 * Retrieves pointer to the last element in the vector, or NULL if the vector
 * is empty.
 *
 * Note: @p vec is evaluated only once.
 *
 * @param vec   Initialized AVS_VECTOR
 * @return Pointer to the last element in the vector or NULL
 *
 * Time complexity: O(1)
 */
#ifdef __cplusplus
template <typename T>
static inline T *avs_vector_back_impl__(AVS_VECTOR(T) vec) {
    return (T *) avs_vector_back__((void **) vec);
}
#    define AVS_VECTOR_BACK(vec) (avs_vector_back_impl__((vec)))
#else
#    define AVS_VECTOR_BACK(vec) \
        ((AVS_TYPEOF_PTR(*(vec))) avs_vector_back__((void **) (vec)))
#endif

/**
 * Moves element from position @p index at the end of the vector and decreases
 * vector size by one. Moved element can be accessed by the user, via pointer
 * returned by this function. It is valid as long as NO MODYFING OPERATION is
 * performed on the vector. Returned pointer MUST NOT be freed by the user.
 *
 * @param vecptr    Pointer to the initialized AVS_VECTOR.
 * @param index     Position of the element to be removed.
 * @return pointer to the element being removed, or NULL if the vector size is
 *         0.
 * Time complexity: at most O(n)
 */
#ifdef __cplusplus
template <typename T>
static inline T *avs_vector_remove_impl__(AVS_VECTOR(T) *vecptr, size_t index) {
    return (T *) avs_vector_remove__((void ***) vecptr, index);
}
#    define AVS_VECTOR_REMOVE_AT(vecptr, index) \
        (avs_vector_remove_impl__((vecptr), (index)))
#else
#    define AVS_VECTOR_REMOVE_AT(vecptr, index)                                \
        ((AVS_TYPEOF_PTR(**(vecptr))) avs_vector_remove__((void ***) (vecptr), \
                                                          (index)))
#endif

/**
 * Equivalent to AVS_VECTOR_REMOVE_AT(max(AVS_VECTOR_SIZE(*vecptr)-1, 0))
 *
 * Time complexity: O(1)
 */
#ifdef __cplusplus
template <typename T>
static inline T *avs_vector_pop_impl__(AVS_VECTOR(T) *vecptr) {
    return (T *) avs_vector_pop__((void ***) vecptr);
}
#    define AVS_VECTOR_POP(vecptr) (avs_vector_pop_impl__((vecptr)))
#else
#    define AVS_VECTOR_POP(vecptr) \
        ((AVS_TYPEOF_PTR(**(vecptr))) avs_vector_pop__((void ***) (vecptr)))
#endif

/**
 * Destroys all elements being held by the AVS_VECTOR leaving it with size equal
 * to 0.
 *
 * Note: this function allows to perform additional user specified operations on
 * for each removed element (@p elemptr) that are defined inside a block.
 *
 * Warning: elements are destroyed in a back-to-front manner, i.e. last element
 * is removed first.
 *
 * Warning: clearing the vector does NOT free its internal memory used to store
 * elements, i.e. vector capacity remains unchanged. To release potentially
 * unneeded memory one should call @ref AVS_VECTOR_FIT.
 *
 * Example usage:
 * @code
 * AVS_VECTOR(some_type) vec = NULL;
 * .
 * . // adding elements to the vector
 * .
 * some_type *elem;
 * AVS_VECTOR_CLEAR(&vec, elem) {
 *     free(elem->some_pointer_field);
 * }
 * printf("%d", AVS_VECTOR_SIZE(vec)); // outputs: 0
 *
 * @param vecptr    Pointer to the initialized AVS_VECTOR
 *
 * Time complexity: O(n * user defined operation time)
 */
#define AVS_VECTOR_CLEAR(vecptr, elemptr) \
    while (((elemptr) = AVS_VECTOR_POP(vecptr)))

/**
 * Tries to optimize vector memory usage by making sure that only
 * sizeof(vector element size) * AVS_VECTOR_SIZE(*vecptr) bytes are allocated.
 *
 * Note: on failure vector pointed by @p vecptr remains unchanged
 *
 * @param vecptr    Pointer to the initialized AVS_VECTOR
 * @return 0 on success, negative value in case of an error (i.e. out of memory)
 *
 * Time complexity: O(n)
 */
#define AVS_VECTOR_FIT(vecptr) (avs_vector_fit__((void ***) (vecptr)))

/**
 * Increases the capacity of the container to a value that's greater or equal
 * to @p new_elements. If @p new_elements is greater than the current capacity,
 * new storage is allocated, otherwise the method does nothing.
 *
 * Note: on error vector is unchanged.
 *
 * @param vecptr        Pointer to the initialized AVS_VECTOR
 * @param num_elements  New capacity
 * @return 0 on success, negative value otherwise
 */
#define AVS_VECTOR_RESERVE(vecptr, num_elements) \
    (avs_vector_reserve__((void ***) (vecptr), (num_elements)))

/**
 * Swaps elements at positions @p i and @p j.
 *
 * @param vecptr    Pointer to the initialized AVS_VECTOR
 * @param i         Index of the element to be replaced by j.
 * @param j         Index of the element to be replaced by i.
 */
#define AVS_VECTOR_SWAP(vecptr, i, j) \
    (avs_vector_swap__((void ***) (vecptr), (i), (j)))

/**
 * Reverses the order of vector elements in-place.
 *
 * @param vecptr    Pointer to the initialized AVS_VECTOR
 * Time complexity: O(n)
 */
#define AVS_VECTOR_REVERSE(vecptr) (avs_vector_reverse__((void ***) (vecptr)))

/**
 * Reverses the range [beg, end) of the vector in-place.
 *
 * @param vecptr    Pointer to the initialized AVS_VECTOR.
 * @param beg       Index of the beginning of the range
 * @param end       Index of the end of the range + 1
 *
 * Note: indexes must not be negative, otherwise the behaviour is undefined
 * Note: if beg >= end then the function does nothing
 *
 * Time complexity: O(end - beg)
 */
#define AVS_VECTOR_REVERSE_RANGE(vecptr, beg, end) \
    (avs_vector_reverse_range__((void ***) (vecptr), (beg), (end)))

/**
 * Sorts range [begidx, endidx) in vector @p vecptr.
 *
 * WARNING: range [begidx, endidx) MUST be valid, i.e. enclosed in the vector
 * range [0, AVS_VECTOR_SIZE(*vecptr) - 1], otherwise the behavior is undefined.
 *
 * @param vecptr    Pointer to the AVS_VECTOR
 * @param begidx    Beginning of the range to be sorted
 * @param endidx    End of the range to be sorted (exclusive)
 * @param cmp       Comparator function of type
 *                  @ref avs_vector_comparator_func_t.
 *
 * Time complexity: because standard C quicksort is used as sorting algorithm,
 *                  it is O(nlogn) on average and O(n^2) in a pesimistic case.
 */
#define AVS_VECTOR_SORT_RANGE(vecptr, begidx, endidx, cmp) \
    (avs_vector_sort_range__((void ***) (vecptr), (begidx), (endidx), (cmp)))

/**
 * Sorts entire vector pointed by @p vecptr. It is equivalent to
 * AVS_VECTOR_SORT_RANGE(vecptr, 0, AVS_VECTOR_SIZE(*vecptr), cmp)
 *
 * @param vecptr    Pointer to the AVS_VECTOR
 * @param cmp       Same as in @ref AVS_VECTOR_SORT_RANGE
 *
 * Time complexity: as in @ref AVS_VECTOR_SORT_RANGE
 */
#define AVS_VECTOR_SORT(vecptr, cmp) \
    (avs_vector_sort__((void ***) (vecptr), (cmp)))

#endif /* AVS_COMMONS_VECTOR_H */
