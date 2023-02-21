/*
 * Copyright 2023 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_SORTED_SET_H
#define AVS_COMMONS_SORTED_SET_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/avs_defs.h>
#ifdef AVS_COMMONS_WITH_AVS_RBTREE
#    include <avsystem/commons/avs_rbtree.h>
#else // AVS_COMMONS_WITH_AVS_RBTREE
#    include <avsystem/commons/avs_list.h>
#endif // AVS_COMMONS_WITH_AVS_RBTREE

#ifdef __cplusplus
extern "C" {
#endif

/** Sorted set type alias.  */
#define AVS_SORTED_SET(type) type **
/** Constant Sorted set type alias.  */
#define AVS_SORTED_SET_CONST(type) const type *const *
/** Sorted set element type alias. */
#define AVS_SORTED_SET_ELEM(type) type *

#ifdef __cplusplus
} /* extern "C" */
#endif

#ifdef AVS_COMMONS_WITH_AVS_RBTREE
/*
 * Macros that are mapped to RBTREE macros.
 */
typedef avs_rbtree_element_comparator_t avs_sorted_set_element_comparator_t;

#    define AVS_SORTED_SET_SIZE(sorted_set) AVS_RBTREE_SIZE(sorted_set)

#    define AVS_SORTED_SET_FOREACH(it, sorted_set) \
        AVS_RBTREE_FOREACH(it, sorted_set)

#    define AVS_SORTED_SET_INSERT(sorted_set, element) \
        AVS_RBTREE_INSERT(sorted_set, element)

#    define AVS_SORTED_SET_ELEM_DELETE_DETACHED(elem_ptr) \
        AVS_RBTREE_ELEM_DELETE_DETACHED(elem_ptr)

#    define AVS_SORTED_SET_CLEAR(sorted_set) AVS_RBTREE_CLEAR(sorted_set)

#    define AVS_SORTED_SET_DELETE_ELEM(sorted_set, elem_ptr) \
        AVS_RBTREE_DELETE_ELEM(sorted_set, elem_ptr)

#    define AVS_SORTED_SET_FIND(sorted_set, val_ptr) \
        AVS_RBTREE_FIND(sorted_set, val_ptr)

#    define AVS_SORTED_SET_DETACH(sorted_set, elem) \
        AVS_RBTREE_DETACH(sorted_set, elem)

#    define AVS_SORTED_SET_DELETE(sorted_set) AVS_RBTREE_DELETE(sorted_set)

#    define AVS_SORTED_SET_ELEM_NEW_BUFFER(size) \
        AVS_RBTREE_ELEM_NEW_BUFFER(size)

#    define AVS_SORTED_SET_NEW(type, cmp) AVS_RBTREE_NEW(type, cmp)

#    define AVS_SORTED_SET_LOWER_BOUND(sorted_set, val_ptr) \
        AVS_RBTREE_LOWER_BOUND(sorted_set, val_ptr)

#    define AVS_SORTED_SET_UPPER_BOUND(sorted_set, val_ptr) \
        AVS_RBTREE_UPPER_BOUND(sorted_set, val_ptr)

#    define AVS_SORTED_SET_ELEM_NEXT(it) AVS_RBTREE_ELEM_NEXT(it)

#    define AVS_SORTED_SET_FIRST(sorted_set) AVS_RBTREE_FIRST(sorted_set)

#    define AVS_SORTED_SET_LAST(sorted_set) AVS_RBTREE_LAST(sorted_set)

#    define AVS_SORTED_SET_ELEM_NEW(type) AVS_RBTREE_ELEM_NEW(type)
#else // AVS_COMMONS_WITH_AVS_RBTREE
#    ifdef __cplusplus
extern "C" {
#    endif
/* Internal functions. use macros defined below instead. */
typedef int avs_sorted_set_element_comparator_t(const void *a, const void *b);

AVS_SORTED_SET_ELEM(void)
avs_sorted_set_lower_bound__(AVS_SORTED_SET_CONST(void) sorted_set,
                             const void *value);
AVS_SORTED_SET_ELEM(void)
avs_sorted_set_upper_bound__(AVS_SORTED_SET_CONST(void) sorted_set,
                             const void *value);

AVS_SORTED_SET_ELEM(void) avs_sorted_set_first__(AVS_SORTED_SET_CONST(void)
                                                         sorted_set);
AVS_SORTED_SET_ELEM(void) avs_sorted_set_last__(AVS_SORTED_SET_CONST(void)
                                                        sorted_set);

AVS_SORTED_SET(void)
avs_sorted_set_new__(avs_sorted_set_element_comparator_t *cmp);
void avs_sorted_set_delete__(AVS_SORTED_SET(void) *sorted_set_ptr);

AVS_SORTED_SET_ELEM(void)
avs_sorted_set_insert__(AVS_SORTED_SET(void) sorted_set, void *insert_ptr);
AVS_SORTED_SET_ELEM(void) avs_sorted_set_find__(AVS_SORTED_SET(void) sorted_set,
                                                const void *element);
#    ifdef __cplusplus
} /* extern "C" */
#    endif

#    ifdef __cplusplus
template <typename Func, typename T>
static inline AVS_SORTED_SET_ELEM(T)
AVS_SORTED_SET_CALL_WITH_ELEM_CAST__(const Func &func,
                                     AVS_SORTED_SET(T) sorted_set) {
    return (AVS_SORTED_SET_ELEM(T)) func((AVS_SORTED_SET(void)) sorted_set);
}

template <typename Func, typename T, typename Arg>
static inline AVS_SORTED_SET_ELEM(T) AVS_SORTED_SET_CALL_WITH_ELEM_CAST__(
        const Func &func, AVS_SORTED_SET(T) sorted_set, const Arg &arg) {
    return (AVS_SORTED_SET_ELEM(T)) func((AVS_SORTED_SET(void)) sorted_set,
                                         arg);
}

template <typename Func, typename T>
static inline AVS_SORTED_SET_ELEM(T)
AVS_SORTED_SET_CALL_WITH_CONST_ELEM_CAST__(const Func &func,
                                           AVS_SORTED_SET_CONST(T) sorted_set) {
    return (AVS_SORTED_SET_ELEM(T)) func(
            (AVS_SORTED_SET_CONST(void)) sorted_set);
}

template <typename Func, typename T, typename Arg>
static inline AVS_SORTED_SET_ELEM(T) AVS_SORTED_SET_CALL_WITH_CONST_ELEM_CAST__(
        const Func &func, AVS_SORTED_SET_CONST(T) sorted_set, const Arg &arg) {
    return (AVS_SORTED_SET_ELEM(
            T)) func((AVS_SORTED_SET_CONST(void)) sorted_set, arg);
}
#    else // __cplusplus
#        define AVS_SORTED_SET_CALL_WITH_ELEM_CAST__(func, ...)  \
            ((AVS_TYPEOF_PTR(*(AVS_VARARG0(__VA_ARGS__)))) func( \
                    (AVS_SORTED_SET(void)) __VA_ARGS__))
#        define AVS_SORTED_SET_CALL_WITH_CONST_ELEM_CAST__(func, ...) \
            ((AVS_TYPEOF_PTR(*(AVS_VARARG0(__VA_ARGS__)))) func(      \
                    (AVS_SORTED_SET_CONST(void)) __VA_ARGS__))
#    endif // __cplusplus

/**
 * Return the number of element in the @p sorted_set. Wrapper around
 * AVS_LIST_SIZE.
 *
 * Complexity: O(n), where:
 * - n - number of elements in set.
 *
 * @param sorted_set   Object to operate on.
 *
 * @return Total number of elements stored in the set.
 */
#    define AVS_SORTED_SET_SIZE(sorted_set) AVS_LIST_SIZE(*sorted_set)

/**
 * A shorthand notation for a for-each loop. Wrapper around AVS_LIST_FOREACH.
 *
 * @param it            Iterator variable.
 * @param sorted_set    Object to operate on.
 */
#    define AVS_SORTED_SET_FOREACH(it, sorted_set) \
        AVS_LIST_FOREACH(it, *sorted_set)

/**
 * Insert an element into the @p sorted_set.
 *
 * Complexity O(n), where:
 * - n - number of elements in set
 *
 * @param sorted_set    Sorted set object to insert the element
 * @param element       The element to insert
 *
 * @return The inserted element
 */
#    define AVS_SORTED_SET_INSERT(sorted_set, element)                \
        AVS_SORTED_SET_CALL_WITH_ELEM_CAST__(avs_sorted_set_insert__, \
                                             (sorted_set), element)

/**
 * Frees memory associated with a given detached element.
 *
 * @param elem_ptr Pointer to a detached element to free.
 */
#    define AVS_SORTED_SET_ELEM_DELETE_DETACHED(elem_ptr) \
        AVS_LIST_DELETE(elem_ptr)

/**
 * Deallocates all @p sorted_set elements. Wrapper around AVS_LIST_CLEAR.
 *
 * @param sorted_set   Object to operate on.
 */
#    define AVS_SORTED_SET_CLEAR(sorted_set) AVS_LIST_CLEAR(sorted_set)

/**
 * Deletes a element attached to a @p sorted_set detaching it before freeing
 * memory.
 *
 * @param sorted_set    Object to operate on.
 * @param elem_ptr      Pointer to the element to remove.
 */
#    define AVS_SORTED_SET_DELETE_ELEM(sorted_set, elem_ptr)          \
        do {                                                          \
            AVS_SORTED_SET_ELEM(void) *ptr =                          \
                    (AVS_SORTED_SET_ELEM(void) *) (elem_ptr);         \
            if (ptr && *ptr) {                                        \
                avs_free(((char *) (intptr_t) (AVS_SORTED_SET_DETACH( \
                                 sorted_set, *ptr)))                  \
                         - AVS_LIST_SPACE_FOR_NEXT__);                \
                *ptr = NULL;                                          \
            }                                                         \
        } while (0)

/**
 * Finds an element with value given by @p val_ptr in @p sorted_set.
 *
 * Complexity: O(n * c), where:
 * - n - number of nodes in @p sorted_set.
 * - c - complexity of @p sorted_set element comparator.
 *
 * @param sorted_set    Sorted set object to search in.
 * @param val_ptr       Pointer to a value to search for.
 *
 * @returns Found attached element pointer on success, NULL if the @p sorted_set
 * does not contain such element.
 */
#    define AVS_SORTED_SET_FIND(sorted_set, val_ptr)                \
        AVS_SORTED_SET_CALL_WITH_ELEM_CAST__(avs_sorted_set_find__, \
                                             (sorted_set), (val_ptr))

/**
 * Detaches given @p elem from @p sorted_set. Does not free @p elem.
 *
 * Complexity: O(n), where:
 * - n - number of nodes in @p sorted_set.
 *
 * @param sorted_set    Sorted set object to operate on.
 * @param elem          Element to remove.
 */
#    define AVS_SORTED_SET_DETACH(sorted_set, elem) \
        AVS_LIST_DETACH(AVS_LIST_FIND_PTR((sorted_set), (elem)))

/**
 * Releases given @p sorted_set and all its elements.
 *
 * Complexity: O(n * f).
 * - n - number of elements in @p sorted_set,
 * - f - avs_free() complexity.
 *
 * @params sorted_set_ptr Pointer to the sorted set object to destroy.
 */
#    define AVS_SORTED_SET_DELETE(sorted_set_ptr)                          \
        if (!*(sorted_set_ptr))                                            \
            ;                                                              \
        else                                                               \
            for (; **(sorted_set_ptr)                                      \
                   || (avs_sorted_set_delete__(                            \
                               (AVS_SORTED_SET(void) *) (sorted_set_ptr)), \
                       0);                                                 \
                 AVS_LIST_DELETE(*(sorted_set_ptr)))

/**
 * Creates an arbitrarily-sized, detached sorted set element. Wrapper around
 * AVS_LIST_NEW_BUFFER.
 *
 * @param size Number of bytes to allocate for the element content.
 *
 * @return Newly allocated sorted set element, as <c>void *</c>.
 */
#    define AVS_SORTED_SET_ELEM_NEW_BUFFER(size) AVS_LIST_NEW_BUFFER(size)

/**
 * Create an sorted set with elements of a given @p type.
 *
 * Complexity: O(m), where:
 * - m - avs_calloc() complexity.
 *
 * @param type Type of elements stored in the sorted set node.
 * @param cmp  Pointer to a function that compares two elements.
 *             See @ref avs_sorted_set_element_comparator_t.
 */
#    define AVS_SORTED_SET_NEW(type, cmp) \
        ((AVS_SORTED_SET(type)) avs_sorted_set_new__(cmp))

/**
 * Finds the first element in @p sorted_set that has a value greater or equal to
 * @p val_ptr
 *
 * Complexity: O(n * c), where:
 * - n - number of nodes in @p sorted_set,
 * - c - complexity of sorted set element comparator.
 *
 * @param sorted_set    Sorted set to search in.
 * @param val_ptr       Pointer to a value to search for.
 *
 * @returns Attached element pointer on success, NULL if @p sorted_set is empty,
 * or all elements present in it are strictly less than @p val_ptr.
 */
#    define AVS_SORTED_SET_LOWER_BOUND(sorted_set, val_ptr) \
        AVS_SORTED_SET_CALL_WITH_CONST_ELEM_CAST__(         \
                avs_sorted_set_lower_bound__, (sorted_set), (val_ptr))
/**
 * Finds the first element in @p sorted_set that has a value strictly greater
 * than
 * @p val_ptr
 *
 * Complexity: O(n * c), where:
 * - n - number of nodes in @p sorted_set,
 * - c - complexity of sorted set element comparator.
 *
 * @param sorted_set    Sorted set to search in.
 * @param val_ptr       Pointer to a value to search for.
 *
 * @returns Attached element pointer on success, NULL if @p sorted_set is empty,
 * or all elements present in it are less or equal to @p val_ptr.
 */
#    define AVS_SORTED_SET_UPPER_BOUND(sorted_set, val_ptr) \
        AVS_SORTED_SET_CALL_WITH_CONST_ELEM_CAST__(         \
                avs_sorted_set_upper_bound__, (sorted_set), (val_ptr))
/**
 * Finds the first element in @p sorted_set in order defined by
 * @ref avs_sorted_set_element_comparator_t of @p sorted_set.
 *
 * Complexity: O(1), where:
 *
 * @param sorted_set  Sorted set to search in.
 *
 * @returns the first element in @p sorted_set (in order defined by
 *          @ref avs_sorted_set_element_comparator_t of @p sorted_set) or NULL
 * if the
 *          @p sorted_set is empty.
 */
#    define AVS_SORTED_SET_FIRST(sorted_set)                               \
        AVS_SORTED_SET_CALL_WITH_CONST_ELEM_CAST__(avs_sorted_set_first__, \
                                                   (sorted_set))

#    define AVS_SORTED_SET_ELEM_NEXT(it) AVS_LIST_NEXT(it)

/**
 * Finds the last element in @p sorted_set in order defined by
 * @ref avs_sorted_set_element_comparator_t of @p sorted_set.
 *
 * Complexity: O(n), where:
 * - n - number of nodes in @p sorted_set,
 *
 * @param sorted_set  Sorted set to search in.
 *
 * @returns the first element in @p sorted_set (in order defined by
 *          @ref avs_sorted_set_element_comparator_t of @p sorted_set) or NULL
 * if the
 *          @p sorted_set is empty.
 */
#    define AVS_SORTED_SET_LAST(sorted_set)                               \
        AVS_SORTED_SET_CALL_WITH_CONST_ELEM_CAST__(avs_sorted_set_last__, \
                                                   (sorted_set))

/**
 * Allocates a new detached sorted set element of a given type. Wrapper around
 * AVS_LIST_NEW_ELEMENT.
 *
 * @param type Type of user data to allocate.
 *
 * @return Newly allocated sorted set element, as <c>type *</c>.
 */
#    define AVS_SORTED_SET_ELEM_NEW(type) AVS_LIST_NEW_ELEMENT(type)
#endif // AVS_COMMONS_WITH_AVS_RBTREE

#endif /* AVS_COMMONS_SORTED_SET_H */
