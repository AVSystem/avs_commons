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

#ifndef AVS_COMMONS_LIST_H
#define AVS_COMMONS_LIST_H

#include <stddef.h>
#include <stdint.h>

#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_memory.h>

/**
 * @file avs_list.h
 *
 * A generic singly linked list implementation.
 *
 * <example>
 * @code
 * #define _GNU_SOURCE // for asprintf()
 * #include <stdio.h>
 * #include <avsystem/commons/avs_list.h>
 *
 * typedef struct {
 *     int index;
 *     char *string;
 * } my_struct_t;
 *
 * int main() {
 *     // declare a list - just like that!
 *     AVS_LIST(my_struct_t) list = NULL;
 *
 *     // let's fill it!
 *     AVS_LIST(my_struct_t) *last_element = &list;
 *     for (int i = 0; i < 10; ++i) {
 *         // create a new list element
 *         *last_element = AVS_LIST_NEW_ELEMENT(my_struct_t);
 *         (*last_element)->index = i;
 *         asprintf(&(*last_element)->string, "This is list element %d", i);
 *
 *         // next element will be added after it
 *         last_element = &AVS_LIST_NEXT(*last_element);
 *     }
 *
 *     // print the contents
 *     my_struct_t *element;
 *     AVS_LIST_FOREACH(element, list) {
 *         printf("%d -- %s\n", element->index, element->string);
 *     }
 *
 *     // now free everything
 *     AVS_LIST_CLEAR(&list) {
 *         free(list->string);
 *     }
 * }
 * @endcode
 *
 * Another starting point for examples might be the testing code
 * (<c>test_list.c</c>).
 * </example>
 */

#if defined(AVS_LIST_CONFIG_ALLOC) || defined(AVS_LIST_CONFIG_FREE)
#    warning "AVS_LIST_CONFIG_ALLOC and AVS_LIST_CONFIG_FREE are no longer " \
         "supported, disable AVS_COMMONS_UTILS_WITH_STANDARD_ALLOCATOR instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Structure definition for padding helper macro.
 */
struct avs_list_space_for_next_helper_struct__ {
    void *next;
    avs_max_align_t value;
};

/**
 * Padding helper macro.
 *
 * The in-memory representation format of the list is as follows:
 *
 * <pre>
 *                                all pointers point here
 *                                |
 *                                v
 * +=================+===========+============================================+
 * | pointer to next | (padding) | element data                               |
 * +=================+===========+============================================+
 *  { AVS_LIST_SPACE_FOR_NEXT__ } {------------- arbitrary size -------------}
 *  { sizeof(void*) }
 * </pre>
 *
 * The <c>AVS_LIST_SPACE_FOR_NEXT__</c> macro calculates the space necessary
 * for the next element pointer with regard to the architecture's alignment
 * requirements. The padding shall be large enough so that the element data lay
 * on an address complying to strictest alignment requirements suitable for any
 * data type on the target architecture.
 *
 * The concept for calculating this size is based on the
 * @ref avs_list_space_for_next_helper_struct__ structure.
 */
#define AVS_LIST_SPACE_FOR_NEXT__ \
    offsetof(struct avs_list_space_for_next_helper_struct__, value)

/**
 * List type for a given element type.
 *
 * This is simply an alias for a pointer type. It is purely syntactic sugar,
 * allowing for semantic marking of list types in the code.
 *
 * Please also note that the value of <c>NULL</c> is a valid, empty list.
 *
 * @param element_type Type of the list element.
 */
#define AVS_LIST(element_type) element_type *

/**
 * Comparator type for @ref AVS_LIST_FIND_BY_VALUE_PTR and
 * @ref AVS_LIST_SORT.
 *
 * Standard library <c>memcmp</c> satisfies this type.
 *
 * @param a            The left element of comparison.
 *
 * @param b            The right element of comparison.
 *
 * @param element_size Size in bytes of compared elements.
 *
 * @return A negative value if <c>a &lt; b</c>, zero if <c>a == b</c> or
 *         a positive value if <c>a &gt; b</c>.
 */
typedef int (*avs_list_comparator_func_t)(const void *a,
                                          const void *b,
                                          size_t element_size);

/**
 * @name Internal functions
 *
 * These functions contain actual implementation of some of the list
 * functionality.
 *
 * They are wrapped in macros that offer additional layer of type safety if
 * <c>typeof</c> is available, so it is preferable to use them instead of these
 * functions directly.
 */
/**@{*/
void *avs_list_adjust_allocated_ptr__(void *allocated);
void *avs_list_nth__(void *list, size_t n);
void **avs_list_nth_ptr__(void **list_ptr, size_t n);
void **avs_list_find_ptr__(void **list_ptr, void *element);
void **avs_list_find_by_value_ptr__(void **list_ptr,
                                    void *value_ptr,
                                    avs_list_comparator_func_t comparator,
                                    size_t value_size);
void *avs_list_tail__(void *list);
void **avs_list_append_ptr__(void **list_ptr);
void *avs_list_append__(void *element, void **list_ptr);
void *avs_list_insert__(void *list_to_insert, void **insert_ptr);
void *avs_list_detach__(void **to_detach_ptr);
size_t avs_list_size__(const void *list);
void avs_list_sort__(void **list_ptr,
                     avs_list_comparator_func_t comparator,
                     size_t element_size);
int avs_list_is_cyclic__(const void *list);
void *avs_list_assert_acyclic__(void *list);
void **avs_list_assert_sorted_ptr__(void **list,
                                    avs_list_comparator_func_t comparator,
                                    size_t element_size);

void *avs_list_simple_clone__(void *list, size_t elem_size);
void avs_list_merge__(void **target_ptr,
                      void **source_ptr,
                      avs_list_comparator_func_t comparator,
                      size_t element_size);

static inline void *avs_list_void_identity__(void *arg) {
    return arg;
}

#ifdef NDEBUG
#    define AVS_LIST_ASSERT_ACYCLIC__(list) (list)
#    define AVS_LIST_ASSERT_SORTED_PTR__(list_ptr, comparator) (list_ptr)
#else
#    define AVS_LIST_ASSERT_ACYCLIC__(list) \
        AVS_CALL_WITH_CAST(0, avs_list_assert_acyclic__, (list))

#    define AVS_LIST_ASSERT_SORTED_PTR__(list_ptr, comparator)       \
        (avs_list_assert_sorted_ptr__((void **) (intptr_t) list_ptr, \
                                      comparator,                    \
                                      sizeof(**list_ptr)),           \
         list_ptr)
#endif
/**@}*/

#ifdef __cplusplus
} /* extern "C" */
#endif

/**
 * Returns a pointer to the next element.
 *
 * The entity returned is syntactically an lvalue.
 *
 * @param element Pointer to a list element.
 *
 * @return Pointer to the next list element.
 */
#ifdef __cplusplus
template <typename T>
static inline AVS_LIST(T) &avs_list_next__(AVS_LIST(T) element) {
    return *AVS_APPLY_OFFSET(AVS_LIST(T), element, -AVS_LIST_SPACE_FOR_NEXT__);
}

#    define AVS_LIST_NEXT(element) (avs_list_next__((element)))
#else
#    define AVS_LIST_NEXT(element) \
        (*AVS_APPLY_OFFSET(        \
                AVS_TYPEOF_PTR(element), element, -AVS_LIST_SPACE_FOR_NEXT__))
#endif

/**
 * Returns a pointer to the variable holding the pointer to the next element.
 *
 * @param element_ptr Pointer to a variable holding a pointer to a list element.
 *
 * @return Pointer to a variable in the list element holding a pointer to the
 *         next element.
 */
#define AVS_LIST_NEXT_PTR(element_ptr) (&AVS_LIST_NEXT(*(element_ptr)))

/**
 * Advances the @p element_ptr to point to the next element of the list.
 *
 * Using <c>AVS_LIST_ADVANCE(&list)</c> is semantically equvialent to
 * <c>list = AVS_LIST_NEXT(list)</c>. The difference is that AVS_LIST_ADVANCE
 * will always work on compilers without typeof() support, because it performs
 * appropriate casts underneath.
 *
 * @param element_ptr   Pointer to the list element which should be modified to
 *                      point to the next list element.
 */
#define AVS_LIST_ADVANCE(element_ptr)                           \
    do {                                                        \
        AVS_TYPEOF_PTR(*(element_ptr)) *curr_ptr =              \
                (AVS_TYPEOF_PTR(*(element_ptr)) *) element_ptr; \
        *curr_ptr = AVS_LIST_NEXT(*curr_ptr);                   \
    } while (0)

/**
 * Advances the @p element_ptr_ptr to point to the pointer to the next element
 * of the list.
 *
 * Using <c>AVS_LIST_ADVANCE_PTR(&list_ptr)</c> is semantically equivalent to
 * <c>list_ptr = AVS_LIST_NEXT_PTR(list_ptr)</c>. The difference is that
 * AVS_LIST_ADVANCE_PTR will always work on compilers without typeof() support,
 * because it performs appropriate casts underneath.
 *
 * @param element_ptr_ptr   Pointer to the pointer to the list element which
 *                          should be modified to point to the pointer to the
 *                          next list element.
 */
#define AVS_LIST_ADVANCE_PTR(element_ptr_ptr)                             \
    do {                                                                  \
        AVS_TYPEOF_PTR(**(element_ptr_ptr)) **curr_ptr_ptr =              \
                (AVS_TYPEOF_PTR(**(element_ptr_ptr)) **) element_ptr_ptr; \
        *curr_ptr_ptr = AVS_LIST_NEXT_PTR(*curr_ptr_ptr);                 \
    } while (0)

/**
 * A shorthand notation for a for-each loop.
 *
 * It is a wrapper around a standard <c>for</c> clause, so all standard features
 * like <c>break</c> and <c>continue</c> will work as expected.
 *
 * <example>
 * The following code prints the contents of a list of <c>int</c>s.
 *
 * @code
 * AVS_LIST(int) list;
 * // ...
 * int *element;
 * AVS_LIST_FOREACH(element, list) {
 *     printf("%d\n", *element);
 * }
 * @endcode
 * </example>
 *
 * @param element Iterator variable. Will be assigned pointers to consecutive
 *                list elements with each iteration.
 *
 * @param list    Pointer to a first element in a list.
 */
#define AVS_LIST_FOREACH(element, list) \
    for ((element) = (list); (element); (element) = AVS_LIST_NEXT(element))

/**
 * Iterates over a list, starting with the current element.
 *
 * It is semantically equivalent to <c>AVS_LIST_FOREACH(element, element)</c>.
 *
 * @param element Pointer to an element in a list. Will be assigned consecutive
 *                elements during iteration.
 */
#define AVS_LIST_ITERATE(element) \
    for (; (element); (element) = AVS_LIST_NEXT(element))

/**
 * A for-each loop over pointers to element pointers.
 *
 * This is similar to @ref AVS_LIST_FOREACH, but the iterator is assigned
 * pointers to variables holding pointers to elements. This may be useful for
 * e.g. inserting elements during iteration.
 *
 * <example>
 * The following code inserts a 4 element before each 5 element in a list of
 * <c>int</c>s.
 *
 * @code
 * AVS_LIST(int) list;
 * // ...
 * AVS_LIST(int) *element_ptr;
 * AVS_LIST_FOREACH_PTR(element_ptr, &list) {
 *     if (**element_ptr == 5) {
 *         AVS_LIST_INSERT_NEW(int, element_ptr);
 *         **element_ptr = 4;
 *         // skip the new element to avoid infinite loop
 *         element_ptr = AVS_LIST_NEXT_PTR(element_ptr);
 *     }
 * }
 * @endcode
 * </example>
 *
 * @param element_ptr Iterator variable. Will be assigned pointers to variables
 *                    holding pointers to consecutive list elements with each
 *                    iteration.
 *
 * @param list_ptr    Pointer to a list variable.
 */
#define AVS_LIST_FOREACH_PTR(element_ptr, list_ptr)  \
    for ((element_ptr) = (list_ptr); *(element_ptr); \
         (element_ptr) = AVS_CALL_WITH_CAST(         \
                 0, avs_list_void_identity__, AVS_LIST_NEXT_PTR(element_ptr)))

/**
 * Iterates over a list as pointers to element pointers, starting with the
 * current element.
 *
 * It is semantically equivalent to
 * <c>AVS_LIST_FOREACH_PTR(element_ptr, element_ptr)</c>.
 *
 * @param element_ptr Pointer to a variable holding a pointer to an element in a
 *                    list. Will be assigned pointers to variables holding
 *                    pointers to consecutive list elements during iteration.
 */
#define AVS_LIST_ITERATE_PTR(element_ptr)    \
    for (; *(element_ptr);                   \
         (element_ptr) = AVS_CALL_WITH_CAST( \
                 0, avs_list_void_identity__, AVS_LIST_NEXT_PTR(element_ptr)))

/**
 * Returns a pointer to <i>n</i>-th element in a list.
 *
 * @param list Pointer to a first element in a list.
 *
 * @param n    Index of a desired element to return, with 0 being the first.
 *
 * @return Pointer to the desired element, or <c>NULL</c> if not found.
 */
#define AVS_LIST_NTH(list, n) AVS_CALL_WITH_CAST(0, avs_list_nth__, (list), (n))

/**
 * Returns a pointer to a variable holding the <i>n</i>-th element in a list.
 *
 * @param list_ptr Pointer to a list variable.
 *
 * @param n        Index of a desired element to return, with 0 being the first.
 *
 * @return Pointer to a variable holding a pointer to the desired element, or
 *         <c>NULL</c> if not found.
 */
#define AVS_LIST_NTH_PTR(list_ptr, n) \
    AVS_CALL_WITH_CAST(1, avs_list_nth_ptr__, (list_ptr), (n))

/**
 * Looks for a given element in the list and returns a pointer to the variable
 * holding it.
 *
 * <example>
 * The following function removes an element given by single pointer from a
 * list.
 *
 * @code
 * void remove_element(AVS_LIST(int) *list_ptr, int *element) {
 *     AVS_LIST(int) *element_ptr = AVS_LIST_FIND_PTR(list_ptr, element);
 *     if (element_ptr) {
 *         AVS_LIST_DELETE(element_ptr);
 *     }
 * }
 * @endcode
 * </example>
 *
 * @param list_ptr Pointer to a list variable.
 *
 * @param element  Pointer to the element to find.
 *
 * @return Pointer to a variable holding a pointer to the desired element, or
 *         <c>NULL</c> if not found.
 */
#define AVS_LIST_FIND_PTR(list_ptr, element) \
    AVS_CALL_WITH_CAST(                      \
            1, avs_list_find_ptr__, (list_ptr), (char *) (intptr_t) (element))

/**
 * Looks for an element in the list, given its literal value, and returns a
 * pointer to the variable holding it.
 *
 * <example>
 * The following code finds the first element with a value of 5 in a list of
 * <c>int</c>s.
 *
 * @code
 * AVS_LIST(int) list;
 * // ...
 * int search_term = 5;
 * AVS_LIST(int) *first_found = AVS_LIST_FIND_BY_VALUE_PTR(&list, &search_term,
 *                                                         memcmp);
 * @endcode
 * </example>
 *
 * @param list_ptr   Pointer to a list variable.
 *
 * @param value_ptr  Pointer to the search term value.
 *
 * @param comparator Comparator function of type
 *                   @ref avs_list_comparator_func_t. <c>sizeof(*value_ptr)</c>
 *                   will be used as the <c>element_size</c> argument.
 *
 * @return Pointer to a variable holding a pointer to the first matching element
 *         found, or <c>NULL</c> if not found.
 */
#define AVS_LIST_FIND_BY_VALUE_PTR(list_ptr, value_ptr, comparator) \
    AVS_CALL_WITH_CAST(1,                                           \
                       avs_list_find_by_value_ptr__,                \
                       (list_ptr),                                  \
                       (void *) (intptr_t) (value_ptr),             \
                       (comparator),                                \
                       sizeof(*(value_ptr)))

/**
 * Returns the last element in a list.
 *
 * @param list Pointer to the first element in a list.
 *
 * @return Pointer to the last element in a list, or <c>NULL</c> if the list is
 *         empty.
 */
#define AVS_LIST_TAIL(list) AVS_CALL_WITH_CAST(0, avs_list_tail__, (list))

/**
 * Returns the next element pointer of last element in a list.
 *
 * For non-empty lists, it is semantically equivalent to
 * <c>&AVS_LIST_NEXT(AVS_LIST_TAIL(*list_ptr))</c>.
 *
 * @param list_ptr Pointer to a list variable.
 *
 * @return Pointer to a variable, writing to which will append an element to the
 *         end of the list. Note that the returned value, when dereferenced,
 *         will always yield <c>NULL</c>.
 */
#define AVS_LIST_APPEND_PTR(list_ptr) \
    AVS_CALL_WITH_CAST(1, avs_list_append_ptr__, (list_ptr))

/**
 * Allocates a new list element with an arbitrary size.
 *
 * Invokes @ref avs_calloc() with the desired size increased by the
 * space necessary for the next pointer, and returns the pointer to user data.
 *
 * @param size Number of bytes to allocate for user data.
 *
 * @return Newly allocated list element, as <c>void *</c>.
 */
#define AVS_LIST_NEW_BUFFER(size)     \
    (avs_list_adjust_allocated_ptr__( \
            avs_calloc(1, (AVS_LIST_SPACE_FOR_NEXT__ + (size)))))

/**
 * Allocates a new list element of a given type.
 *
 * It is semantically equivalent to <c>AVS_LIST_NEW_BUFFER(sizeof(type))</c>.
 *
 * @param type Type of user data to allocate.
 *
 * @return Newly allocated list element, as <c>type *</c>.
 */
#define AVS_LIST_NEW_ELEMENT(type) ((type *) AVS_LIST_NEW_BUFFER(sizeof(type)))

/**
 * Inserts an element or a list into the list.
 *
 * Note that if <c>NDEBUG</c> is not defined at the point of including this
 * header file, this macro will contain an assertion that checks if the
 * resulting list is acyclic, which runs in O(n) time complexity. Otherwise
 * it runs in O(1).
 *
 * @param destination_element_ptr Pointer to a variable holding a pointer to the
 *                                element (which may be null) before which to
 *                                insert the new element. The variable value
 *                                will be updated with the newly added element.
 *
 * @param new_element             The element to insert.
 *
 *                                If it has subsequent elements (i.e. is already
 *                                a list), they will be preserved, and the part
 *                                of the list previously held at
 *                                <c>destination_element_ptr</c> will be
 *                                appended after element at <c>new_element</c>.
 *
 *                                Note that <c>NULL</c> is a valid list
 *                                containing zero elements, so passing
 *                                <c>NULL</c> as <c>new_elements</c> is
 *                                essentially a no-op.
 *
 * @return The inserted element, i.e. <c>new_element</c>. If <c>new_element</c>
 *         is <c>NULL</c>, the return value will also be <c>NULL</c>.
 */
#define AVS_LIST_INSERT(destination_element_ptr, new_element)      \
    ((((void) sizeof(*(destination_element_ptr) = (new_element))), \
      AVS_LIST_ASSERT_ACYCLIC__(AVS_CALL_WITH_CAST(                \
              0,                                                   \
              avs_list_insert__,                                   \
              (new_element),                                       \
              (void **) (intptr_t) (destination_element_ptr)))))

/**
 * Allocates a new element and inserts it into the list.
 *
 * It is semantically equivalent to
 * <c>AVS_LIST_INSERT(destination_element_ptr, AVS_LIST_NEW_ELEMENT(type))</c>.
 *
 * Note that if <c>NDEBUG</c> is not defined at the point of including this
 * header file, this macro will contain an assertion that checks if the
 * resulting list is acyclic, which runs in O(n) time complexity. Otherwise
 * it runs in O(1).
 *
 * @param type                    Type of user data to allocate.
 *
 * @param destination_element_ptr Pointer to a variable holding a pointer to the
 *                                element (which may be null) before which to
 *                                insert the new element. The variable value
 *                                will be updated with the newly added element.
 *
 * @return Pointer to the created and inserted element, or <c>NULL</c> in case
 *         of error.
 */
#define AVS_LIST_INSERT_NEW(type, destination_element_ptr) \
    AVS_LIST_INSERT(destination_element_ptr, AVS_LIST_NEW_ELEMENT(type))

/**
 * Appends an element or a list at the end of a list.
 *
 * @param list_ptr    Pointer to a list variable.
 *
 * @param new_element An element to append. If it has subsequent elements (i.e.
 *                    is already a list), they will be preserved, actually
 *                    concatenating two lists.
 */
#define AVS_LIST_APPEND(list_ptr, new_element)      \
    ((((void) sizeof(*(list_ptr) = (new_element))), \
      AVS_LIST_ASSERT_ACYCLIC__(                    \
              AVS_CALL_WITH_CAST(0,                 \
                                 avs_list_append__, \
                                 (new_element),     \
                                 (void **) (intptr_t) (list_ptr)))))

/**
 * Allocates a new element and appends at the end of a list.
 *
 * It is semantically equivalent to
 * <c>AVS_LIST_APPEND(list_ptr, AVS_LIST_NEW_ELEMENT(type))</c>.
 *
 * @param type     Type of user data to allocate.
 *
 * @param list_ptr Pointer to a list variable.
 *
 * @return Pointer to the created and inserted element, or <c>NULL</c> in case
 *         of error.
 */
#define AVS_LIST_APPEND_NEW(type, list_ptr) \
    AVS_LIST_APPEND(list_ptr, AVS_LIST_NEW_ELEMENT(type))

/**
 * Detaches an element from a list.
 *
 * @param element_to_detach_ptr Pointer to a variable on a list holding a
 *                              pointer to the element to detach.
 *
 * @return Pointer to the detached element, that has been removed from the list
 *         originally containing it, and is now a self-contained element with
 *         the <i>next</i> pointer guaranteed to be <c>NULL</c>.
 */
/* additional casts through char * work around aliasing rules */
#ifdef __cplusplus
template <typename T>
static inline AVS_LIST(T)
avs_list_detach_impl__(AVS_LIST(T) *element_to_detach_ptr) {
    return (AVS_LIST(T)) (char *) avs_list_detach__(
            (void **) (intptr_t) (const char *) element_to_detach_ptr);
}

#    define AVS_LIST_DETACH(element_to_detach_ptr) \
        (avs_list_detach_impl__((element_to_detach_ptr)))
#else
#    define AVS_LIST_DETACH(element_to_detach_ptr)                             \
        ((AVS_TYPEOF_PTR(*(element_to_detach_ptr)))(char *) avs_list_detach__( \
                (void **) (intptr_t) (const char *) (element_to_detach_ptr)))
#endif

/**
 * Deallocates memory claimed by a list element, detaching it beforehand.
 *
 * @param element_to_delete_ptr Pointer to a variable on a list holding a
 *                              pointer to the element to destroy.
 */
#define AVS_LIST_DELETE(element_to_delete_ptr)                              \
    avs_free(((char *) (intptr_t) (AVS_LIST_DETACH(element_to_delete_ptr))) \
             - AVS_LIST_SPACE_FOR_NEXT__)

/**
 * Checks whether the element has not been deleted during
 * @ref AVS_LIST_DELETABLE_FOREACH_PTR.
 *
 * @param element_ptr    Variable passed as <c>element_ptr</c> to
 *                       @ref AVS_LIST_DELETABLE_FOREACH_PTR.
 *
 * @param helper_element Variable passed as <c>helper_element</c> to
 *                       @ref AVS_LIST_DELETABLE_FOREACH_PTR.
 *
 * @return True, unless <c>element_ptr</c> has been deleted.
 */
#define AVS_LIST_DELETABLE_FOREACH_PTR_VALID(element_ptr, helper_element) \
    ((helper_element) == *(element_ptr))

/**
 * A for-each loop that allows deleting elements during iteration.
 *
 * This is similar to @ref AVS_LIST_FOREACH_PTR, but elements may be detached
 * or deleted during iteration.
 *
 * <example>
 * The following code deletes all elements with a value of 5 from a list of
 * <c>int</c>s.
 *
 * @code
 * AVS_LIST(int) list;
 * // ...
 * AVS_LIST(int) *element_ptr;
 * AVS_LIST(int) helper;
 * AVS_LIST_DELETABLE_FOREACH_PTR(element_ptr, helper, &list) {
 *     if (**element_ptr == 5) {
 *         AVS_LIST_DELETE(element_ptr);
 *     }
 * }
 * @endcode
 * </example>
 *
 * @param element_ptr    Iterator variable. Will be assigned pointers to
 *                       variables holding pointers to consecutive list elements
 *                       with each iteration.
 *
 * @param helper_element Helper variable (of element pointer type - not pointer
 *                       to variable holding pointer to element, as in the case
 *                       of <c>element_ptr</c>), used internally by the
 *                       iteration algorithm. <strong>It shall not be modified
 *                       by user code.</strong>
 *
 * @param list_ptr       Pointer to a list variable.
 */
#define AVS_LIST_DELETABLE_FOREACH_PTR(element_ptr, helper_element, list_ptr) \
    for ((element_ptr) = (list_ptr), (helper_element) = *(element_ptr);       \
         *(element_ptr);                                                      \
         (element_ptr) =                                                      \
                 AVS_LIST_DELETABLE_FOREACH_PTR_VALID(element_ptr,            \
                                                      helper_element)         \
                         ? AVS_CALL_WITH_CAST(0,                              \
                                              avs_list_void_identity__,       \
                                              AVS_LIST_NEXT_PTR(element_ptr)) \
                         : (element_ptr),                                     \
        (helper_element) = *(element_ptr))

/**
 * Deallocates all list elements.
 *
 * It can be used as a normal statement if no additional freeing code is
 * necessary.
 *
 * Alternatively a block of code can follow it, that can do additional cleanup -
 * the first element of the list at the moment of execution is to be considered.
 *
 * <example>
 * Example usage of the long form:
 *
 * @code
 * typedef struct {
 *     int *some_data;
 *     double *some_other_data;
 * } complicated_structure_t;
 * AVS_LIST(complicated_structure_t) list;
 * // ...
 * AVS_LIST_CLEAR(&list) {
 *     free(list->some_data);
 *     free(list->some_other_data);
 * }
 * @endcode
 * </example>
 *
 * @param first_element_ptr Pointer to a list variable.
 */
#define AVS_LIST_CLEAR(first_element_ptr) \
    for (; *(first_element_ptr); AVS_LIST_DELETE(first_element_ptr))

/**
 * Returns the number of elements on the list.
 *
 * Note that if <c>NDEBUG</c> is not defined at the point of including this
 * header file, this macro will contain an assertion that checks if the list is
 * acyclic before calculating the size.
 *
 * @param list Pointer to the first element of a list.
 *
 * @return Number of elements on the list.
 */
#define AVS_LIST_SIZE(list) avs_list_size__(AVS_LIST_ASSERT_ACYCLIC__(list))

/**
 * Sorts the list elements, ascending by the ordering enforced by the specified
 * comparator.
 *
 * The sorting is performed using the recursive merge sort algorithm.
 *
 * The sort is guaranteed to be stable - in case of elements that compare equal,
 * their relative order is preserved.
 *
 * @param list_ptr   Pointer to a list variable.
 *
 * @param comparator Comparator function of type
 *                   @ref avs_list_comparator_func_t. <c>sizeof(**list_ptr)</c>
 *                   will be used as the <c>element_size</c> argument.
 */
#define AVS_LIST_SORT(list_ptr, comparator)          \
    avs_list_sort__((void **) (intptr_t) (list_ptr), \
                    (comparator),                    \
                    sizeof(**(list_ptr)))

/**
 * @def AVS_LIST_IS_CYCLIC(list)
 *
 * Checks whether the list contains cycles.
 *
 * @param list Pointer to the first element of a list.
 *
 * @return 1 if the list contains cycles, 0 otherwise.
 */
#define AVS_LIST_IS_CYCLIC avs_list_is_cyclic__

/**
 * Clones the list by copying every element naively.
 *
 * WARNING: This function WILL NOT WORK as expected on lists that contain
 * variable length data. It is safe to use only if list constists fixed-size
 * datatypes. Data type of the list argument (@p list) must reflect the actual
 * type of the data held in that list.
 *
 * @return pointer to the cloned list, NULL in case of an error.
 */
#define AVS_LIST_SIMPLE_CLONE(list)                     \
    AVS_CALL_WITH_CAST(0,                               \
                       avs_list_simple_clone__,         \
                       AVS_LIST_ASSERT_ACYCLIC__(list), \
                       sizeof(*(list)))

/**
 * Merges two sorted lists @p target_ptr and @p source_ptr, writing the results
 * into @p target_ptr list, and leaving @p source_ptr list empty in the end.
 *
 * The merge is guranteed to be stable - in case of elements that compare equal,
 * elements pre-existing in @p target_ptr will appear before elements moved from
 * @p source_ptr.
 *
 * WARNING: If at least one of the lists is not sorted (according to the
 * ordering established by @p comparator) then the behavior is undefined.
 *
 * @param target_ptr    Pointer to a list where the result will be stored.
 * @param source_ptr    Pointer to a list which shall be merged with @p
 * target_ptr.
 * @param comparator    Comparator function of type
 *                      @ref avs_list_comparator_func_t.
 * <c>sizeof(**target_ptr)</c> will be used as the <c>element_size</c> argument.
 */
#define AVS_LIST_MERGE(target_ptr, source_ptr, comparator)              \
    avs_list_merge__((void **) (intptr_t) AVS_LIST_ASSERT_SORTED_PTR__( \
                             target_ptr, comparator),                   \
                     (void **) (intptr_t) AVS_LIST_ASSERT_SORTED_PTR__( \
                             source_ptr, comparator),                   \
                     (comparator),                                      \
                     sizeof(**(target_ptr)));

#endif /* AVS_COMMONS_LIST_H */
