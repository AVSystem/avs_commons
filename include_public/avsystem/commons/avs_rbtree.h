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

#ifndef AVS_COMMONS_RBTREE_INCLUDE_PUBLIC_COMMONS_RBTREE_H
#define AVS_COMMONS_RBTREE_INCLUDE_PUBLIC_COMMONS_RBTREE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/avs_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RB-tree element comparator.
 *
 * @param a    First element. Note that the comparator must be aware of actual
 *             type of compared elements.
 * @param b    Second element.
 *
 * @returns:
 * - a negative value if @p a < @p b,
 * - 0 if @p a == @p b,
 * - a positive value if @p a > @p b.
 *
 * WARNING: The comparator MUST establish a total ordering of RB-tree elements.
 * Moreover, element components used to establish an ordering MUST be immutable
 * for the whole lifetime of an RB-tree, otherwise the behavior of operations on
 * the tree is undefined.
 *
 * NOTE: Since a comparator may use only a fragment of the RB-tree element, it
 * is possible to implement a map (dictionary) by storing a { key; value }
 * struct in each tree element and comparing them by key.
 */
typedef int avs_rbtree_element_comparator_t(const void *a, const void *b);

/** RB-tree type alias.  */
#define AVS_RBTREE(type) type **
/** Constant RB-tree type alias.  */
#define AVS_RBTREE_CONST(type) const type *const *
/** RB element type alias. */
#define AVS_RBTREE_ELEM(type) type *

/* Internal functions. Use macros defined above instead. */
AVS_RBTREE(void) avs_rbtree_new__(avs_rbtree_element_comparator_t *cmp);
void avs_rbtree_delete__(AVS_RBTREE(void) *tree);
AVS_RBTREE(void) avs_rbtree_simple_clone__(AVS_RBTREE_CONST(void) tree,
                                           size_t elem_size);

size_t avs_rbtree_size__(AVS_RBTREE_CONST(void) tree);
AVS_RBTREE_ELEM(void) avs_rbtree_lower_bound__(AVS_RBTREE_CONST(void) tree,
                                               const void *value);
AVS_RBTREE_ELEM(void) avs_rbtree_upper_bound__(AVS_RBTREE_CONST(void) tree,
                                               const void *value);
AVS_RBTREE_ELEM(void) avs_rbtree_find__(AVS_RBTREE_CONST(void) tree,
                                        const void *value);
AVS_RBTREE_ELEM(void) avs_rbtree_attach__(AVS_RBTREE(void) tree,
                                          AVS_RBTREE_ELEM(void) node);
AVS_RBTREE_ELEM(void) avs_rbtree_detach__(AVS_RBTREE(void) tree,
                                          AVS_RBTREE_ELEM(void) node);

AVS_RBTREE_ELEM(void) avs_rbtree_first__(AVS_RBTREE(void) tree);
AVS_RBTREE_ELEM(void) avs_rbtree_last__(AVS_RBTREE(void) tree);

AVS_RBTREE_ELEM(void) avs_rbtree_elem_new_buffer__(size_t elem_size);
void avs_rbtree_elem_delete__(AVS_RBTREE_ELEM(void) *node);

AVS_RBTREE_ELEM(void) avs_rbtree_elem_next__(AVS_RBTREE_ELEM(void) elem);
AVS_RBTREE_ELEM(void) avs_rbtree_elem_prev__(AVS_RBTREE_ELEM(void) elem);

AVS_RBTREE_ELEM(void) avs_rbtree_cleanup_first__(AVS_RBTREE(void) tree);
AVS_RBTREE_ELEM(void) avs_rbtree_cleanup_next__(AVS_RBTREE(void) tree);

#ifdef __cplusplus
} /* extern "C" */
#endif

#define _AVS_RB_TYPECHECK(first_ptr_type, second_ptr_type) \
    ((void) (sizeof((first_ptr_type) < (second_ptr_type))))

/**
 * Create an RB-tree with elements of given @p type.
 *
 * Complexity: O(m), where:
 * - m - avs_calloc() complexity.
 *
 * @param type Type of elements stored in the tree nodes.
 * @param cmp  Pointer to a function that compares two elements.
 *             See @ref avs_rbtree_element_comparator_t .
 *
 * @returns Created RB-tree object on success, NULL in case of error.
 */
#define AVS_RBTREE_NEW(type, cmp) ((AVS_RBTREE(type)) avs_rbtree_new__(cmp))

#ifdef __cplusplus
template <typename T>
static inline AVS_RBTREE_ELEM(T)
AVS_RBTREE_CLEANUP_FIRST__(AVS_RBTREE(T) tree) {
    return (AVS_RBTREE_ELEM(T)) avs_rbtree_cleanup_first__(
            (AVS_RBTREE(void)) tree);
}

template <typename T>
static inline AVS_RBTREE_ELEM(T) AVS_RBTREE_CLEANUP_NEXT__(AVS_RBTREE(T) tree) {
    return (AVS_RBTREE_ELEM(T)) avs_rbtree_cleanup_next__(
            (AVS_RBTREE(void)) tree);
}

template <typename Func, typename T>
static inline AVS_RBTREE_ELEM(T)
AVS_RBTREE_CALL_WITH_ELEM_CAST__(const Func &func, AVS_RBTREE(T) tree) {
    return (AVS_RBTREE_ELEM(T)) func((AVS_RBTREE(void)) tree);
}

template <typename Func, typename T, typename Arg>
static inline AVS_RBTREE_ELEM(T) AVS_RBTREE_CALL_WITH_ELEM_CAST__(
        const Func &func, AVS_RBTREE(T) tree, const Arg &arg) {
    return (AVS_RBTREE_ELEM(T)) func((AVS_RBTREE(void)) tree, arg);
}

template <typename Func, typename T, typename Arg>
static inline AVS_RBTREE_ELEM(T) AVS_RBTREE_CALL_WITH_CONST_ELEM_CAST__(
        const Func &func, AVS_RBTREE_CONST(T) tree, const Arg &arg) {
    return (AVS_RBTREE_ELEM(T)) func((AVS_RBTREE_CONST(void)) tree, arg);
}
#else
#    define AVS_RBTREE_CLEANUP_FIRST__(tree) \
        (AVS_TYPEOF_PTR(*(tree)))            \
                avs_rbtree_cleanup_first__((AVS_RBTREE(void)) (tree))
#    define AVS_RBTREE_CLEANUP_NEXT__(tree) \
        (AVS_TYPEOF_PTR(*(tree)))           \
                avs_rbtree_cleanup_next__((AVS_RBTREE(void)) (tree))
#    define AVS_RBTREE_CALL_WITH_ELEM_CAST__(func, ...)      \
        ((AVS_TYPEOF_PTR(*(AVS_VARARG0(__VA_ARGS__)))) func( \
                (AVS_RBTREE(void)) __VA_ARGS__))
#    define AVS_RBTREE_CALL_WITH_CONST_ELEM_CAST__(func, ...) \
        ((AVS_TYPEOF_PTR(*(AVS_VARARG0(__VA_ARGS__)))) func(  \
                (AVS_RBTREE_CONST(void)) __VA_ARGS__))
#endif

/**
 * Releases all nodes in RB-tree, making it empty.
 *
 * Complexity: O(n * f), where:
 * - n - number of nodes in @p tree,
 * - f - avs_free() complexity.
 *
 * Example usage:
 *
 * @code
 * // simple cleanup - no extra operations required for elements
 * AVS_RBTREE(int) ints = ...;
 * AVS_RBTREE_CLEAR(ints);
 *
 * // cleanup with extra operation before releasing each element:
 * AVS_RBTREE(char *) strings = ...;
 * AVS_RBTREE_CLEAR(strings) {
 *     avs_free(**strings);
 * }
 * @endcode
 *
 * WARNING: during cleanup the tree is NOT in an consistent state. Attempting
 * any kind of tree operations while AVS_RBTREE_CLEAR or AVS_RBTREE_DELETE on
 * that tree is in progress invokes undefined behavior.
 *
 * WARNING: <c>break;</c> from the AVS_RBTREE_CLEAR loop leaves the tree in an
 * invalid state. One can resume cleanup using AVS_RBTREE_CLEAR or
 * AVS_RBTREE_DELETE again, but any other operations cause undefined behavior.
 * In case of resumption, iteration starts from the element which previously
 * triggered the <c>break;</c>.
 *
 * @param tree RB-tree object to make empty. The next element to be released can
 *             be accessed using <c>*tree</c>.
 */
#define AVS_RBTREE_CLEAR(tree)                                \
    for (*(tree) = AVS_RBTREE_CLEANUP_FIRST__(tree); *(tree); \
         *(tree) = AVS_RBTREE_CLEANUP_NEXT__(tree))

/**
 * Releases given RB-tree and all its nodes.
 *
 * Complexity: O(n * f), where:
 * - n - number of nodes in @p tree_ptr,
 * - f - avs_free() complexity.
 *
 * Example usage:
 *
 * @code
 * // simple destruction - no extra operations required for elements
 * AVS_RBTREE(int) ints = ...;
 * AVS_RBTREE_DELETE(&ints);
 *
 * // destruction with extra operation before releasing each element:
 * AVS_RBTREE(char *) strings = ...;
 * AVS_RBTREE_DELETE(&strings) {
 *     avs_free(**strings);
 * }
 * @endcode
 *
 * WARNING: during cleanup the tree is NOT in an consistent state. Attempting
 * any kind of tree operations while AVS_RBTREE_CLEAR or AVS_RBTREE_DELETE on
 * that tree is in progress invokes undefined behavior.
 *
 * WARNING: <c>break;</c> from the AVS_RBTREE_DELETE loop leaves the tree in an
 * invalid state. One can resume cleanup using AVS_RBTREE_CLEAR or
 * AVS_RBTREE_DELETE again, but any other operations cause undefined behavior.
 * In case of resumption, iteration starts from the element which previously
 * triggered the <c>break;</c>.
 *
 * @param tree_ptr Pointer to the RB-tree object to destroy. *tree_ptr is set to
 *                 NULL after the cleanup is done. The next element to be
 *                 released can be accessed using <c>**tree</c>.
 */
#define AVS_RBTREE_DELETE(tree_ptr)                                        \
    if (!*(tree_ptr))                                                      \
        ;                                                                  \
    else                                                                   \
        for (**(tree_ptr) = AVS_RBTREE_CLEANUP_FIRST__(*(tree_ptr));       \
             **(tree_ptr)                                                  \
             || (avs_rbtree_delete__((AVS_RBTREE(void) *) (tree_ptr)), 0); \
             **(tree_ptr) = AVS_RBTREE_CLEANUP_NEXT__(*(tree_ptr)))

/**
 * Clones the tree by copying every element naively.
 *
 * Complexity: O(n * m), where:
 * - n - number of nodes in @p tree,
 * - m - avs_calloc() complexity.
 *
 * WARNING: This function WILL NOT WORK as expected on trees that contain
 * variable length data. It is safe to use only if tree constists fixed-size
 * datatypes. Data type of the tree argument (@p tree) must reflect the actual
 * type of the data held in tree elements.
 *
 * @param tree RB-tree object to clone.
 *
 * @returns Cloned RB-tree object on success, NULL in case of error.
 */
#ifdef __cplusplus
template <typename T>
static inline AVS_RBTREE(T) avs_rbtree_simple_clone_impl__(AVS_RBTREE_CONST(T)
                                                                   tree) {
    return (AVS_RBTREE(T)) avs_rbtree_simple_clone__(
            (AVS_RBTREE_CONST(void)) tree, sizeof(T));
}

#    define AVS_RBTREE_SIMPLE_CLONE(tree) \
        (avs_rbtree_simple_clone_impl__((tree)))
#else
#    define AVS_RBTREE_SIMPLE_CLONE(tree)                       \
        ((AVS_TYPEOF_PTR(*(tree)) *) avs_rbtree_simple_clone__( \
                (AVS_RBTREE_CONST(void))(tree), sizeof(**(tree))))
#endif

/**
 * Complexity: O(1).
 *
 * @param tree RB-tree object to operate on.
 *
 * @returns Total number of elements stored in the tree.
 */
#define AVS_RBTREE_SIZE(tree) avs_rbtree_size__((AVS_RBTREE_CONST(void))(tree))

/**
 * Creates an arbitrarily-sized, detached RB-tree element.
 *
 * Complexity: O(m), where:
 * - m - avs_calloc() complexity.
 *
 * Example:
 * @code
 * struct string {
 *     size_t size;
 *     char c_str[]; // C99 flexible array member
 * };
 *
 * const size_t STRING_CAPACITY = 64;
 *
 * AVS_RBTREE_ELEM(struct string) node = (AVS_RBTREE_ELEM(struct string))
 *     AVS_RBTREE_ELEM_NEW_BUFFER(sizeof(struct string) + STRING_CAPACITY);
 * // allocated string is able to hold STRING_CAPACITY characters in its c_str
 * // member array
 * @endcode
 *
 * NOTE: the in-memory representation of a node is as follows:
 * <pre>
 *                                     element pointers point here
 *                                     |
 *                                     v
 * +========+========+========+========+======================================+
 * |  color | parent |  left  |  right | element value                        |
 * +========+========+========+========+======================================+
 *  { sizeof(int) + 3 * sizeof(void)  } { -------- arbitrary size ---------- }
 *  {           (+ padding)           }
 *
 * </pre>
 *
 * @param size Number of bytes to allocate for the element content.
 *
 * @returns Pointer to created element on success, NULL in case of error.
 */
#define AVS_RBTREE_ELEM_NEW_BUFFER(size) avs_rbtree_elem_new_buffer__(size)

/**
 * Creates a detached RB-tree element large enough to hold a value of
 * given @p type.
 *
 * Complexity: O(m), where:
 * - m - avs_calloc() complexity.
 *
 * @param type Desired element type.
 *
 * @returns Pointer to created element cast to @p type * on success,
 *          NULL in case of error.
 */
#define AVS_RBTREE_ELEM_NEW(type) \
    ((AVS_RBTREE_ELEM(type)) AVS_RBTREE_ELEM_NEW_BUFFER(sizeof(type)))

/**
 * Frees memory associated with given detached RB-tree element.
 *
 * NOTE: when passed @p elem is attached to some tree, the behavior
 * is undefined.
 *
 * Complexity: O(f), where:
 * - f - avs_free() complexity.
 *
 * @param elem_ptr Pointer to element to free. *elem is set to NULL after
 *                 cleanup.
 */
#define AVS_RBTREE_ELEM_DELETE_DETACHED(elem_ptr) \
    avs_rbtree_elem_delete__((AVS_RBTREE_ELEM(void) *) (elem_ptr))

/**
 * Inserts a detached @p elem into given @p tree, if an element
 * equivalent to @p elem (wrt. @ref avs_rbtree_element_comparator_t
 * of @p tree) does not yet exist in the tree.
 *
 * NOTE: when passed @p elem is attached to some tree, the behavior
 * is undefined.
 *
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @param tree Tree to insert element into.
 * @param elem Element to insert.
 *
 * @returns:
 * - @p elem on success,
 * - a pointer to the equivalent element if one already existed in the tree.
 */
#define AVS_RBTREE_INSERT(tree, elem)    \
    (_AVS_RB_TYPECHECK(*(tree), (elem)), \
     AVS_RBTREE_CALL_WITH_ELEM_CAST__(avs_rbtree_attach__, (tree), (elem)))

/**
 * Detaches given @p elem from @p tree. Does not free @p elem.
 *
 * NOTE: when passed @p elem is not attached to @p tree, the behavior
 * is undefined.
 *
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @param tree Tree to remove element from.
 * @param elem Element to remove.
 *
 * @returns Detached @p elem.
 */
#define AVS_RBTREE_DETACH(tree, elem)    \
    (_AVS_RB_TYPECHECK(*(tree), (elem)), \
     avs_rbtree_detach__((AVS_RBTREE(void)) (tree), (elem)))

/**
 * Deletes a @p elem attached to @p tree by detaching it from @p tree.
 *
 * NOTE: when passed @p elem is not attached to @p tree, the behavior
 * is undefined. In such case, use @ref AVS_RBTREE_ELEM_DELETE_DETACHED.
 *
 * Complexity: O((log n) * c + f).
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator,
 * - f - avs_free() complexity.
 *
 * Example usage:
 *
 * @param tree     Tree to remove element from.
 * @param elem_ptr Pointer to the element to remove. On success, *elem_ptr
 *                 will be set to NULL.
 */
#define AVS_RBTREE_DELETE_ELEM(tree, elem_ptr)                               \
    do {                                                                     \
        _AVS_RB_TYPECHECK(*(tree), *(elem_ptr));                             \
        AVS_RBTREE_ELEM(void) *ptr__ = (AVS_RBTREE_ELEM(void) *) (elem_ptr); \
        avs_rbtree_detach__((AVS_RBTREE(void)) (tree), *ptr__);              \
        avs_rbtree_elem_delete__(ptr__);                                     \
    } while (0)

/**
 * Finds the first element in @p tree that has a value greater or equal to
 * @p val_ptr in @p tree.
 *
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @param tree    Tree to search in.
 * @param val_ptr Pointer to a node value to search for.
 *                NOTE: this does not need to be an AVS_RBTREE_ELEM object.
 *
 * @returns Attached element pointer on success, NULL if @p tree is empty, or
 *          all elements present in it are strictly less than @p val_ptr.
 */
#define AVS_RBTREE_LOWER_BOUND(tree, val_ptr) \
    (_AVS_RB_TYPECHECK(*(tree), (val_ptr)),   \
     AVS_RBTREE_CALL_WITH_CONST_ELEM_CAST__(  \
             avs_rbtree_lower_bound__, (tree), (val_ptr)))

/**
 * Finds the first element in @p tree that has a value strictly greater than
 * @p val_ptr in @p tree.
 *
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @param tree    Tree to search in.
 * @param val_ptr Pointer to a node value to search for.
 *                NOTE: this does not need to be an AVS_RBTREE_ELEM object.
 *
 * @returns Attached element pointer on success, NULL if @pr tree is empty, or
 *          all elements present in it are less or equal to @p val_ptr.
 */
#define AVS_RBTREE_UPPER_BOUND(tree, val_ptr) \
    (_AVS_RB_TYPECHECK(*(tree), (val_ptr)),   \
     AVS_RBTREE_CALL_WITH_CONST_ELEM_CAST__(  \
             avs_rbtree_upper_bound__, (tree), (val_ptr)))

/**
 * Finds an element with value given by @p val_ptr in @p tree.
 *
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @param tree    Tree to search in.
 * @param val_ptr Pointer to a node value to search for.
 *                NOTE: this does not need to be an AVS_RBTREE_ELEM object.
 *
 * @returns Found attached element pointer on success, NULL if the @p tree does
 *          not contain such element.
 */
#define AVS_RBTREE_FIND(tree, val_ptr)       \
    (_AVS_RB_TYPECHECK(*(tree), (val_ptr)),  \
     AVS_RBTREE_CALL_WITH_CONST_ELEM_CAST__( \
             avs_rbtree_find__, (tree), (val_ptr)))

/**
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @returns:
 * - @p elem successor in order defined by
 *   @ref avs_rbtree_element_comparator_t of an RB-tree object @p elem is
 *   attached to.
 * - NULL if there is no successor or the node is detached.
 */
#define AVS_RBTREE_ELEM_NEXT(elem) \
    AVS_CALL_WITH_CAST(0, avs_rbtree_elem_next__, elem)

/**
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @returns:
 * - @p elem predecessor in order defined by
 *   @ref avs_rbtree_element_comparator_t of an RB-tree object @p elem is
 *   attached to.
 * - NULL if there is no predecessor or the node is detached.
 */
#define AVS_RBTREE_ELEM_PREV(elem) \
    AVS_CALL_WITH_CAST(0, avs_rbtree_elem_prev__, elem)

/**
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @returns the first element in @p tree (in order defined by
 *          @ref avs_rbtree_element_comparator_t of @p tree) or NULL if the
 *          @p tree is empty.
 */
#define AVS_RBTREE_FIRST(tree) \
    AVS_RBTREE_CALL_WITH_ELEM_CAST__(avs_rbtree_first__, (tree))

/**
 * Complexity: O((log n) * c), where:
 * - n - number of nodes in @p tree,
 * - c - complexity of tree element comparator.
 *
 * @returns the last element in @p tree (in order defined by
 *          @ref avs_rbtree_element_comparator_t of @p tree) or NULL if the
 *          tree is empty.
 */
#define AVS_RBTREE_LAST(tree) \
    AVS_RBTREE_CALL_WITH_ELEM_CAST__(avs_rbtree_last__, (tree))

/** Convenience macro for forward iteration on elements of @p tree. */
#define AVS_RBTREE_FOREACH(it, tree)                                      \
    for (_AVS_RB_TYPECHECK(*(tree), (it)), (it) = AVS_RBTREE_FIRST(tree); \
         (it);                                                            \
         (it) = AVS_RBTREE_ELEM_NEXT(it))

/**
 * Convenience macro for forward iteration on elements of @p tree, also allowing
 * for element deletion.
 *
 * @p helper needs to be an AVS_RBTREE_ELEM variable - it will be used
 * internally.
 */
#define AVS_RBTREE_DELETABLE_FOREACH(it, helper, tree)      \
    for (_AVS_RB_TYPECHECK(*(tree), (it)),                  \
         _AVS_RB_TYPECHECK((it), (helper)),                 \
         (it) = AVS_RBTREE_FIRST(tree),                     \
         (helper) = (it) ? AVS_RBTREE_ELEM_NEXT(it) : (it); \
         (it);                                              \
         (it) = (helper),                                   \
         (helper) = (helper) ? AVS_RBTREE_ELEM_NEXT(helper) : (helper))

/** Convenience macro for backward iteration on elements of @p tree. */
#define AVS_RBTREE_FOREACH_REVERSE(it, tree)                                   \
    for (_AVS_RB_TYPECHECK(*(tree), (it)), (it) = AVS_RBTREE_LAST(tree); (it); \
         (it) = AVS_RBTREE_ELEM_PREV(it))

/**
 * Convenience macro for backward iteration on elements of @p tree, also
 * allowing for element deletion.
 *
 * @p helper needs to be an AVS_RBTREE_ELEM variable - it will be used
 * internally.
 */
#define AVS_RBTREE_DELETABLE_FOREACH_REVERSE(it, helper, tree) \
    for (_AVS_RB_TYPECHECK(*(tree), (it)),                     \
         _AVS_RB_TYPECHECK((it), (helper)),                    \
         (it) = AVS_RBTREE_LAST(tree),                         \
         (helper) = (it) ? AVS_RBTREE_ELEM_PREV(it) : (it);    \
         (it);                                                 \
         (it) = (helper),                                      \
         (helper) = (helper) ? AVS_RBTREE_ELEM_PREV(helper) : (helper))

#endif /* AVS_COMMONS_RBTREE_INCLUDE_PUBLIC_COMMONS_RBTREE_H */
