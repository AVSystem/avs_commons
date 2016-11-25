#ifndef AVS_COMMONS_RBTREE_INCLUDE_PUBLIC_COMMONS_RBTREE_H
#define AVS_COMMONS_RBTREE_INCLUDE_PUBLIC_COMMONS_RBTREE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/defs.h>

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
 * NOTE: the comparator MUST establish a total ordering of RB-tree elements.
 * If it does not fullfill this requirement, the behavior of operations on the
 * tree is undefined.
 */
typedef int avs_rbtree_element_comparator_t(const void *a,
                                            const void *b);

/**
 * RB-tree element deleter. May be passed to @ref AVS_RBTREE_DELETE to perform
 * additional cleanup for each deleted element.
 *
 * NOTE: the deleter MUST NOT call <c>free()</c> on the @p elem itself.
 *
 * @param elem Pointer to the element to perform cleanup on.
 */
typedef void avs_rbtree_element_deleter_t(void *elem);

/** RB-tree type alias.  */
#define AVS_RBTREE(type) type**
/** RB element type alias. */
#define AVS_RBTREE_NODE(type) type*

#define _AVS_RB_TYPECHECK(tree_type, elem_type) \
    ((void)(**(tree_type) < *(elem_type)))

/**
 * Create an RB-tree with elements of given @p type.
 *
 * @param type Type of elements stored in the tree nodes.
 * @param cmp  Pointer to a function that compares two elements.
 *             See @ref avs_rbtree_element_comparator_t .
 *
 * @returns Created RB-tree object on success, NULL in case of error.
 */
#define AVS_RBTREE_NEW(type, cmp) ((AVS_RBTREE(type))_avs_rbtree_new(cmp))

/**
 * Releases given RB-tree and all its nodes.
 *
 * @param tree_ptr Pointer to the RB-tree object to destroy. *tree_ptr is set to
 *                 NULL after the cleanup is done.
 * @param deleter  Cleanup callback, called before deleting each tree element.
 *                 May be NULL if no additional cleanup is required.
 */
#define AVS_RBTREE_DELETE(tree_ptr, deleter) \
    _avs_rbtree_delete((AVS_RBTREE(void)*)(tree_ptr), (deleter))

/**
 * @param tree RB-tree object to operate on.
 *
 * @returns Total number of elements stored in the tree.
 */
#define AVS_RBTREE_SIZE(tree) _avs_rbtree_size((const AVS_RBTREE(void))tree)

/**
 * Creates an arbitrarily-sized, detached RB-tree element.
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
 * AVS_RBTREE_NODE(struct string) node = (AVS_RBTREE_NODE(struct string))
 *     AVS_RBTREE_NEW_BUFFER(sizeof(struct string) + STRING_CAPACITY);
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
#define AVS_RBTREE_NEW_BUFFER(size) _avs_rb_alloc_node(size)

/**
 * Creates a detached RB-tree element large enough to hold a value of
 * given @p type.
 *
 * @param type Desired element type.
 *
 * @returns Pointer to created element cast to @p type * on success,
 *          NULL in case of error.
 */
#define AVS_RBTREE_NEW_ELEMENT(type) \
    ((type*)AVS_RBTREE_NEW_BUFFER(sizeof(type)))

/**
 * Frees memory associated with given detached RB-tree element.
 *
 * NOTE: when passed @p elem is attached to some tree, the behavior
 * is undefined.
 *
 * @param elem Pointer to element to free. *elem is set to NULL after cleanup.
 */
#define AVS_RBTREE_DELETE_ELEMENT(elem) \
    _avs_rb_free_node((AVS_RBTREE(void))elem, NULL)

/**
 * Inserts a detached @p elem into given @p tree.
 *
 * NOTE: when passed @p elem is attached to some tree, the behavior
 * is undefined.
 *
 * @param tree Tree to insert element into.
 * @param elem Element to insert.
 *
 * @returns 0 on success, a nonzero value if the element is already present in
 * the tree.
 */
#define AVS_RBTREE_INSERT(tree, elem) \
    (_AVS_RB_TYPECHECK(tree, elem), \
     _avs_rbtree_attach((AVS_RBTREE(void))(tree), (elem)))

/**
 * Detaches given @p elem from @p tree. Does not free @p elem.
 *
 * NOTE: when passed @p elem is not attached to @p tree, the behavior
 * is undefined.
 *
 * @param tree Tree to remove element from.
 * @param elem Element to remove.
 *
 * @returns Detached @p elem.
 */
#define AVS_RBTREE_DETACH(tree, elem) \
    (_AVS_RB_TYPECHECK(tree, elem), \
     _avs_rbtree_detach((AVS_RBTREE(void))(tree), (elem)))

/**
 * Finds an element with value given by @p val_ptr in @p tree.
 *
 * @param tree    Tree to search in.
 * @param val_ptr Pointer to a node value to search for.
 *
 * @returns Found attached element pointer on success, NULL if the @p tree does
 *          not contain such element.
 */
#define AVS_RBTREE_FIND(tree, val_ptr) \
    (_AVS_RB_TYPECHECK(tree, val_ptr), \
     ((AVS_TYPEOF_PTR(val_ptr)) \
      _avs_rbtree_find((const AVS_RBTREE(void))tree, val_ptr)))

/**
 * Returns @p elem successor in order defined by
 * @ref avs_rbtree_element_comparator_t of an RB-tree object @p elem is
 * attached to.
 *
 * Returns NULL if there is no successor or the node is detached.
 */
#define AVS_RBTREE_NEXT(elem) ((AVS_TYPEOF_PTR(elem))_avs_rb_next(elem))

/**
 * Returns @p elem predecessor in order defined by
 * @ref avs_rbtree_element_comparator_t of an RB-tree object @p elem is
 * attached to.
 *
 * Returns NULL if there is no predecessor or the node is detached.
 */
#define AVS_RBTREE_PREV(elem) ((AVS_TYPEOF_PTR(elem))_avs_rb_prev(elem))

/**
 * Returns the first element in @p tree (in order defined by
 * @ref avs_rbtree_element_comparator_t of @p tree).
 */
#define AVS_RBTREE_FIRST(tree) \
    ((AVS_TYPEOF_PTR(*tree))_avs_rbtree_first((AVS_RBTREE(void))tree))

/**
 * Returns the last element in @p tree (in order defined by
 * @ref avs_rbtree_element_comparator_t of @p tree).
 */
#define AVS_RBTREE_LAST(tree) \
    ((AVS_TYPEOF_PTR(*tree))_avs_rbtree_last((AVS_RBTREE(void))tree))

/** Convenience macro for forward iteration on elements of @p tree. */
#define AVS_RBTREE_FOREACH(it, tree) \
    for (it = AVS_RB_FIRST(tree); \
            it; \
            it = AVS_RB_NEXT(it))

/** Convenience macro for backward iteration on elements of @p tree. */
#define AVS_RBTREE_FOREACH_REVERSE(it, tree) \
    for (it = AVS_RB_LAST(tree); \
            it; \
            it = AVS_RB_PREV(it))

/* Internal functions. Use macros defined above instead. */
AVS_RBTREE(void) _avs_rbtree_new(avs_rbtree_element_comparator_t *cmp);
void _avs_rbtree_delete(AVS_RBTREE(void) *tree,
                        avs_rbtree_element_deleter_t *deleter);

size_t _avs_rbtree_size(const AVS_RBTREE(void) tree);
AVS_RBTREE_NODE(void) _avs_rbtree_find(const AVS_RBTREE(void) tree,
                                       const void *value);
int _avs_rbtree_attach(AVS_RBTREE(void) tree,
                       AVS_RBTREE_NODE(void) node);
AVS_RBTREE_NODE(void) _avs_rbtree_detach(AVS_RBTREE(void) tree,
                                         AVS_RBTREE_NODE(void) node);

AVS_RBTREE_NODE(void) _avs_rbtree_first(AVS_RBTREE(void) tree);
AVS_RBTREE_NODE(void) _avs_rbtree_last(AVS_RBTREE(void) tree);

AVS_RBTREE_NODE(void) _avs_rb_alloc_node(size_t elem_size);
void _avs_rb_free_node(AVS_RBTREE_NODE(void) *node,
                       avs_rbtree_element_deleter_t *deleter);

AVS_RBTREE_NODE(void) _avs_rb_next(AVS_RBTREE_NODE(void) elem);
AVS_RBTREE_NODE(void) _avs_rb_prev(AVS_RBTREE_NODE(void) elem);

#endif /* AVS_COMMONS_RBTREE_INCLUDE_PUBLIC_COMMONS_RBTREE_H */
