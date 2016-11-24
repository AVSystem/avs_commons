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
 * @returns The comparator should return:
 * - a negative value if @p a < @p b,
 * - 0 if @p a == @p b,
 * - a positive value if @p a > @p b.
 *
 * NOTE: the comparator MUST establish a total ordering of RB-tree elements.
 * If it does not fullfill this requirement, the behavior of operations on the
 * tree is undefined.
 */
typedef int avs_rb_cmp_t(const void *a,
                         const void *b);

/** RB tree type alias.  */
#define AVS_RB_TREE(type) type**
/** RB element type alias. */
#define AVS_RB_NODE(type) type*

#define _AVS_RB_TYPECHECK(tree_type, elem_type) \
    ((void)(**(tree_type) < *(elem_type)))

/**
 * Create an RB tree with elements of given @p type. @p cmp function is used
 * to compare its elements.
 *
 * @param type Type of elements in the tree.
 * @param cmp  A function that compares two elements. See @ref avs_rb_cmp_t .
 *
 * @returns Created RB tree object on success, NULL in case of error.
 */
#define AVS_RB_TREE_CREATE(type, cmp) ((AVS_RB_TREE(type))_avs_rb_tree_create(cmp))

/**
 * Releases given RB tree and all its nodes.
 *
 * @param tree_ptr Pointer to the RB tree object to destroy. *tree_ptr is set to
 *                 NULL after the cleanup is done.
 */
#define AVS_RB_TREE_RELEASE(tree_ptr) _avs_rb_tree_release((void***)(tree_ptr))

/**
 * @param tree RB tree object to operate on.
 *
 * @returns Total number of elements in the tree.
 */
#define AVS_RB_TREE_SIZE(tree) _avs_rb_tree_size((void**)tree)

/**
 * Creates an arbitrarily-sized, detached RB tree element.
 *
 * @param size Number of bytes to allocate for the element content.
 *
 * @returns Pointer to created element on success, NULL in case of error.
 */
#define AVS_RB_NEW_BUFFER(size) _avs_rb_alloc_node(size)

/**
 * Creates a detached RB tree element large enough to hold a value of
 * given @p type.
 *
 * @param type Desired element type.
 *
 * @returns Pointer to created element cast to @p type * on success,
 *          NULL in case of error.
 */
#define AVS_RB_NEW_ELEMENT(type) ((type*)AVS_RB_NEW_BUFFER(sizeof(type)))

/**
 * Frees memory associated with given detached RB tree element.
 *
 * NOTE: when passed @p elem is attached to some tree, the behavior
 * is undefined.
 *
 * @param elem Pointer to element to free. *elem is set to NULL after cleanup.
 */
#define AVS_RB_DELETE_ELEMENT(elem) _avs_rb_free_node((void**)elem)

/**
 * Inserts an detached @p elem into given @p tree. 
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
#define AVS_RB_TREE_INSERT(tree, elem) \
    (_AVS_RB_TYPECHECK(tree, elem), \
     _avs_rb_tree_attach((void**)(tree), (elem)))

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
#define AVS_RB_TREE_DETACH(tree, elem) \
    (_AVS_RB_TYPECHECK(tree, elem), \
     _avs_rb_tree_detach((void**)(tree), (elem)))

/**
 * Finds an element with value given by @p val_ptr in @p tree.
 *
 * @param tree    Tree to search in.
 * @param val_ptr Pointer to a node value to search for.
 *
 * @returns Found attached element pointer on success, NULL if the @p tree does
 *          not contain such element.
 */
#define AVS_RB_TREE_FIND(tree, val_ptr) \
    (_AVS_RB_TYPECHECK(tree, val_ptr), \
     ((AVS_TYPEOF_PTR(val_ptr)) \
      _avs_rb_tree_find((void**)tree, val_ptr)))

/** Returns @p elem successor or NULL if there is none. */
#define AVS_RB_NEXT(elem) ((AVS_TYPEOF_PTR(elem))_avs_rb_next(elem))

/** Returns @p elem predecessor or NULL if there is none. */
#define AVS_RB_PREV(elem) ((AVS_TYPEOF_PTR(elem))_avs_rb_prev(elem))

/** Returns the first element in @p tree. */
#define AVS_RB_TREE_FIRST(tree) \
    ((AVS_TYPEOF_PTR(*tree))_avs_rb_tree_first((AVS_RB_TREE(void))tree))

/** Returns the last element in @p tree. */
#define AVS_RB_TREE_LAST(tree) \
    ((AVS_TYPEOF_PTR(*tree))_avs_rb_tree_last((AVS_RB_TREE(void))tree))

/** Convenience macro for forward iteration on elements of @p tree. */
#define AVS_RB_FOREACH(it, tree) \
    for (it = AVS_RB_FIRST((AVS_TYPEOF_PTR(it))(tree)->root); \
            it; \
            it = AVS_RB_NEXT(it))

/** Convenience macro for backward iteration on elements of @p tree. */
#define AVS_RB_FOREACH_REVERSE(it, tree) \
    for (it = AVS_RB_LAST((AVS_TYPEOF_PTR(it))(tree)->root); \
            it; \
            it = AVS_RB_PREV(it))

/* Internal functions. Use macros defined above instead. */
AVS_RB_TREE(void) _avs_rb_tree_create(avs_rb_cmp_t *cmp);
void _avs_rb_tree_release(AVS_RB_TREE(void) *tree);

size_t _avs_rb_tree_size(AVS_RB_TREE(void) tree);
AVS_RB_NODE(void) _avs_rb_tree_find(AVS_RB_TREE(void) tree,
                                    const void *value);
int _avs_rb_tree_attach(AVS_RB_TREE(void) tree,
                        AVS_RB_NODE(void) node);
AVS_RB_NODE(void) _avs_rb_tree_detach(AVS_RB_TREE(void) tree,
                                      AVS_RB_NODE(void) node);

AVS_RB_NODE(void) _avs_rb_tree_first(AVS_RB_TREE(void) tree);
AVS_RB_NODE(void) _avs_rb_tree_last(AVS_RB_TREE(void) tree);

AVS_RB_NODE(void) _avs_rb_alloc_node(size_t elem_size);
void _avs_rb_free_node(AVS_RB_NODE(void) *node);

AVS_RB_NODE(void) _avs_rb_next(AVS_RB_NODE(void) elem);
AVS_RB_NODE(void) _avs_rb_prev(AVS_RB_NODE(void) elem);

#endif /* AVS_COMMONS_RBTREE_INCLUDE_PUBLIC_COMMONS_RBTREE_H */
