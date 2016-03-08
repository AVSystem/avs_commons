#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/defs.h>

typedef int avs_rb_cmp_t(const void *a,
                         const void *b,
                         size_t size);

#define AVS_RB_TREE(type) type**
#define AVS_RB_NODE(type) type*

AVS_RB_TREE(void) _avs_rb_tree_create(avs_rb_cmp_t *cmp);
void _avs_rb_tree_release(AVS_RB_TREE(void) *tree);

size_t _avs_rb_tree_size(AVS_RB_TREE(void) tree);
AVS_RB_NODE(void) _avs_rb_tree_find(AVS_RB_TREE(void) tree,
                                    const void *value,
                                    size_t value_size);
int _avs_rb_tree_attach(AVS_RB_TREE(void) tree,
                        AVS_RB_NODE(void) node,
                        size_t node_size);
AVS_RB_NODE(void) _avs_rb_tree_detach(AVS_RB_TREE(void) tree,
                                      AVS_RB_NODE(void) node);

AVS_RB_NODE(void) _avs_rb_tree_first(AVS_RB_TREE(void) tree);
AVS_RB_NODE(void) _avs_rb_tree_last(AVS_RB_TREE(void) tree);

AVS_RB_NODE(void) _avs_rb_alloc_node(size_t elem_size);
void _avs_rb_free_node(AVS_RB_NODE(void) node);

AVS_RB_NODE(void) _avs_rb_next(AVS_RB_NODE(void) elem);
AVS_RB_NODE(void) _avs_rb_prev(AVS_RB_NODE(void) elem);

#define _AVS_RB_TYPECHECK(tree_type, elem_type) \
    ((void)(*(tree_type) < (elem_type)))

#define AVS_RB_TREE_CREATE(type, cmp) ((AVS_RB_TREE(type))_avs_rb_tree_create(cmp))
#define AVS_RB_TREE_RELEASE(tree_ptr) _avs_rb_tree_release((void***)(tree_ptr))

#define AVS_RB_TREE_SIZE(tree) _avs_rb_tree_size(tree)

#define AVS_RB_NEW_BUFFER(size) _avs_rb_alloc_node(size)
#define AVS_RB_NEW_ELEMENT(type) ((type*)AVS_RB_NEW_BUFFER(sizeof(type)))

#define AVS_RB_DELETE_ELEMENT(elem) _avs_rb_free_node(elem)

#define AVS_RB_TREE_INSERT(tree, elem_ptr) \
    (_AVS_RB_TYPECHECK(tree, elem_ptr), \
     _avs_rb_tree_attach((void**)(tree), (elem_ptr), sizeof(*(elem_ptr))))

#define AVS_RB_TREE_DETACH(tree, elem_ptr) \
    (_AVS_RB_TYPECHECK(tree, elem_ptr), \
     _avs_rb_tree_detach((void**)(tree), (elem_ptr)))

#define AVS_RB_TREE_FIND(tree, val_ptr) \
    (_AVS_RB_TYPECHECK(tree, val_ptr), \
     ((_AVS_TYPEOF(val_ptr)) \
      _avs_rb_tree_find((void**)tree, val_ptr, sizeof(*val_ptr))))

#define AVS_RB_NEXT(elem) ((_AVS_TYPEOF(elem))_avs_rb_next(elem))
#define AVS_RB_PREV(elem) ((_AVS_TYPEOF(elem))_avs_rb_prev(elem))

#define AVS_RB_TREE_FIRST(tree) \
    ((_AVS_TYPEOF(*tree))_avs_rb_tree_first((AVS_RB_TREE(void))tree))
#define AVS_RB_TREE_LAST(tree) \
    ((_AVS_TYPEOF(*tree))_avs_rb_tree_last((AVS_RB_TREE(void))tree))

#define AVS_RB_FOREACH(it, tree) \
    for (it = AVS_RB_FIRST((_AVS_TYPEOF(it))(tree)->root); \
            it; \
            it = AVS_RB_NEXT(it))
#define AVS_RB_FOREACH_REVERSE(it, tree) \
    for (it = AVS_RB_LAST((_AVS_TYPEOF(it))(tree)->root); \
            it; \
            it = AVS_RB_PREV(it))

