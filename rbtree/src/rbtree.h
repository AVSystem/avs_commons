#ifndef AVS_COMMONS_RBTREE_RBTREE_H
#define AVS_COMMONS_RBTREE_RBTREE_H

#include <stdint.h>
#include <assert.h>

#include <avsystem/commons/rbtree.h>

#ifndef NDEBUG
#define _AVS_RB_USE_MAGIC
static const uint32_t _AVS_RB_MAGIC = 0x00031337;
#endif /* NDEBUG */

enum rb_color {
    RED,
    BLACK
};

struct rb_node {
#ifdef _AVS_RB_USE_MAGIC
    const uint32_t rb_magic; /* always set to _AVS_RB_MAGIC */
    uint32_t tree_magic; /* marks the tree a node is attached to, 0 if detached */
#endif

    enum rb_color color;
    void *parent;
    void *left;
    void *right;
};

struct rb_tree {
#ifdef _AVS_RB_USE_MAGIC
    const uint32_t rb_magic; /* always set to _AVS_RB_MAGIC */
    uint32_t tree_magic; /* uniquely identifies a tree; used to check whether
                            a node is attached to this tree */
#endif

    avs_rbtree_element_comparator_t *cmp;
    void *root;
};

#define _AVS_NODE_SPACE__ \
    offsetof(struct { \
        struct rb_node node; \
        avs_max_align_t value; \
    }, value)

#define _AVS_RB_NODE(elem) \
    ((struct rb_node*)((char*)(elem) - _AVS_NODE_SPACE__))

#define container_of(ptr, type, member) \
    ((type*)((char*)(ptr) - offsetof(type, member)))

#define _AVS_RB_TREE(ptr) \
    container_of((ptr), struct rb_tree, root)

#define _AVS_RB_ALLOC(size) calloc(1, size)
#define _AVS_RB_DEALLOC(ptr) free(ptr)

#define _AVS_RB_LEFT_PTR(elem) \
    ((AVS_TYPEOF_PTR(elem)*)&(_AVS_RB_NODE(elem)->left))

#define _AVS_RB_LEFT(elem) (*_AVS_RB_LEFT_PTR(elem))

#define _AVS_RB_RIGHT_PTR(elem) \
    ((AVS_TYPEOF_PTR(elem)*)&(_AVS_RB_NODE(elem)->right))

#define _AVS_RB_RIGHT(elem) (*_AVS_RB_RIGHT_PTR(elem))

#define _AVS_RB_PARENT_PTR(elem) \
    ((AVS_TYPEOF_PTR(elem)*)&(_AVS_RB_NODE(elem)->parent))

#define _AVS_RB_PARENT(elem) (*_AVS_RB_PARENT_PTR(elem))

#ifdef _AVS_RB_USE_MAGIC
# define _AVS_RB_NODE_VALID(node) \
    (!(node) || _AVS_RB_NODE(node)->rb_magic == _AVS_RB_MAGIC)
# define _AVS_RB_TREE_VALID(tree) \
    (!(tree) || _AVS_RB_TREE(tree)->rb_magic == _AVS_RB_MAGIC)

# define _AVS_RB_NODE_SET_TREE_MAGIC(node, magic) \
    (_AVS_RB_NODE(node)->tree_magic = (magic))
# define _AVS_RB_NODE_TREE_MAGIC(node) (_AVS_RB_NODE(node)->tree_magic)
# define _AVS_RB_TREE_MAGIC(tree) (_AVS_RB_TREE(tree)->tree_magic)
#else
# define _AVS_RB_NODE_VALID(node) 1
# define _AVS_RB_TREE_VALID(tree) 1

# define _AVS_RB_NODE_SET_TREE_MAGIC(node, magic) (void)0
# define _AVS_RB_NODE_TREE_MAGIC(node) 0
# define _AVS_RB_TREE_MAGIC(tree) 0
#endif

enum rb_color _avs_rb_node_color(void *elem);

void _avs_rb_swap_nodes(struct rb_tree *tree,
                        void *a,
                        void *b);

void _avs_rb_rotate_left(struct rb_tree *tree,
                         void *root);

void _avs_rb_rotate_right(struct rb_tree *tree,
                          void *root);

#endif /* AVS_COMMONS_RBTREE_RBTREE_H */
