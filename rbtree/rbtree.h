#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/defs.h>

#define RB_USE_MAGIC
#define RB_MAGIC 0x00031337

struct rb_tree;
static void dump_tree(struct rb_tree *tree);

typedef int rb_cmp(const void *a,
                   const void *b,
                   size_t size);

struct rb_tree {
    rb_cmp *cmp;
    void *root;
};

enum rb_color {
    RED,
    BLACK
};

struct rb_node {
#ifdef RB_USE_MAGIC
    const uint32_t magic;
#endif
    enum rb_color color;
    void *parent;
    void *left;
    void *right;
};

#define TYPEOF __typeof__

#define PTR_SPACE__ \
offsetof(struct { \
    struct rb_node node; \
    avs_max_align_t value; \
}, value)

#define RB_ALLOC(size) calloc(1, size)
#define RB_DEALLOC(ptr) free(ptr)

#define RB_NODE(elem) \
    ((struct rb_node*)((char*)(elem) - PTR_SPACE__))

#define RB_LEFT_PTR(elem) \
    ((TYPEOF(elem)*)&(RB_NODE(elem)->left))

#define RB_LEFT(elem) (*RB_LEFT_PTR(elem))

#define RB_RIGHT_PTR(elem) \
    ((TYPEOF(elem)*)&(RB_NODE(elem)->right))

#define RB_RIGHT(elem) (*RB_RIGHT_PTR(elem))

#define RB_PARENT_PTR(elem) \
    ((TYPEOF(elem)*)&(RB_NODE(elem)->parent))

#define RB_PARENT(elem) (*RB_PARENT_PTR(elem))

#define RB_TREE_NEW_ELEMENT(type) ((type*)rb_create_node(sizeof(type)))

#define RB_TREE_DELETE(elem) (RB_DEALLOC(RB_NODE(rb_detach(elem))))

#define RB_INSERT(tree, ptr) rb_insert((tree), (ptr), sizeof(*(ptr)))

#ifdef RB_USE_MAGIC
# define RB_NODE_VALID(node) (!node || RB_NODE(node)->magic == RB_MAGIC)
#else
# define RB_NODE_VALID(node) true
#endif

struct rb_tree *rb_create(rb_cmp *cmp) {
    struct rb_tree *tree = (struct rb_tree*)RB_ALLOC(sizeof(struct rb_tree));
    if (tree) {
        tree->cmp = cmp;
        tree->root = NULL;
    }
    return tree;
}

static void *rb_create_node(size_t elem_size) {
    struct rb_node *node = (struct rb_node*)RB_ALLOC(PTR_SPACE__ + elem_size);

#ifdef RB_USE_MAGIC
    uint32_t magic = RB_MAGIC;
    memcpy((void*)(intptr_t)&node->magic, &magic, sizeof(node->magic));
#endif // RB_USE_MAGIC

    void *elem = (void*)node + PTR_SPACE__;
    assert(RB_NODE_VALID(elem));
    return elem;
}

void *rb_find_parent(struct rb_tree *tree,
                     void *elem,
                     size_t elem_size,
                     void ***out_ptr) {
    assert(tree);
    assert(elem);
    assert(RB_NODE_VALID(elem));

    void *parent = NULL;
    void **curr = &tree->root;

    while (*curr) {
        assert(RB_NODE_VALID(*curr));

        const int cmp = tree->cmp(elem, *curr, elem_size);
        if (cmp == 0) {
            break;
        }

        parent = *curr;
        if (cmp < 0) {
            curr = RB_LEFT_PTR(*curr);
        } else {
            curr = RB_RIGHT_PTR(*curr);
        }
    }

    *out_ptr = curr;
    return parent;
}

void **rb_find_ptr(struct rb_tree *tree,
                   void *elem,
                   size_t elem_size) {
    assert(tree);
    assert(elem);
    assert(RB_NODE_VALID(elem));

    void **curr = &tree->root;

    while (*curr) {
        assert(RB_NODE_VALID(*curr));

        const int cmp = tree->cmp(elem, *curr, elem_size);
        if (cmp < 0) {
            curr = RB_LEFT_PTR(*curr);
        } else if (cmp > 0) {
            curr = RB_RIGHT_PTR(*curr);
        } else {
            return curr;
        }
    }

    return curr;
}

static void *rb_sibling(void *elem) {
    assert(elem);
    assert(RB_NODE_VALID(elem));

    void *parent = RB_PARENT(elem);
    assert(parent);
    assert(RB_NODE_VALID(parent));

    void *p_left = RB_LEFT(parent);
    void *p_right = RB_RIGHT(parent);
    assert(RB_NODE_VALID(p_left));
    assert(RB_NODE_VALID(p_right));

    if (elem == p_left) {
        return p_right;
    } else {
        assert(elem == p_right);
        return p_left;
    }
}

static void *rb_uncle(void *elem) {
    assert(elem);
    assert(RB_NODE_VALID(elem));

    void *parent = RB_PARENT(elem);
    assert(parent);
    assert(RB_NODE_VALID(parent));

    return rb_sibling(parent);
}

static enum rb_color rb_node_color(void *elem) {
    assert(RB_NODE_VALID(elem));

    if (!elem) {
        return BLACK;
    } else {
        return RB_NODE(elem)->color;
    }
}

/**
 * Returns a reference to parent's pointer to @p node.
 * If @p node is the root, returns a root reference from the @p tree.
 */
static void **rb_own_parent_ptr(struct rb_tree *tree,
                                void *node) {
    void *parent = RB_PARENT(node);
    if (!parent) {
        return &tree->root;
    }

    if (RB_LEFT(parent) == node) {
        return RB_LEFT_PTR(parent);
    } else {
        assert(RB_RIGHT(parent) == node);
        return RB_RIGHT_PTR(parent);
    }
}

static void rb_rotate_left(struct rb_tree *tree,
                           void *root) {
    void *parent = RB_PARENT(root);
    void **own_parent_ptr = rb_own_parent_ptr(tree, root);
    assert(own_parent_ptr);

    void *pivot = RB_RIGHT(root);
    assert(pivot);
    assert(RB_NODE_VALID(pivot));

    *own_parent_ptr = pivot;
    RB_PARENT(pivot) = parent;

    void *grandchild = RB_LEFT(pivot);
    RB_LEFT(pivot) = root;
    RB_PARENT(root) = pivot;

    RB_RIGHT(root) = grandchild;
    if (grandchild) {
        RB_PARENT(grandchild) = root;
    }
}

static void rb_rotate_right(struct rb_tree *tree,
                            void *root) {
    void *parent = RB_PARENT(root);
    void **own_parent_ptr = rb_own_parent_ptr(tree, root);
    assert(own_parent_ptr);

    void *pivot = RB_LEFT(root);
    assert(pivot);
    assert(RB_NODE_VALID(pivot));

    *own_parent_ptr = pivot;
    RB_PARENT(pivot) = parent;

    void *grandchild = RB_RIGHT(pivot);
    RB_RIGHT(pivot) = root;
    RB_PARENT(root) = pivot;

    RB_LEFT(root) = grandchild;
    if (grandchild) {
        RB_PARENT(grandchild) = root;
    }
}

static void rb_fix(struct rb_tree *tree,
                   void *elem) {
    // case 1
    if (elem == tree->root) {
        RB_NODE(elem)->color = BLACK;
        return;
    }

    RB_NODE(elem)->color = RED;

    // case 2
    void *parent = RB_PARENT(elem);
    if (rb_node_color(parent) == BLACK) {
        return;
    }

    // case 3
    void *uncle = rb_sibling(parent);
    void *grandparent = RB_PARENT(parent);

    if (rb_node_color(uncle) == RED) {
        RB_NODE(parent)->color = BLACK;
        RB_NODE(uncle)->color = BLACK;
        RB_NODE(grandparent)->color = RED;
        return rb_fix(tree, grandparent);
    }

    // case 4
    if (elem == RB_RIGHT(parent)
            && parent == RB_LEFT(grandparent)) {
        rb_rotate_left(tree, parent);
        elem = RB_LEFT(elem);
    } else if (elem == RB_LEFT(parent)
                   && parent == RB_RIGHT(grandparent)) {
        rb_rotate_right(tree, parent);
        elem = RB_RIGHT(elem);
    }

    // case 5
    parent = RB_PARENT(elem);
    grandparent = RB_PARENT(parent);

    RB_NODE(parent)->color = BLACK;
    RB_NODE(grandparent)->color = RED;
    if (elem == RB_LEFT(parent)) {
        rb_rotate_right(tree, grandparent);
    } else {
        rb_rotate_left(tree, grandparent);
    }
}

static void rb_replace(void *old_elem,
                       void *new_elem) {
    void *parent = RB_PARENT(old_elem);
    RB_PARENT(new_elem) = parent;
    if (parent) {
        if (RB_LEFT(parent) == old_elem) {
            RB_LEFT(parent) = new_elem;
        } else {
            assert(RB_RIGHT(parent) == old_elem);
            RB_RIGHT(parent) = new_elem;
        }
    }
    RB_PARENT(old_elem) = NULL;

    void *left = RB_LEFT(old_elem);
    RB_LEFT(new_elem) = left;
    if (left) {
        RB_PARENT(left) = new_elem;
    }
    RB_LEFT(old_elem) = NULL;

    void *right = RB_RIGHT(old_elem);
    RB_RIGHT(new_elem) = right;
    if (right) {
        RB_PARENT(right) = new_elem;
    }
    RB_RIGHT(old_elem) = NULL;
}

int rb_insert(struct rb_tree *tree,
              void *elem,
              size_t elem_size) {
    assert(elem);

    void **dst = NULL;
    void *parent = rb_find_parent(tree, elem, elem_size, &dst);
    assert(dst);

    if (*dst) {
        // already present
        return -1;
    } else {
        *dst = elem;
        RB_PARENT(elem) = parent;
    }

    rb_fix(tree, elem);
    return 0;
}

void *rb_detach(void *elem) {
    assert(elem);

#warning TODO

    return elem;
}
