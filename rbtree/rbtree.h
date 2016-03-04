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

#define RB_TREE_DELETE(elem) rb_delete(elem)

#define RB_INSERT(tree, ptr) rb_insert((tree), (ptr), sizeof(*(ptr)))

#define RB_NEXT(elem) ((TYPEOF(elem))rb_next(elem))
#define RB_PREV(elem) ((TYPEOF(elem))rb_prev(elem))

#define RB_FIRST(root) ((TYPEOF(root))rb_min(root))
#define RB_LAST(root) ((TYPEOF(root))rb_max(root))

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

static void rb_release_subtree(void *root) {
    if (!root) {
        return;
    }

    rb_release_subtree(RB_LEFT(root));
    rb_release_subtree(RB_RIGHT(root));
    RB_DEALLOC(RB_NODE(root));
}

void rb_release(struct rb_tree **tree) {
    if (!tree || !*tree) {
        return;
    }

    rb_release_subtree((*tree)->root);
    RB_DEALLOC(*tree);
    *tree = NULL;
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

static void rb_insert_fix(struct rb_tree *tree,
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
        return rb_insert_fix(tree, grandparent);
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

    rb_insert_fix(tree, elem);
    return 0;
}

void *rb_min(void *root) {
    assert(root);

    void *min = root;
    void *left = root;

    do {
        min = left;
        left = RB_LEFT(min);
    } while (left);

    return min;
}

void *rb_max(void *root) {
    assert(root);

    void *max = root;
    void *right = root;

    do {
        max = right;
        right = RB_RIGHT(max);
    } while (right);

    return max;
}

void *rb_next(void *elem) {
    void *right = RB_RIGHT(elem);
    if (right) {
        return rb_min(right);
    }

    void *parent = RB_PARENT(elem);
    void *curr = elem;
    while (parent && RB_RIGHT(parent) == curr) {
        curr = parent;
        parent = RB_PARENT(parent);
    }

    return parent;
}

void *rb_prev(void *elem) {
    void *left = RB_LEFT(elem);
    if (left) {
        return rb_max(left);
    }

    void *parent = RB_PARENT(elem);
    void *curr = elem;
    while (parent && RB_LEFT(parent) == curr) {
        curr = parent;
        parent = RB_PARENT(parent);
    }

    return parent;
}

static void swap(void **a,
                 void **b) {
    assert(a);
    assert(b);

    void *tmp = *a;
    *a = *b;
    *b = tmp;
}

static void swap_nodes(struct rb_tree *tree,
                       void *a,
                       void *b) {
    if (a == b) {
        return;
    }

    swap(rb_own_parent_ptr(tree, a), rb_own_parent_ptr(tree, b));
    swap(RB_PARENT_PTR(a), RB_PARENT_PTR(b));

    swap(RB_LEFT_PTR(a), RB_LEFT_PTR(b));
    if (RB_LEFT(a)) {
        RB_PARENT(RB_LEFT(a)) = a;
    }

    swap(RB_RIGHT_PTR(a), RB_RIGHT_PTR(b));
    if (RB_RIGHT(a)) {
        RB_PARENT(RB_RIGHT(a)) = a;
    }
}

void rb_detach_fix(struct rb_tree *tree,
                   void *elem) {
    assert(elem);
    assert(rb_node_color(elem) == BLACK);

    // case 1
    void *parent = RB_PARENT(elem);
    if (!parent) {
        return;
    }

    // case 2
    void *sibling = rb_sibling(elem);
    if (rb_node_color(sibling) == RED) {
        RB_NODE(parent)->color = RED;
        RB_NODE(sibling)->color = BLACK;

        if (elem == RB_LEFT(parent)) {
            rb_rotate_left(tree, parent);
        } else {
            rb_rotate_right(tree, parent);
        }
    }

    // case 3
    parent = RB_PARENT(elem);
    sibling = rb_sibling(elem);
    if (rb_node_color(parent) == BLACK
            && rb_node_color(sibling) == BLACK
            && rb_node_color(RB_LEFT(sibling)) == BLACK
            && rb_node_color(RB_RIGHT(sibling)) == BLACK) {
        RB_NODE(sibling)->color = RED;
        return rb_detach_fix(tree, parent);
    }

    // case 4
    if (rb_node_color(parent) == RED
            && rb_node_color(sibling) == BLACK
            && rb_node_color(RB_LEFT(sibling)) == BLACK
            && rb_node_color(RB_RIGHT(sibling)) == BLACK) {
        RB_NODE(sibling)->color = RED;
        RB_NODE(parent)->color = BLACK;
        return;
    }

    // case 5
    assert(rb_node_color(sibling) == BLACK);
    if (elem == RB_LEFT(parent)
            && rb_node_color(RB_RIGHT(sibling)) == BLACK) {
        assert(rb_node_color(RB_LEFT(sibling)) == RED);

        RB_NODE(sibling)->color = RED;
        RB_NODE(RB_LEFT(sibling))->color = BLACK;
        rb_rotate_right(tree, sibling);
    } else if (elem == RB_RIGHT(parent)
               && rb_node_color(RB_LEFT(sibling)) == BLACK) {
        assert(rb_node_color(RB_RIGHT(sibling)) == RED);

        RB_NODE(sibling)->color = RED;
        RB_NODE(RB_RIGHT(sibling))->color = BLACK;
        rb_rotate_left(tree, sibling);
    }

    // case 6
    parent = RB_PARENT(elem);
    sibling = rb_sibling(elem);

    RB_NODE(sibling)->color = rb_node_color(parent);
    RB_NODE(parent)->color = BLACK;

    if (elem == RB_LEFT(parent)) {
        RB_NODE(RB_RIGHT(sibling))->color = BLACK;
        rb_rotate_left(tree, parent);
    } else {
        RB_NODE(RB_LEFT(sibling))->color = BLACK;
        rb_rotate_right(tree, parent);
    }
}

void *rb_detach(struct rb_tree *tree,
                void *elem) {
    assert(tree);
    assert(elem);

    void *left = RB_LEFT(elem);
    void *right = RB_RIGHT(elem);

    if (left && right) {
        void *replacement = rb_next(elem);
        swap_nodes(tree, elem, replacement);
        return rb_detach(tree, elem);
    }

    void *child = left ? left : right;
    void *parent = RB_PARENT(elem);

    if (child) {
        assert(RB_PARENT(child) == elem);
        RB_PARENT(child) = parent;
    }

    *rb_own_parent_ptr(tree, elem) = child;

    if (rb_node_color(elem) == RED
            || rb_node_color(child) == RED) {
        if (child) {
            // if elem is red, child is already black
            // if child is red, we need to repaint it
            RB_NODE(child)->color = BLACK;
        }

        return elem;
    }

    // both node and child are black
    if (child) {
        rb_detach_fix(tree, child);
    }
    return elem;
}

void rb_delete(void *elem) {
    struct rb_node *node = RB_NODE(elem);
    assert(!node->parent);
    assert(!node->left);
    assert(!node->right);
    RB_DEALLOC(node);
}
