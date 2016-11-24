#include <avsystem/commons/rbtree.h>
#include "rbtree.h"

enum rb_color _avs_rb_node_color(void *elem) {
    assert(_AVS_RB_NODE_VALID(elem));

    if (!elem) {
        return BLACK;
    } else {
        return _AVS_RB_NODE(elem)->color;
    }
}

#ifdef _AVS_RB_USE_MAGIC
static void rb_tree_init_magic(struct rb_tree *tree) {
    static uint32_t tree_magic_gen = 0;

    memcpy((void*)(intptr_t)&tree->rb_magic, &_AVS_RB_MAGIC,
           sizeof(tree->rb_magic));
    tree_magic_gen++;
    memcpy((void*)(intptr_t)&tree->tree_magic, &tree_magic_gen,
           sizeof(tree->tree_magic));
}
#else
#define rb_tree_init_magic(tree) (void)0
#endif

void **_avs_rb_tree_new(avs_rb_cmp_t *cmp) {
    struct rb_tree *tree = (struct rb_tree*)_AVS_RB_ALLOC(sizeof(struct rb_tree));
    if (!tree) {
        return NULL;
    }

    rb_tree_init_magic(tree);
    tree->cmp = cmp;
    tree->root = NULL;

    assert(_AVS_RB_TREE_VALID(&tree->root));
    return &tree->root;
}

#if _DEBUG
static int rb_is_node_detached(AVS_RB_NODE(void) elem) {
    return _AVS_RB_PARENT(elem) == NULL
        && _AVS_RB_LEFT(elem) == NULL
        && _AVS_RB_RIGHT(elem) == NULL
        && _AVS_RB_TREE_MAGIC(elem) == 0;
}
#else
# define rb_is_node_detached(_) 1
#endif

void _avs_rb_free_node(void **node) {
    if (node && *node) {
        assert(_AVS_RB_NODE_VALID(*node));
        assert(rb_is_node_detached(*node));

        _AVS_RB_DEALLOC(_AVS_RB_NODE(*node));
        *node = NULL;
    }
}

static void rb_delete_subtree(void **root) {
    if (!root || !*root) {
        return;
    }

    rb_delete_subtree(_AVS_RB_LEFT_PTR(*root));
    rb_delete_subtree(_AVS_RB_RIGHT_PTR(*root));

    _AVS_RB_PARENT(*root) = NULL;
    _AVS_RB_NODE_SET_TREE_MAGIC(*root, 0);

    _avs_rb_free_node(root);
}

void _avs_rb_tree_delete(void ***tree_) {
    struct rb_tree *tree;

    if (!tree_ || !*tree_) {
        return;
    }

    tree = _AVS_RB_TREE(*tree_);
    assert(_AVS_RB_TREE_VALID(*tree_));

    rb_delete_subtree(&tree->root);
    _AVS_RB_DEALLOC(tree);
    *tree_ = NULL;
}

static size_t rb_subtree_size(void *root) {
    if (!root) {
        return 0;
    }

    return (1 + rb_subtree_size(_AVS_RB_LEFT(root))
            + rb_subtree_size(_AVS_RB_RIGHT(root)));
}

size_t _avs_rb_tree_size(AVS_RB_TREE(void) tree) {
    return rb_subtree_size(_AVS_RB_TREE(tree)->root);
}

#ifdef _AVS_RB_USE_MAGIC
static void rb_node_init_magic(struct rb_node *node) {
    memcpy((void*)(intptr_t)&node->rb_magic, &_AVS_RB_MAGIC,
           sizeof(node->rb_magic));
    node->tree_magic = 0;
}
#else
#define rb_node_init_magic(_) (void)0
#endif

AVS_RB_NODE(void) _avs_rb_alloc_node(size_t elem_size) {
    struct rb_node *node =
            (struct rb_node*)_AVS_RB_ALLOC(_AVS_NODE_SPACE__ + elem_size);
    void *elem = (char*)node + _AVS_NODE_SPACE__;
    rb_node_init_magic(node);

    assert(_AVS_RB_NODE_VALID(elem));
    return elem;
}

static void *rb_find_parent(struct rb_tree *tree,
                            void *elem,
                            void ***out_ptr) {
    void *parent = NULL;
    void **curr = NULL;

    assert(tree);
    assert(elem);
    assert(_AVS_RB_NODE_VALID(elem));

    curr = &tree->root;

    while (*curr) {
        int cmp;

        assert(_AVS_RB_NODE_VALID(*curr));

        cmp = tree->cmp(elem, *curr);
        if (cmp == 0) {
            break;
        }

        parent = *curr;
        if (cmp < 0) {
            curr = _AVS_RB_LEFT_PTR(*curr);
        } else {
            curr = _AVS_RB_RIGHT_PTR(*curr);
        }
    }

    *out_ptr = curr;
    return parent;
}

static void **rb_find_ptr(struct rb_tree *tree,
                          const void *elem) {
    void **curr = NULL;

    assert(tree);
    assert(elem);

    curr = &tree->root;

    while (*curr) {
        int cmp;

        assert(_AVS_RB_NODE_VALID(*curr));

        cmp = tree->cmp(elem, *curr);
        if (cmp < 0) {
            curr = _AVS_RB_LEFT_PTR(*curr);
        } else if (cmp > 0) {
            curr = _AVS_RB_RIGHT_PTR(*curr);
        } else {
            return curr;
        }
    }

    return curr;
}

void *_avs_rb_tree_find(void **tree,
                        const void *val) {
    void **elem_ptr = NULL;

    assert(_AVS_RB_TREE_VALID(tree));

    elem_ptr = rb_find_ptr(_AVS_RB_TREE(tree), val);
    return elem_ptr ? *elem_ptr : NULL;
}

static void *rb_sibling(void *elem,
                        void *parent) {
    void *p_left = NULL;
    void *p_right = NULL;

    assert(!elem || _AVS_RB_NODE_VALID(elem));

    assert(parent);
    assert(_AVS_RB_NODE_VALID(parent));

    p_left = _AVS_RB_LEFT(parent);
    p_right = _AVS_RB_RIGHT(parent);
    assert(_AVS_RB_NODE_VALID(p_left));
    assert(_AVS_RB_NODE_VALID(p_right));

    if (elem == p_left) {
        return p_right;
    } else {
        assert(elem == p_right);
        return p_left;
    }
}

/**
 * Returns a reference to parent's pointer to @p node.
 * If @p node is the root, returns a root reference from the @p tree.
 */
static void **rb_own_parent_ptr(struct rb_tree *tree,
                                void *node) {
    void *parent = _AVS_RB_PARENT(node);
    if (!parent) {
        return &tree->root;
    }

    if (_AVS_RB_LEFT(parent) == node) {
        return _AVS_RB_LEFT_PTR(parent);
    } else {
        assert(_AVS_RB_RIGHT(parent) == node);
        return _AVS_RB_RIGHT_PTR(parent);
    }
}

void _avs_rb_rotate_left(struct rb_tree *tree,
                         void *root) {
    void *parent = _AVS_RB_PARENT(root);
    void **own_parent_ptr = rb_own_parent_ptr(tree, root);
    void *pivot = NULL;
    void *grandchild = NULL;

    assert(own_parent_ptr);

    pivot = _AVS_RB_RIGHT(root);
    assert(pivot);
    assert(_AVS_RB_NODE_VALID(pivot));

    *own_parent_ptr = pivot;
    _AVS_RB_PARENT(pivot) = parent;

    grandchild = _AVS_RB_LEFT(pivot);
    _AVS_RB_LEFT(pivot) = root;
    _AVS_RB_PARENT(root) = pivot;

    _AVS_RB_RIGHT(root) = grandchild;
    if (grandchild) {
        _AVS_RB_PARENT(grandchild) = root;
    }
}

void _avs_rb_rotate_right(struct rb_tree *tree,
                          void *root) {
    void *parent = _AVS_RB_PARENT(root);
    void **own_parent_ptr = rb_own_parent_ptr(tree, root);
    void *pivot = NULL;
    void *grandchild = NULL;

    assert(own_parent_ptr);

    pivot = _AVS_RB_LEFT(root);
    assert(pivot);
    assert(_AVS_RB_NODE_VALID(pivot));

    *own_parent_ptr = pivot;
    _AVS_RB_PARENT(pivot) = parent;

    grandchild = _AVS_RB_RIGHT(pivot);
    _AVS_RB_RIGHT(pivot) = root;
    _AVS_RB_PARENT(root) = pivot;

    _AVS_RB_LEFT(root) = grandchild;
    if (grandchild) {
        _AVS_RB_PARENT(grandchild) = root;
    }
}

static void rb_insert_fix(struct rb_tree *tree,
                          void *elem) {
    void *parent = NULL;
    void *grandparent = NULL;
    void *uncle = NULL;

    /* case 1 */
    if (elem == tree->root) {
        _AVS_RB_NODE(elem)->color = BLACK;
        return;
    }

    _AVS_RB_NODE(elem)->color = RED;

    /* case 2 */
    parent = _AVS_RB_PARENT(elem);
    if (_avs_rb_node_color(parent) == BLACK) {
        return;
    }

    /* case 3 */
    grandparent = _AVS_RB_PARENT(parent);
    uncle = rb_sibling(parent, grandparent);

    if (_avs_rb_node_color(uncle) == RED) {
        _AVS_RB_NODE(parent)->color = BLACK;
        _AVS_RB_NODE(uncle)->color = BLACK;
        _AVS_RB_NODE(grandparent)->color = RED;
        rb_insert_fix(tree, grandparent);
        return;
    }

    /* case 4 */
    if (elem == _AVS_RB_RIGHT(parent)
            && parent == _AVS_RB_LEFT(grandparent)) {
        _avs_rb_rotate_left(tree, parent);
        elem = _AVS_RB_LEFT(elem);
    } else if (elem == _AVS_RB_LEFT(parent)
                   && parent == _AVS_RB_RIGHT(grandparent)) {
        _avs_rb_rotate_right(tree, parent);
        elem = _AVS_RB_RIGHT(elem);
    }

    /* case 5 */
    parent = _AVS_RB_PARENT(elem);
    grandparent = _AVS_RB_PARENT(parent);

    _AVS_RB_NODE(parent)->color = BLACK;
    _AVS_RB_NODE(grandparent)->color = RED;
    if (elem == _AVS_RB_LEFT(parent)) {
        _avs_rb_rotate_right(tree, grandparent);
    } else {
        _avs_rb_rotate_left(tree, grandparent);
    }
}

int _avs_rb_tree_attach(AVS_RB_TREE(void) tree_,
                        AVS_RB_NODE(void) elem) {
    struct rb_tree *tree = _AVS_RB_TREE(tree_);
    void **dst = NULL;
    void *parent = NULL;

    assert(tree_);
    assert(elem);
    assert(rb_is_node_detached(elem));

    parent = rb_find_parent(tree, elem, &dst);
    assert(dst);

    if (*dst) {
        /* already present */
        return -1;
    } else {
        *dst = elem;
        _AVS_RB_PARENT(elem) = parent;
    }

    rb_insert_fix(tree, elem);
    _AVS_RB_NODE_SET_TREE_MAGIC(elem, _AVS_RB_TREE_MAGIC(tree));
    return 0;
}

static AVS_RB_NODE(void) rb_min(void *root) {
    void *min = root;
    void *left = root;

    assert(root);

    do {
        min = left;
        left = _AVS_RB_LEFT(min);
    } while (left);

    return min;
}

AVS_RB_NODE(void) _avs_rb_tree_first(AVS_RB_TREE(void) tree) {
    return rb_min(_AVS_RB_TREE(tree)->root);
}

static AVS_RB_NODE(void) rb_max(AVS_RB_NODE(void) root) {
    void *max = root;
    void *right = root;

    assert(root);

    do {
        max = right;
        right = _AVS_RB_RIGHT(max);
    } while (right);

    return max;
}

AVS_RB_NODE(void) _avs_rb_tree_last(AVS_RB_TREE(void) tree) {
    return rb_max(_AVS_RB_TREE(tree)->root);
}

AVS_RB_NODE(void) _avs_rb_next(AVS_RB_NODE(void) elem) {
    void *right = _AVS_RB_RIGHT(elem);
    void *parent = NULL;
    void *curr = NULL;

    if (right) {
        return rb_min(right);
    }

    parent = _AVS_RB_PARENT(elem);
    curr = elem;
    while (parent && _AVS_RB_RIGHT(parent) == curr) {
        curr = parent;
        parent = _AVS_RB_PARENT(parent);
    }

    return parent;
}

void *_avs_rb_prev(void *elem) {
    void *left = _AVS_RB_LEFT(elem);
    void *parent = NULL;
    void *curr = NULL;

    if (left) {
        return rb_max(left);
    }

    parent = _AVS_RB_PARENT(elem);
    curr = elem;
    while (parent && _AVS_RB_LEFT(parent) == curr) {
        curr = parent;
        parent = _AVS_RB_PARENT(parent);
    }

    return parent;
}

static void swap(void **a,
                 void **b) {
    void *tmp;

    assert(a);
    assert(b);

    tmp = *a;
    *a = *b;
    *b = tmp;
}

/**
 * Swaps parent/left/right pointers and color. Retains value.
 */
void _avs_rb_swap_nodes(struct rb_tree *tree,
                        void *a,
                        void *b) {
    void **a_parent_ptr = NULL;
    void **b_parent_ptr = NULL;
    enum rb_color col;

    assert(a);
    assert(b);

    if (a == b) {
        return;
    }

    a_parent_ptr = rb_own_parent_ptr(tree, a);
    b_parent_ptr = rb_own_parent_ptr(tree, b);

    /* simply swapping pointers in case where one node is a parent of
     * another would set parent pointer of the former parent to itself */
    if (_AVS_RB_PARENT(a) == b) {
        _AVS_RB_PARENT(a) = a;
    } else if (_AVS_RB_PARENT(b) == a) {
        _AVS_RB_PARENT(b) = b;
    }

    swap(a_parent_ptr, b_parent_ptr);
    swap(_AVS_RB_PARENT_PTR(a), _AVS_RB_PARENT_PTR(b));

    swap(_AVS_RB_LEFT_PTR(a), _AVS_RB_LEFT_PTR(b));
    if (_AVS_RB_LEFT(a)) {
        void *left = _AVS_RB_LEFT(a);
        _AVS_RB_PARENT(left) = a;
    }
    if (_AVS_RB_LEFT(b)) {
        void *left = _AVS_RB_LEFT(b);
        _AVS_RB_PARENT(left) = b;
    }

    swap(_AVS_RB_RIGHT_PTR(a), _AVS_RB_RIGHT_PTR(b));
    if (_AVS_RB_RIGHT(a)) {
        void *right = _AVS_RB_RIGHT(a);
        _AVS_RB_PARENT(right) = a;
    }
    if (_AVS_RB_RIGHT(b)) {
        void *right = _AVS_RB_RIGHT(b);
        _AVS_RB_PARENT(right) = b;
    }

    col = _avs_rb_node_color(a);
    _AVS_RB_NODE(a)->color = _avs_rb_node_color(b);
    _AVS_RB_NODE(b)->color = col;
}

static void rb_detach_fix(struct rb_tree *tree,
                          void *elem,
                          void *parent) {
    void *sibling = NULL;

    assert(_avs_rb_node_color(elem) == BLACK);

    /* case 1 */
    if (!parent) {
        return;
    }

    /* case 2 */
    sibling = rb_sibling(elem, parent);
    if (_avs_rb_node_color(sibling) == RED) {
        _AVS_RB_NODE(parent)->color = RED;
        _AVS_RB_NODE(sibling)->color = BLACK;

        if (elem == _AVS_RB_LEFT(parent)) {
            _avs_rb_rotate_left(tree, parent);
        } else {
            _avs_rb_rotate_right(tree, parent);
        }
    }

    /* case 3 */
    sibling = rb_sibling(elem, parent);
    if (_avs_rb_node_color(parent) == BLACK
            && _avs_rb_node_color(sibling) == BLACK
            && _avs_rb_node_color(_AVS_RB_LEFT(sibling)) == BLACK
            && _avs_rb_node_color(_AVS_RB_RIGHT(sibling)) == BLACK) {
        _AVS_RB_NODE(sibling)->color = RED;
        rb_detach_fix(tree, parent, _AVS_RB_PARENT(parent));
        return;
    }

    /* case 4 */
    if (_avs_rb_node_color(parent) == RED
            && _avs_rb_node_color(sibling) == BLACK
            && _avs_rb_node_color(_AVS_RB_LEFT(sibling)) == BLACK
            && _avs_rb_node_color(_AVS_RB_RIGHT(sibling)) == BLACK) {
        _AVS_RB_NODE(sibling)->color = RED;
        _AVS_RB_NODE(parent)->color = BLACK;
        return;
    }

    /* case 5 */
    assert(sibling);
    assert(_avs_rb_node_color(sibling) == BLACK);
    if (elem == _AVS_RB_LEFT(parent)
            && _avs_rb_node_color(_AVS_RB_RIGHT(sibling)) == BLACK) {
        assert(_avs_rb_node_color(_AVS_RB_LEFT(sibling)) == RED);

        _AVS_RB_NODE(sibling)->color = RED;
        _AVS_RB_NODE(_AVS_RB_LEFT(sibling))->color = BLACK;
        _avs_rb_rotate_right(tree, sibling);
    } else if (elem == _AVS_RB_RIGHT(parent)
               && _avs_rb_node_color(_AVS_RB_LEFT(sibling)) == BLACK) {
        assert(_avs_rb_node_color(_AVS_RB_RIGHT(sibling)) == RED);

        _AVS_RB_NODE(sibling)->color = RED;
        _AVS_RB_NODE(_AVS_RB_RIGHT(sibling))->color = BLACK;
        _avs_rb_rotate_left(tree, sibling);
    }

    /* case 6 */
    sibling = rb_sibling(elem, parent);

    _AVS_RB_NODE(sibling)->color = _avs_rb_node_color(parent);
    _AVS_RB_NODE(parent)->color = BLACK;

    if (elem == _AVS_RB_LEFT(parent)) {
        _AVS_RB_NODE(_AVS_RB_RIGHT(sibling))->color = BLACK;
        _avs_rb_rotate_left(tree, parent);
    } else {
        _AVS_RB_NODE(_AVS_RB_LEFT(sibling))->color = BLACK;
        _avs_rb_rotate_right(tree, parent);
    }
}

void *_avs_rb_tree_detach(void **tree_,
                          void *elem) {
    struct rb_tree *tree = _AVS_RB_TREE(tree_);
    void *left = NULL;
    void *right = NULL;
    void *child = NULL;
    void *parent = NULL;

    if (!elem) {
        return NULL;
    }

    assert(tree_);
    assert(elem);
    assert(_AVS_RB_NODE_TREE_MAGIC(elem) == _AVS_RB_TREE_MAGIC(tree)
           && "node not attached to given tree");

    left = _AVS_RB_LEFT(elem);
    right = _AVS_RB_RIGHT(elem);

    if (left && right) {
        void *replacement = _avs_rb_next(elem);
        _avs_rb_swap_nodes(tree, elem, replacement);
        return _avs_rb_tree_detach(tree_, elem);
    }

    child = left ? left : right;
    parent = _AVS_RB_PARENT(elem);

    if (child) {
        assert(_AVS_RB_PARENT(child) == elem);
        _AVS_RB_PARENT(child) = parent;
    }

    *rb_own_parent_ptr(tree, elem) = child;
    _AVS_RB_PARENT(elem) = NULL;
    _AVS_RB_LEFT(elem) = NULL;
    _AVS_RB_RIGHT(elem) = NULL;

    assert(_avs_rb_node_color(elem) == BLACK || _avs_rb_node_color(child) == BLACK);
    if (_avs_rb_node_color(elem) == RED
            || _avs_rb_node_color(child) == RED) {
        if (child) {
            /* if elem is red, child is already black
             * if child is red, we need to repaint it */
            _AVS_RB_NODE(child)->color = BLACK;
        }

        return elem;
    }

    /* both node and child are black */
    rb_detach_fix(tree, child, parent);
    _AVS_RB_NODE_SET_TREE_MAGIC(elem, 0);

    assert(_avs_rb_node_color(tree->root) == BLACK);
    return elem;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_rbtree.c"
#endif
