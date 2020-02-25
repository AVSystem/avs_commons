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
#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_RBTREE

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_rbtree.h>

#    include <assert.h>

VISIBILITY_SOURCE_BEGIN

enum rb_color { DETACHED = 0x50DD, RED = 0x50DE, BLACK = 0x50DF };

struct rb_node {
    enum rb_color color;
    void *parent;
    void *left;
    void *right;
};

struct rb_node_space {
    struct rb_node node;
    avs_max_align_t value;
};

struct rb_tree {
    size_t size;
    avs_rbtree_element_comparator_t *cmp;
    void *root;
};

#    define _AVS_NODE_SPACE__ offsetof(struct rb_node_space, value)

#    define _AVS_RB_NODE(elem) \
        ((struct rb_node *) ((char *) (elem) -_AVS_NODE_SPACE__))
#    define _AVS_RB_NODE_CONST(elem) \
        ((const struct rb_node *) ((const char *) (elem) -_AVS_NODE_SPACE__))

#    define _AVS_RB_TREE(ptr) AVS_CONTAINER_OF((ptr), struct rb_tree, root)

#    define _AVS_RB_ALLOC(size) avs_calloc(1, size)
#    define _AVS_RB_DEALLOC(ptr) avs_free(ptr)

#    define _AVS_RB_LEFT_PTR(elem) \
        ((AVS_TYPEOF_PTR(elem) *) &(_AVS_RB_NODE(elem)->left))
#    define _AVS_RB_LEFT_PTR_CONST(elem) \
        ((AVS_TYPEOF_PTR(elem) const *) &(_AVS_RB_NODE_CONST(elem)->left))

#    define _AVS_RB_LEFT(elem) (*_AVS_RB_LEFT_PTR(elem))
#    define _AVS_RB_LEFT_CONST(elem) (*_AVS_RB_LEFT_PTR_CONST(elem))

#    define _AVS_RB_RIGHT_PTR(elem) \
        ((AVS_TYPEOF_PTR(elem) *) &(_AVS_RB_NODE(elem)->right))
#    define _AVS_RB_RIGHT_PTR_CONST(elem) \
        ((AVS_TYPEOF_PTR(elem) const *) &(_AVS_RB_NODE_CONST(elem)->right))

#    define _AVS_RB_RIGHT(elem) (*_AVS_RB_RIGHT_PTR(elem))
#    define _AVS_RB_RIGHT_CONST(elem) (*_AVS_RB_RIGHT_PTR_CONST(elem))

#    define _AVS_RB_PARENT_PTR(elem) \
        ((AVS_TYPEOF_PTR(elem) *) &(_AVS_RB_NODE(elem)->parent))
#    define _AVS_RB_PARENT_PTR_CONST(elem) \
        ((AVS_TYPEOF_PTR(elem) const *) &(_AVS_RB_NODE_CONST(elem)->parent))

#    define _AVS_RB_PARENT(elem) (*_AVS_RB_PARENT_PTR(elem))
#    define _AVS_RB_PARENT_CONST(elem) (*_AVS_RB_PARENT_PTR_CONST(elem))

enum rb_color _avs_rb_node_color(void *elem);

#    ifdef AVS_UNIT_TESTING
static void *test_rb_alloc(size_t num_bytes);
static void test_rb_dealloc(void *ptr);

#        undef _AVS_RB_ALLOC
#        undef _AVS_RB_DEALLOC
#        define _AVS_RB_ALLOC test_rb_alloc
#        define _AVS_RB_DEALLOC test_rb_dealloc
#    endif

#    ifndef NDEBUG
static int rb_is_cleanup_in_progress(AVS_RBTREE_CONST(void) tree) {
    return *tree && (_AVS_RB_PARENT_CONST(*tree) != NULL);
}

static int rb_is_node_detached(AVS_RBTREE_ELEM(void) elem) {
    return _AVS_RB_NODE(elem)->color == DETACHED && _AVS_RB_PARENT(elem) == NULL
           && _AVS_RB_LEFT(elem) == NULL && _AVS_RB_RIGHT(elem) == NULL;
}

static AVS_RBTREE_CONST(void) rb_tree_const(AVS_RBTREE(void) tree) {
    return (AVS_RBTREE_CONST(void))(intptr_t) tree;
}

static int rb_is_node_owner(AVS_RBTREE(void) tree, AVS_RBTREE_ELEM(void) elem) {
    while (elem && elem != _AVS_RB_TREE(tree)->root) {
        elem = _AVS_RB_PARENT(elem);
    }
    return elem == _AVS_RB_TREE(tree)->root;
}
#    else
#        define rb_is_cleanup_in_progress(_) 0
#        define rb_is_node_owner(...) 1
#    endif

enum rb_color _avs_rb_node_color(AVS_RBTREE_ELEM(void) elem) {
    if (!elem) {
        return BLACK;
    } else {
        /* checking the color of a detached node is pointless, so
         * this function should never be called on one */
        assert(_AVS_RB_NODE(elem)->color == RED
               || _AVS_RB_NODE(elem)->color == BLACK);
        return _AVS_RB_NODE(elem)->color;
    }
}

AVS_RBTREE(void) avs_rbtree_new__(avs_rbtree_element_comparator_t *cmp) {
    struct rb_tree *tree =
            (struct rb_tree *) _AVS_RB_ALLOC(sizeof(struct rb_tree));
    if (!tree) {
        return NULL;
    }

    tree->cmp = cmp;
    tree->root = NULL;

    return &tree->root;
}

void avs_rbtree_elem_delete__(AVS_RBTREE_ELEM(void) *node_ptr) {
    if (node_ptr && *node_ptr) {
        assert(rb_is_node_detached(*node_ptr));
        _AVS_RB_DEALLOC(_AVS_RB_NODE(*node_ptr));
        *node_ptr = NULL;
    }
}

void avs_rbtree_delete__(AVS_RBTREE(void) *tree_ptr) {
    struct rb_tree *tree;

    if (!tree_ptr || !*tree_ptr) {
        return;
    }

    assert(!**tree_ptr); /* should only be called on empty trees */
    tree = _AVS_RB_TREE(*tree_ptr);
    _AVS_RB_DEALLOC(tree);
    *tree_ptr = NULL;
}

static void rb_subtree_delete(AVS_RBTREE_ELEM(void) elem) {
    if (elem) {
        rb_subtree_delete(_AVS_RB_LEFT(elem));
        rb_subtree_delete(_AVS_RB_RIGHT(elem));
        _AVS_RB_DEALLOC(_AVS_RB_NODE(elem));
    }
}

static AVS_RBTREE_ELEM(void) rb_subtree_clone(AVS_RBTREE_ELEM(void) node,
                                              AVS_RBTREE_ELEM(void) new_parent,
                                              size_t elem_size) {
    if (!node) {
        return NULL;
    }

    AVS_RBTREE_ELEM(void) left = _AVS_RB_LEFT(node);
    AVS_RBTREE_ELEM(void) right = _AVS_RB_RIGHT(node);

    AVS_RBTREE_ELEM(void) clone = AVS_RBTREE_ELEM_NEW_BUFFER(elem_size);
    if (!clone) {
        return NULL;
    }

    if ((left
         && !(_AVS_RB_LEFT(clone) = rb_subtree_clone(left, clone, elem_size)))
            || (right
                && !(_AVS_RB_RIGHT(clone) =
                             rb_subtree_clone(right, clone, elem_size)))) {
        rb_subtree_delete(clone);
        return NULL;
    }

    _AVS_RB_NODE(clone)->color = _AVS_RB_NODE(node)->color;
    _AVS_RB_PARENT(clone) = new_parent;
    memcpy(clone, node, elem_size);
    return clone;
}

AVS_RBTREE(void) avs_rbtree_simple_clone__(AVS_RBTREE_CONST(void) tree,
                                           size_t elem_size) {
    assert(tree);
    AVS_RBTREE(void) result = avs_rbtree_new__(_AVS_RB_TREE(tree)->cmp);
    if (result && *tree) {
        *result = rb_subtree_clone((AVS_RBTREE_ELEM(void)) (intptr_t) *tree,
                                   NULL, elem_size);
        if (!*result) {
            avs_rbtree_delete__(&result);
        } else {
            _AVS_RB_TREE(result)->size = AVS_RBTREE_SIZE(tree);
        }
    }
    return result;
}

size_t avs_rbtree_size__(AVS_RBTREE_CONST(void) tree) {
    AVS_ASSERT(!rb_is_cleanup_in_progress(tree),
               "avs_rbtree_size__ called while tree deletion in progress");
    return _AVS_RB_TREE(tree)->size;
}

AVS_RBTREE_ELEM(void) avs_rbtree_elem_new_buffer__(size_t elem_size) {
    struct rb_node *node =
            (struct rb_node *) _AVS_RB_ALLOC(_AVS_NODE_SPACE__ + elem_size);
    if (!node) {
        return NULL;
    }

    node->color = DETACHED;

    return (char *) node + _AVS_NODE_SPACE__;
}

static AVS_RBTREE_ELEM(void) *
rb_find_ptr(struct rb_tree *tree,
            const void *val,
            AVS_RBTREE_ELEM(void) *out_parent_of_found) {
    AVS_RBTREE_ELEM(void) parent = NULL;
    AVS_RBTREE_ELEM(void) *curr = NULL;

    assert(tree);
    assert(val);

    curr = &tree->root;

    while (*curr) {
        int cmp = tree->cmp(val, *curr);

        if (cmp == 0) {
            break;
        } else {
            parent = *curr;
            curr = (cmp < 0) ? _AVS_RB_LEFT_PTR(*curr)
                             : _AVS_RB_RIGHT_PTR(*curr);
        }
    }

    if (out_parent_of_found) {
        *out_parent_of_found = parent;
    }
    return curr;
}

AVS_RBTREE_ELEM(void) avs_rbtree_lower_bound__(AVS_RBTREE_CONST(void) tree,
                                               const void *value) {
    AVS_RBTREE_ELEM(void) curr;
    AVS_RBTREE_ELEM(void) result;

    AVS_ASSERT(
            !rb_is_cleanup_in_progress(tree),
            "avs_rbtree_lower_bound__ called while tree deletion in progress");

    assert(tree);
    assert(value);

    curr = *(AVS_RBTREE(void)) (intptr_t) tree;
    result = NULL;

    while (curr) {
        if (_AVS_RB_TREE(tree)->cmp(value, curr) <= 0) {
            result = curr;
            curr = _AVS_RB_LEFT(curr);
        } else {
            curr = _AVS_RB_RIGHT(curr);
        }
    }
    return result;
}

AVS_RBTREE_ELEM(void) avs_rbtree_upper_bound__(AVS_RBTREE_CONST(void) tree,
                                               const void *value) {
    AVS_RBTREE_ELEM(void) curr;
    AVS_RBTREE_ELEM(void) result;

    AVS_ASSERT(
            !rb_is_cleanup_in_progress(tree),
            "avs_rbtree_upper_bound__ called while tree deletion in progress");

    assert(tree);
    assert(value);

    curr = *(AVS_RBTREE(void)) (intptr_t) tree;
    result = NULL;

    while (curr) {
        if (_AVS_RB_TREE(tree)->cmp(value, curr) < 0) {
            result = curr;
            curr = _AVS_RB_LEFT(curr);
        } else {
            curr = _AVS_RB_RIGHT(curr);
        }
    }
    return result;
}

AVS_RBTREE_ELEM(void) avs_rbtree_find__(AVS_RBTREE_CONST(void) tree,
                                        const void *val) {
    AVS_RBTREE_ELEM(void) *elem_ptr;

    AVS_ASSERT(!rb_is_cleanup_in_progress(tree),
               "avs_rbtree_find__ called while tree deletion in progress");

    elem_ptr = rb_find_ptr(_AVS_RB_TREE((AVS_RBTREE(void)) (intptr_t) tree),
                           val, NULL);
    return elem_ptr ? *elem_ptr : NULL;
}

static AVS_RBTREE_ELEM(void) rb_sibling(AVS_RBTREE_ELEM(void) elem,
                                        AVS_RBTREE_ELEM(void) parent) {
    AVS_RBTREE_ELEM(void) p_left = NULL;
    AVS_RBTREE_ELEM(void) p_right = NULL;

    assert(parent);

    p_left = _AVS_RB_LEFT(parent);
    p_right = _AVS_RB_RIGHT(parent);

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
static AVS_RBTREE_ELEM(void) *rb_own_parent_ptr(struct rb_tree *tree,
                                                AVS_RBTREE_ELEM(void) node) {
    AVS_RBTREE_ELEM(void) parent = _AVS_RB_PARENT(node);
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

/**
 *      (parent)                 (parent)
 *         |                        |
 *         |                        |
 *       (root)                  (pivot)
 *        /  \         -->        /   \
 *       /    \                  /     \
 *     (A)  (pivot)           (root)   (B)
 *           /   \             /  \
 *          /     \           /    \
 *  (grandchild)  (B)       (A)  (grandchild)
 */
static void rb_rotate_left(struct rb_tree *tree, AVS_RBTREE_ELEM(void) root) {
    AVS_RBTREE_ELEM(void) parent = _AVS_RB_PARENT(root);
    AVS_RBTREE_ELEM(void) *own_parent_ptr = rb_own_parent_ptr(tree, root);
    AVS_RBTREE_ELEM(void) pivot = NULL;
    AVS_RBTREE_ELEM(void) grandchild = NULL;

    assert(own_parent_ptr);

    pivot = _AVS_RB_RIGHT(root);
    assert(pivot);

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

/**
 *       (parent)                 (parent)
 *          |                        |
 *          |                        |
 *        (root)                  (pivot)
 *         /  \         -->        /   \
 *        /    \                  /     \
 *    (pivot)  (A)              (B)    (root)
 *     /   \                            /  \
 *    /     \                          /    \
 *  (B)  (grandchild)         (grandchild)  (A)
 */
static void rb_rotate_right(struct rb_tree *tree, AVS_RBTREE_ELEM(void) root) {
    AVS_RBTREE_ELEM(void) parent = _AVS_RB_PARENT(root);
    AVS_RBTREE_ELEM(void) *own_parent_ptr = rb_own_parent_ptr(tree, root);
    AVS_RBTREE_ELEM(void) pivot = NULL;
    AVS_RBTREE_ELEM(void) grandchild = NULL;

    assert(own_parent_ptr);

    pivot = _AVS_RB_LEFT(root);
    assert(pivot);

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

static void rb_insert_fix(struct rb_tree *tree, AVS_RBTREE_ELEM(void) elem) {
    AVS_RBTREE_ELEM(void) parent = NULL;
    AVS_RBTREE_ELEM(void) grandparent = NULL;
    AVS_RBTREE_ELEM(void) uncle = NULL;

    /* case 1 */
    if (elem == tree->root) {
        _AVS_RB_NODE(elem)->color = BLACK;
        return;
    }

    _AVS_RB_NODE(elem)->color = RED;

    /* case 2 */
    parent = _AVS_RB_PARENT(elem);
    assert(parent);
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
    if (elem == _AVS_RB_RIGHT(parent) && parent == _AVS_RB_LEFT(grandparent)) {
        rb_rotate_left(tree, parent);
        elem = _AVS_RB_LEFT(elem);
    } else if (elem == _AVS_RB_LEFT(parent)
               && parent == _AVS_RB_RIGHT(grandparent)) {
        rb_rotate_right(tree, parent);
        elem = _AVS_RB_RIGHT(elem);
    }

    /* case 5 */
    parent = _AVS_RB_PARENT(elem);
    assert(grandparent == _AVS_RB_PARENT(parent));

    _AVS_RB_NODE(parent)->color = BLACK;
    _AVS_RB_NODE(grandparent)->color = RED;
    if (elem == _AVS_RB_LEFT(parent)) {
        rb_rotate_right(tree, grandparent);
    } else {
        rb_rotate_left(tree, grandparent);
    }
}

AVS_RBTREE_ELEM(void) avs_rbtree_attach__(AVS_RBTREE(void) tree_,
                                          AVS_RBTREE_ELEM(void) elem) {
    struct rb_tree *tree = _AVS_RB_TREE(tree_);
    AVS_RBTREE_ELEM(void) *dst = NULL;
    AVS_RBTREE_ELEM(void) parent = NULL;

    AVS_ASSERT(!rb_is_cleanup_in_progress(rb_tree_const(tree_)),
               "avs_rbtree_attach__ called while tree deletion in progress");
    assert(tree_);
    assert(elem);
    assert(rb_is_node_detached(elem));

    dst = rb_find_ptr(tree, elem, &parent);
    assert(dst);

    if (*dst) {
        /* already present */
        return *dst;
    } else {
        *dst = elem;
        _AVS_RB_PARENT(elem) = parent;
        ++tree->size;
    }

    rb_insert_fix(tree, elem);
    return elem;
}

static AVS_RBTREE_ELEM(void) rb_min(AVS_RBTREE_ELEM(void) root) {
    AVS_RBTREE_ELEM(void) min = root;
    AVS_RBTREE_ELEM(void) left = root;

    if (!root) {
        return NULL;
    }

    do {
        min = left;
        left = _AVS_RB_LEFT(min);
    } while (left);

    return min;
}

AVS_RBTREE_ELEM(void) avs_rbtree_first__(AVS_RBTREE(void) tree) {
    /* operation allowed while delete in progress to allow delete resumption */
    return rb_min(_AVS_RB_TREE(tree)->root);
}

static AVS_RBTREE_ELEM(void) rb_max(AVS_RBTREE_ELEM(void) root) {
    AVS_RBTREE_ELEM(void) max = root;
    AVS_RBTREE_ELEM(void) right = root;

    if (!root) {
        return NULL;
    }

    do {
        max = right;
        right = _AVS_RB_RIGHT(max);
    } while (right);

    return max;
}

AVS_RBTREE_ELEM(void) avs_rbtree_last__(AVS_RBTREE(void) tree) {
    AVS_ASSERT(!rb_is_cleanup_in_progress(rb_tree_const(tree)),
               "avs_rbtree_last__ called while tree deletion in progress");
    return rb_max(_AVS_RB_TREE(tree)->root);
}

AVS_RBTREE_ELEM(void) avs_rbtree_elem_next__(AVS_RBTREE_ELEM(void) elem) {
    AVS_RBTREE_ELEM(void) right = _AVS_RB_RIGHT(elem);
    AVS_RBTREE_ELEM(void) parent = NULL;
    AVS_RBTREE_ELEM(void) curr = NULL;

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

AVS_RBTREE_ELEM(void) avs_rbtree_elem_prev__(AVS_RBTREE_ELEM(void) elem) {
    AVS_RBTREE_ELEM(void) left = _AVS_RB_LEFT(elem);
    AVS_RBTREE_ELEM(void) parent = NULL;
    AVS_RBTREE_ELEM(void) curr = NULL;

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

static void swap(void **a, void **b) {
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
static void rb_swap_nodes(struct rb_tree *tree,
                          AVS_RBTREE_ELEM(void) a,
                          AVS_RBTREE_ELEM(void) b) {
    AVS_RBTREE_ELEM(void) *a_parent_ptr = NULL;
    AVS_RBTREE_ELEM(void) *b_parent_ptr = NULL;
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
        AVS_RBTREE_ELEM(void) left = _AVS_RB_LEFT(a);
        _AVS_RB_PARENT(left) = a;
    }
    if (_AVS_RB_LEFT(b)) {
        AVS_RBTREE_ELEM(void) left = _AVS_RB_LEFT(b);
        _AVS_RB_PARENT(left) = b;
    }

    swap(_AVS_RB_RIGHT_PTR(a), _AVS_RB_RIGHT_PTR(b));
    if (_AVS_RB_RIGHT(a)) {
        AVS_RBTREE_ELEM(void) right = _AVS_RB_RIGHT(a);
        _AVS_RB_PARENT(right) = a;
    }
    if (_AVS_RB_RIGHT(b)) {
        AVS_RBTREE_ELEM(void) right = _AVS_RB_RIGHT(b);
        _AVS_RB_PARENT(right) = b;
    }

    col = _avs_rb_node_color(a);
    _AVS_RB_NODE(a)->color = _avs_rb_node_color(b);
    _AVS_RB_NODE(b)->color = col;
}

static void rb_detach_fix(struct rb_tree *tree,
                          AVS_RBTREE_ELEM(void) elem,
                          AVS_RBTREE_ELEM(void) parent) {
    AVS_RBTREE_ELEM(void) sibling = NULL;

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
            rb_rotate_left(tree, parent);
        } else {
            rb_rotate_right(tree, parent);
        }

        sibling = rb_sibling(elem, parent);
    }

    assert(sibling);
    assert(_avs_rb_node_color(sibling) == BLACK);

    /* case 3 */
    if (_avs_rb_node_color(parent) == BLACK
            && _avs_rb_node_color(_AVS_RB_LEFT(sibling)) == BLACK
            && _avs_rb_node_color(_AVS_RB_RIGHT(sibling)) == BLACK) {
        _AVS_RB_NODE(sibling)->color = RED;
        rb_detach_fix(tree, parent, _AVS_RB_PARENT(parent));
        return;
    }

    /* case 4 */
    if (_avs_rb_node_color(parent) == RED
            && _avs_rb_node_color(_AVS_RB_LEFT(sibling)) == BLACK
            && _avs_rb_node_color(_AVS_RB_RIGHT(sibling)) == BLACK) {
        _AVS_RB_NODE(sibling)->color = RED;
        _AVS_RB_NODE(parent)->color = BLACK;
        return;
    }

    /* case 5 */
    if (elem == _AVS_RB_LEFT(parent)
            && _avs_rb_node_color(_AVS_RB_RIGHT(sibling)) == BLACK) {
        assert(_avs_rb_node_color(_AVS_RB_LEFT(sibling)) == RED);

        _AVS_RB_NODE(sibling)->color = RED;
        _AVS_RB_NODE(_AVS_RB_LEFT(sibling))->color = BLACK;
        rb_rotate_right(tree, sibling);
    } else if (elem == _AVS_RB_RIGHT(parent)
               && _avs_rb_node_color(_AVS_RB_LEFT(sibling)) == BLACK) {
        assert(_avs_rb_node_color(_AVS_RB_RIGHT(sibling)) == RED);

        _AVS_RB_NODE(sibling)->color = RED;
        _AVS_RB_NODE(_AVS_RB_RIGHT(sibling))->color = BLACK;
        rb_rotate_left(tree, sibling);
    }

    /* case 6 */
    sibling = rb_sibling(elem, parent);

    _AVS_RB_NODE(sibling)->color = _avs_rb_node_color(parent);
    _AVS_RB_NODE(parent)->color = BLACK;

    if (elem == _AVS_RB_LEFT(parent)) {
        assert(_AVS_RB_RIGHT(sibling));

        _AVS_RB_NODE(_AVS_RB_RIGHT(sibling))->color = BLACK;
        rb_rotate_left(tree, parent);
    } else {
        assert(_AVS_RB_LEFT(sibling));

        _AVS_RB_NODE(_AVS_RB_LEFT(sibling))->color = BLACK;
        rb_rotate_right(tree, parent);
    }
}

AVS_RBTREE_ELEM(void) avs_rbtree_detach__(AVS_RBTREE(void) tree_,
                                          AVS_RBTREE_ELEM(void) elem) {
    struct rb_tree *tree = _AVS_RB_TREE(tree_);
    AVS_RBTREE_ELEM(void) left = NULL;
    AVS_RBTREE_ELEM(void) right = NULL;
    AVS_RBTREE_ELEM(void) child = NULL;
    AVS_RBTREE_ELEM(void) parent = NULL;
    enum rb_color elem_color;

    if (!elem) {
        return NULL;
    }

    AVS_ASSERT(!rb_is_node_detached(elem),
               "cannot detach an node that's already detached");
    AVS_ASSERT(!rb_is_cleanup_in_progress(rb_tree_const(tree_)),
               "avs_rbtree_detach__ called while tree deletion in progress");
    assert(tree_);
    assert(elem);
    AVS_ASSERT(rb_is_node_owner(tree_, elem),
               "cannot detach node not owned by the tree");

    left = _AVS_RB_LEFT(elem);
    right = _AVS_RB_RIGHT(elem);

    if (left && right) {
        AVS_RBTREE_ELEM(void) replacement = avs_rbtree_elem_next__(elem);
        rb_swap_nodes(tree, elem, replacement);

        assert(!_AVS_RB_LEFT(elem));
        left = NULL;
        right = _AVS_RB_RIGHT(elem);
    }

    child = left ? left : right;
    parent = _AVS_RB_PARENT(elem);

    if (child) {
        assert(_AVS_RB_PARENT(child) == elem);
        _AVS_RB_PARENT(child) = parent;
    }

    *rb_own_parent_ptr(tree, elem) = child;
    elem_color = _avs_rb_node_color(elem);
    _AVS_RB_NODE(elem)->color = DETACHED;
    _AVS_RB_PARENT(elem) = NULL;
    _AVS_RB_LEFT(elem) = NULL;
    _AVS_RB_RIGHT(elem) = NULL;
    assert(tree->size > 0u);
    --tree->size;

    assert(elem_color == BLACK || _avs_rb_node_color(child) == BLACK);
    if (elem_color == RED || _avs_rb_node_color(child) == RED) {
        if (child) {
            /* if elem is red, child is already black
             * if child is red, we need to repaint it */
            _AVS_RB_NODE(child)->color = BLACK;
        }

        return elem;
    }

    /* both node and child are black */
    rb_detach_fix(tree, child, parent);

    assert(_avs_rb_node_color(tree->root) == BLACK);
    return elem;
}

static AVS_RBTREE_ELEM(void) rb_postorder_first(AVS_RBTREE_ELEM(void) node) {
    while (node) {
        if (_AVS_RB_LEFT(node)) {
            node = _AVS_RB_LEFT(node);
        } else if (_AVS_RB_RIGHT(node)) {
            node = _AVS_RB_RIGHT(node);
        } else {
            return node;
        }
    }

    return NULL;
}

AVS_RBTREE_ELEM(void) avs_rbtree_cleanup_first__(AVS_RBTREE(void) tree) {
    return rb_postorder_first(*tree);
}

static AVS_RBTREE_ELEM(void) rb_postorder_next(AVS_RBTREE_ELEM(void) curr) {
    AVS_RBTREE_ELEM(void) parent = _AVS_RB_PARENT(curr);
    if (!parent) {
        return NULL;
    }

    if (_AVS_RB_RIGHT(parent) && _AVS_RB_RIGHT(parent) != curr) {
        return rb_postorder_first(_AVS_RB_RIGHT(parent));
    }

    return parent;
}

AVS_RBTREE_ELEM(void) avs_rbtree_cleanup_next__(AVS_RBTREE(void) tree) {
    AVS_RBTREE_ELEM(void) next;
    AVS_RBTREE_ELEM(void) *curr_ptr;

    next = rb_postorder_next(*tree);
    curr_ptr = rb_own_parent_ptr(_AVS_RB_TREE(tree), *tree);

    _AVS_RB_NODE(*tree)->color = DETACHED;
    _AVS_RB_PARENT(*tree) = NULL;
    assert(AVS_RBTREE_SIZE(tree) > 0u);
    --_AVS_RB_TREE(tree)->size;
    /* at this point, child nodes should be cleaned up */
    assert(_AVS_RB_LEFT(*tree) == NULL);
    assert(_AVS_RB_RIGHT(*tree) == NULL);

    avs_rbtree_elem_delete__(curr_ptr);

    return *tree = next;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/rbtree/test_rbtree.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_RBTREE
