#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <avsystem/commons/log.h>
#include <avsystem/commons/unit/test.h>

static int CONST_1 = 1;
static int CONST_2 = 2;
static int CONST_3 = 3;
static int CONST_4 = 4;
static int CONST_5 = 5;
static int CONST_6 = 6;
static int CONST_7 = 7;
static int CONST_8 = 8;

static int CONST_10 = 10;

static int CONST_12 = 12;

static int CONST_14 = 14;

static int int_comparator(const void *a_,
                          const void *b_) {
    int a = *(const int*)a_;
    int b = *(const int*)b_;
    return a < b ? -1
                 : (a == b ? 0 : 1);
}

static void assert_rb_properties_hold_recursive(void *node,
                                                size_t *out_black_height) {
    void *left = NULL;
    void *right = NULL;
    size_t left_black_height = 0;
    size_t right_black_height = 0;

    *out_black_height = 1;
    if (!node) {
        return;
    }

    left = _AVS_RB_LEFT(node);
    right = _AVS_RB_RIGHT(node);

    left_black_height = 0;
    if (left) {
        AVS_UNIT_ASSERT_TRUE(node == _AVS_RB_PARENT(left));
        assert_rb_properties_hold_recursive(left, &left_black_height);
    }

    right_black_height = 0;
    if (right) {
        AVS_UNIT_ASSERT_TRUE(node == _AVS_RB_PARENT(right));
        assert_rb_properties_hold_recursive(right, &right_black_height);
    }

    AVS_UNIT_ASSERT_EQUAL(left_black_height, right_black_height);
    *out_black_height = left_black_height;

    if (_avs_rb_node_color(node) == RED) {
        AVS_UNIT_ASSERT_EQUAL(BLACK, _avs_rb_node_color(left));
        AVS_UNIT_ASSERT_EQUAL(BLACK, _avs_rb_node_color(right));
    } else {
        ++*out_black_height;
    }
}

static void assert_rb_properties_hold(AVS_RBTREE(int) tree_) {
    struct rb_tree *tree = _AVS_RB_TREE(tree_);
    size_t black_height = 0;

    AVS_UNIT_ASSERT_EQUAL(BLACK, _avs_rb_node_color(tree->root));
    if (tree->root) {
        AVS_UNIT_ASSERT_NULL(_AVS_RB_PARENT(tree->root));
    }

    assert_rb_properties_hold_recursive(tree->root, &black_height);
}

/* terminated with 0 */
static AVS_RBTREE(int) make_tree(int first, ...) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);
    va_list list;
    int value = first;

    AVS_UNIT_ASSERT_NOT_NULL(tree);
    va_start(list, first);

    while (value != 0) {
        AVS_RBTREE_ELEM(int) elem = AVS_RBTREE_ELEM_NEW(int);
        AVS_UNIT_ASSERT_NOT_NULL(elem);

        *elem = value;
        AVS_UNIT_ASSERT_TRUE(elem == AVS_RBTREE_INSERT(tree, elem));

        value = va_arg(list, int);
    }

    va_end(list);

    assert_rb_properties_hold(tree);

    return tree;
}

static const char *get_color_name(enum rb_color color) {
    switch (color) {
    case DETACHED: return "DETACHED";
    case BLACK: return "BLACK";
    case RED: return "RED";
    }

    return "(invalid color)";
}

static void assert_node_equal(int *node,
                              int value,
                              enum rb_color color,
                              int *parent,
                              int *left,
                              int *right) {
    AVS_UNIT_ASSERT_EQUAL(value, *node);
    AVS_UNIT_ASSERT_EQUAL_STRING(get_color_name(color),
                                 get_color_name(_AVS_RB_NODE(node)->color));
    AVS_UNIT_ASSERT_TRUE(parent == _AVS_RB_PARENT(node));
    AVS_UNIT_ASSERT_TRUE(left == _AVS_RB_LEFT(node));
    AVS_UNIT_ASSERT_TRUE(right == _AVS_RB_RIGHT(node));
}

AVS_UNIT_TEST(rbtree, create) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);

    struct rb_tree *tree_struct = _AVS_RB_TREE(tree);
    AVS_UNIT_ASSERT_TRUE(tree_struct->cmp == int_comparator);
    AVS_UNIT_ASSERT_NULL(tree_struct->root);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, create_element) {
    AVS_RBTREE_ELEM(int) elem = AVS_RBTREE_ELEM_NEW(int);

    assert_node_equal(elem, 0, DETACHED, NULL, NULL, NULL);

    AVS_RBTREE_ELEM_DELETE_DETACHED(&elem);
}

AVS_UNIT_TEST(rbtree, delete) {
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);

    int expected_cleanup_order[] = {
        1, 3, 2, 5, 7, 6, 4, 9, 11, 10, 13, 15, 14, 12, 8
    };

    size_t i = 0;
    AVS_RBTREE_DELETE(&tree) {
        AVS_UNIT_ASSERT_EQUAL(**tree, expected_cleanup_order[i++]);
    }
}

AVS_UNIT_TEST(rbtree, delete_break_resume) {
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);

    int expected_cleanup_order[] = {
        1, 3, 2, 5, 7, 6, 4, 9, 11, 10, 13, 15, 14, 12, 8
    };

    size_t i = 0;
    AVS_RBTREE_DELETE(&tree) {
        AVS_UNIT_ASSERT_EQUAL(**tree, expected_cleanup_order[i]);
        break;
    }

    AVS_RBTREE_DELETE(&tree) {
        AVS_UNIT_ASSERT_EQUAL(**tree, expected_cleanup_order[i++]);
    }
}

AVS_UNIT_TEST(rbtree, delete_postorder_first_different_from_min) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);

    AVS_RBTREE_ELEM(int) _1 = AVS_RBTREE_ELEM_NEW(int);
    AVS_RBTREE_ELEM(int) _2 = AVS_RBTREE_ELEM_NEW(int);
    *_1 = 1;
    *_2 = 2;
    AVS_RBTREE_INSERT(tree, _1);
    AVS_RBTREE_INSERT(tree, _2);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, delete_1234) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);

    AVS_RBTREE_ELEM(int) _1 = AVS_RBTREE_ELEM_NEW(int);
    AVS_RBTREE_ELEM(int) _2 = AVS_RBTREE_ELEM_NEW(int);
    AVS_RBTREE_ELEM(int) _3 = AVS_RBTREE_ELEM_NEW(int);
    AVS_RBTREE_ELEM(int) _4 = AVS_RBTREE_ELEM_NEW(int);
    *_1 = 1;
    *_2 = 2;
    *_3 = 3;
    *_4 = 4;
    AVS_RBTREE_INSERT(tree, _1);
    AVS_RBTREE_INSERT(tree, _2);
    AVS_RBTREE_INSERT(tree, _3);
    AVS_RBTREE_INSERT(tree, _4);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, swap_nodes_unrelated) {
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);

    int *_1 = AVS_RBTREE_FIND(tree, &CONST_1);
    int *_2 = AVS_RBTREE_FIND(tree, &CONST_2);
    int *_3 = AVS_RBTREE_FIND(tree, &CONST_3);
    int *_4 = AVS_RBTREE_FIND(tree, &CONST_4);

    int *_8 =  AVS_RBTREE_FIND(tree, &CONST_8);
    int *_12 = AVS_RBTREE_FIND(tree, &CONST_12);
    int *_10 = AVS_RBTREE_FIND(tree, &CONST_10);
    int *_14 = AVS_RBTREE_FIND(tree, &CONST_14);

    int *a = _2;
    int *b = _12;

    assert_node_equal(a, 2,  BLACK, _4, _1,  _3);
    assert_node_equal(b, 12, RED,   _8, _10, _14);

    rb_swap_nodes(_AVS_RB_TREE(tree), a, b);

    assert_node_equal(a, 2,  RED,   _8, _10, _14);
    assert_node_equal(b, 12, BLACK, _4, _1,  _3);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, swap_nodes_parent_child) {
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);

    int *_1 = AVS_RBTREE_FIND(tree, &CONST_1);
    int *_2 = AVS_RBTREE_FIND(tree, &CONST_2);
    int *_3 = AVS_RBTREE_FIND(tree, &CONST_3);
    int *_4 = AVS_RBTREE_FIND(tree, &CONST_4);
    int *_6 = AVS_RBTREE_FIND(tree, &CONST_6);
    int *_8 = AVS_RBTREE_FIND(tree, &CONST_8);

    int *a = _2;
    int *b = _4;

    assert_node_equal(a, 2, BLACK, _4, _1, _3);
    assert_node_equal(b, 4, RED,   _8, _2, _6);

    rb_swap_nodes(_AVS_RB_TREE(tree), a, b);

    assert_node_equal(a, 2, RED,   _8, _4, _6);
    assert_node_equal(b, 4, BLACK, _2, _1, _3);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, swap_nodes_parent_child_under_root) {
    AVS_RBTREE(int) tree = make_tree(
                  4,
              2,      6,
            1,  3,  5,  7, 0);

    int *_1 = AVS_RBTREE_FIND(tree, &CONST_1);
    int *_2 = AVS_RBTREE_FIND(tree, &CONST_2);
    int *_3 = AVS_RBTREE_FIND(tree, &CONST_3);
    int *_4 = AVS_RBTREE_FIND(tree, &CONST_4);
    int *_6 = AVS_RBTREE_FIND(tree, &CONST_6);

    int *a = _2;
    int *b = _4;

    AVS_UNIT_ASSERT_TRUE(_4 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(a, 2, BLACK, _4,   _1, _3);
    assert_node_equal(b, 4, BLACK, NULL, _2, _6);

    rb_swap_nodes(_AVS_RB_TREE(tree), a, b);

    AVS_UNIT_ASSERT_TRUE(_2 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(a, 2, BLACK, NULL, _4, _6);
    assert_node_equal(b, 4, BLACK, _2,   _1, _3);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, rotate_left) {
    AVS_RBTREE(int) tree = make_tree(3, 2, 5, 7, 4, 0);
    /*          3B
     *     2B         5B
     *    *  *     4R    7R
     *            *  *  *  *
     */

    int *_3 = AVS_RBTREE_FIND(tree, &CONST_3);
    int *_2 = AVS_RBTREE_FIND(tree, &CONST_2);
    int *_5 = AVS_RBTREE_FIND(tree, &CONST_5);
    int *_4 = AVS_RBTREE_FIND(tree, &CONST_4);
    int *_7 = AVS_RBTREE_FIND(tree, &CONST_7);

    assert_node_equal(_3, 3, BLACK, NULL, _2,   _5);
    assert_node_equal(_2, 2, BLACK, _3,   NULL, NULL);
    assert_node_equal(_5, 5, BLACK, _3,   _4,   _7);
    assert_node_equal(_4, 4, RED,   _5,   NULL, NULL);
    assert_node_equal(_7, 7, RED,   _5,   NULL, NULL);

    rb_rotate_left(_AVS_RB_TREE(tree), _3);

    /* should be:
     *            5B
     *       3B        7R
     *    2B    4R   *    *
     *   *  *  *  *
     */

    AVS_UNIT_ASSERT_TRUE(_5 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(_5, 5, BLACK, NULL, _3,   _7);
    assert_node_equal(_3, 3, BLACK, _5,   _2,   _4);
    assert_node_equal(_7, 7, RED,   _5,   NULL, NULL);
    assert_node_equal(_2, 2, BLACK, _3,   NULL, NULL);
    assert_node_equal(_4, 4, RED,   _3,   NULL, NULL);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, rotate_right) {
    AVS_RBTREE(int) tree = make_tree(5, 3, 7, 2, 4, 0);
    /*           5B
     *      3B        7B
     *   2R    4R   *    *
     *  *  *  *  *
     */

    int *_5 = AVS_RBTREE_FIND(tree, &CONST_5);
    int *_3 = AVS_RBTREE_FIND(tree, &CONST_3);
    int *_7 = AVS_RBTREE_FIND(tree, &CONST_7);
    int *_2 = AVS_RBTREE_FIND(tree, &CONST_2);
    int *_4 = AVS_RBTREE_FIND(tree, &CONST_4);

    assert_node_equal(_5, 5, BLACK, NULL, _3,   _7);
    assert_node_equal(_3, 3, BLACK, _5,   _2,   _4);
    assert_node_equal(_7, 7, BLACK, _5,   NULL, NULL);
    assert_node_equal(_2, 2, RED,   _3,   NULL, NULL);
    assert_node_equal(_4, 4, RED,   _3,   NULL, NULL);

    rb_rotate_right(_AVS_RB_TREE(tree), _5);

    /* should be:
     *          3B
     *     2R         5B
     *    *  *     4R    7B
     *            *  *  *  *
     */

    AVS_UNIT_ASSERT_TRUE(_3 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(_3, 3, BLACK, NULL, _2,   _5);
    assert_node_equal(_2, 2, RED,   _3,   NULL, NULL);
    assert_node_equal(_5, 5, BLACK, _3,   _4,   _7);
    assert_node_equal(_7, 7, BLACK, _5,   NULL, NULL);
    assert_node_equal(_4, 4, RED,   _5,   NULL, NULL);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, insert_case1_first) {
    int **tree = AVS_RBTREE_NEW(int, int_comparator);
    int *elem = AVS_RBTREE_ELEM_NEW(int);

    AVS_UNIT_ASSERT_TRUE(elem == AVS_RBTREE_INSERT(tree, elem));

    AVS_UNIT_ASSERT_TRUE(_AVS_RB_TREE(tree)->cmp == int_comparator);
    AVS_UNIT_ASSERT_TRUE(_AVS_RB_TREE(tree)->root == elem);

    assert_node_equal(elem, 0, BLACK, NULL, NULL, NULL);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, insert_case2) {
    AVS_RBTREE(int) tree = make_tree(2, 0);
    /*     2
     *   *   *
     */

    void *root = NULL;

    int *elem = AVS_RBTREE_ELEM_NEW(int);
    *elem = 1;
    AVS_UNIT_ASSERT_TRUE(elem == AVS_RBTREE_INSERT(tree, elem));

    /* should be:
     *      2
     *    1   *
     *   * *
     */

    root = _AVS_RB_TREE(tree)->root;
    AVS_UNIT_ASSERT_TRUE(root == _AVS_RB_PARENT(elem));
    AVS_UNIT_ASSERT_NULL(_AVS_RB_LEFT(elem));
    AVS_UNIT_ASSERT_NULL(_AVS_RB_RIGHT(elem));
    AVS_UNIT_ASSERT_EQUAL(BLACK, _AVS_RB_NODE(root)->color);

    AVS_UNIT_ASSERT_NULL(_AVS_RB_PARENT(root));
    AVS_UNIT_ASSERT_TRUE(elem == _AVS_RB_LEFT(root));
    AVS_UNIT_ASSERT_NULL(_AVS_RB_RIGHT(root));
    AVS_UNIT_ASSERT_EQUAL(RED, _AVS_RB_NODE(elem)->color);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, insert_case3) {
    AVS_RBTREE(int) tree = make_tree(5, 2, 7, 0);
    /*     5
     *  2     7
     * * *   * *
     */

    int *_5 = AVS_RBTREE_FIND(tree, &CONST_5);
    int *_2 = AVS_RBTREE_FIND(tree, &CONST_2);
    int *_7 = AVS_RBTREE_FIND(tree, &CONST_7);

    int *_1 = AVS_RBTREE_ELEM_NEW(int);
    *_1 = 1;
    AVS_UNIT_ASSERT_TRUE(_1 == AVS_RBTREE_INSERT(tree, _1));

    /* should be:
     *            5
     *       2         7
     *    1     *     * *
     *   * *
     */

    AVS_UNIT_ASSERT_TRUE(_5 == _AVS_RB_TREE(tree)->root);

    assert_node_equal(_5, 5, BLACK, NULL, _2,   _7);
    assert_node_equal(_2, 2, BLACK, _5,   _1,   NULL);
    assert_node_equal(_1, 1, RED,   _2,   NULL, NULL);
    assert_node_equal(_7, 7, BLACK, _5,   NULL, NULL);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, insert_case4_5) {
    AVS_RBTREE(int) tree = make_tree(5, 4, 7, 2, 0);
    /*            5B
     *       4B        7B
     *    2R    *    *    *
     *   *  *
     */

    int *_5 = AVS_RBTREE_FIND(tree, &CONST_5);
    int *_4 = AVS_RBTREE_FIND(tree, &CONST_4);
    int *_7 = AVS_RBTREE_FIND(tree, &CONST_7);
    int *_2 = AVS_RBTREE_FIND(tree, &CONST_2);
    int *_3 = NULL;

    AVS_UNIT_ASSERT_TRUE(_5 == _AVS_RB_TREE(tree)->root);

    assert_node_equal(_5, 5, BLACK, NULL, _4,   _7);
    assert_node_equal(_4, 4, BLACK, _5,   _2,   NULL);
    assert_node_equal(_7, 7, BLACK, _5,   NULL, NULL);
    assert_node_equal(_2, 2, RED,   _4,   NULL, NULL);

    _3 = AVS_RBTREE_ELEM_NEW(int);
    *_3 = 3;
    AVS_UNIT_ASSERT_TRUE(_3 == AVS_RBTREE_INSERT(tree, _3));

    /* should be:
     *             5B
     *       3B          7B
     *    2R    4R      *  *
     *   *  *  *  *
     */

    AVS_UNIT_ASSERT_TRUE(_5 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(_5, 5, BLACK, NULL, _3,   _7);
    assert_node_equal(_3, 3, BLACK, _5,   _2,   _4);
    assert_node_equal(_7, 7, BLACK, _5,   NULL, NULL);
    assert_node_equal(_2, 2, RED,   _3,   NULL, NULL);
    assert_node_equal(_4, 4, RED,   _3,   NULL, NULL);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, insert_existing) {
    int **tree = AVS_RBTREE_NEW(int, int_comparator);
    int *elem = AVS_RBTREE_ELEM_NEW(int);
    void avs_rbtree_cleanup_elem__(AVS_RBTREE_ELEM(void) *elem);
    int *elem2 = AVS_RBTREE_ELEM_NEW(int);

    AVS_UNIT_ASSERT_TRUE(elem == AVS_RBTREE_INSERT(tree, elem));
    /* attempt to insert an equivalent element should return the previous one */
    AVS_UNIT_ASSERT_TRUE(elem == AVS_RBTREE_INSERT(tree, elem2));

    AVS_UNIT_ASSERT_TRUE(_AVS_RB_TREE(tree)->cmp == int_comparator);
    AVS_UNIT_ASSERT_TRUE(_AVS_RB_TREE(tree)->root == elem);

    assert_node_equal(elem, 0, BLACK, NULL, NULL, NULL);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_ELEM_DELETE_DETACHED(&elem2);
    AVS_RBTREE_DELETE(&tree);
}


static AVS_RBTREE(int) make_full_3level_tree(void) {
    AVS_RBTREE(int) tree = make_tree(
                4,
            2,      6,
          1,  3,  5,  7, 0);

    int *_4 = AVS_RBTREE_FIND(tree, &CONST_4);
    int *_2 = AVS_RBTREE_FIND(tree, &CONST_2);
    int *_1 = AVS_RBTREE_FIND(tree, &CONST_1);
    int *_3 = AVS_RBTREE_FIND(tree, &CONST_3);
    int *_6 = AVS_RBTREE_FIND(tree, &CONST_6);
    int *_5 = AVS_RBTREE_FIND(tree, &CONST_5);
    int *_7 = AVS_RBTREE_FIND(tree, &CONST_7);

    AVS_UNIT_ASSERT_TRUE(_4 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(_4, 4, BLACK, NULL, _2,  _6);
    assert_node_equal(_2, 2, BLACK, _4,   _1,   _3);
    assert_node_equal(_1, 1, RED,   _2,   NULL, NULL);
    assert_node_equal(_3, 3, RED,   _2,   NULL, NULL);
    assert_node_equal(_6, 6, BLACK, _4,   _5,   _7);
    assert_node_equal(_5, 5, RED,   _6,   NULL, NULL);
    assert_node_equal(_7, 7, RED,   _6,   NULL, NULL);

    assert_rb_properties_hold(tree);

    return tree;
}

AVS_UNIT_TEST(rbtree, first_on_empty_tree) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);
    AVS_UNIT_ASSERT_NULL(AVS_RBTREE_FIRST(tree));
    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, last_on_empty_tree) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);
    AVS_UNIT_ASSERT_NULL(AVS_RBTREE_LAST(tree));
    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, traverse_forward) {
    AVS_RBTREE(int) tree = make_full_3level_tree();

    int *node = AVS_RBTREE_FIRST(tree);
    int i;
    for (i = 1; i <= 7; ++i) {
        AVS_UNIT_ASSERT_EQUAL(i, *node);
        node = AVS_RBTREE_ELEM_NEXT(node);
    }

    AVS_UNIT_ASSERT_NULL(node);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, traverse_backward) {
    AVS_RBTREE(int) tree = make_full_3level_tree();

    int *node = AVS_RBTREE_LAST(tree);
    int i;
    for (i = 7; i >= 1; --i) {
        AVS_UNIT_ASSERT_EQUAL(i, *node);
        node = AVS_RBTREE_ELEM_PREV(node);
    }

    AVS_UNIT_ASSERT_NULL(node);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, foreach) {
    AVS_RBTREE(int) tree = make_full_3level_tree();

    int *node;
    int i = 1;
    AVS_RBTREE_FOREACH(node, tree) {
        AVS_UNIT_ASSERT_EQUAL(i++, *node);
    }

    AVS_UNIT_ASSERT_NULL(node);
    AVS_UNIT_ASSERT_EQUAL(8, i);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, foreach_reverse) {
    AVS_RBTREE(int) tree = make_full_3level_tree();

    int *node;
    int i = 7;
    AVS_RBTREE_FOREACH_REVERSE(node, tree) {
        AVS_UNIT_ASSERT_EQUAL(i--, *node);
    }

    AVS_UNIT_ASSERT_NULL(node);
    AVS_UNIT_ASSERT_EQUAL(0, i);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, detach_root) {
    AVS_RBTREE(int) tree = make_tree(1, 0);
    /*   1B
     *  *  *
     */

    int *_1 = AVS_RBTREE_FIND(tree, &CONST_1);
    assert_node_equal(_1, 1, BLACK, NULL, NULL, NULL);
    assert_rb_properties_hold(tree);

    AVS_UNIT_ASSERT_TRUE(_1 == AVS_RBTREE_DETACH(tree, _1));
    /* should be:
     *   *
     */

    assert_node_equal(_1, 1, DETACHED, NULL, NULL, NULL);
    AVS_UNIT_ASSERT_NULL(_AVS_RB_TREE(tree)->root);
    assert_rb_properties_hold(tree);

    AVS_RBTREE_ELEM_DELETE_DETACHED(&_1);
    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, detach_single_root_child) {
    AVS_RBTREE(int) tree = make_tree(1, 2, 0);
    /*    1B
     *   *  2R
     */

    int *_1 = NULL;
    int *_2 = NULL;

    assert_rb_properties_hold(tree);

    _1 = AVS_RBTREE_FIND(tree, &CONST_1);
    _2 = AVS_RBTREE_FIND(tree, &CONST_2);

    assert_node_equal(_1, 1, BLACK, NULL, NULL, _2);
    assert_node_equal(_2, 2, RED,   _1,   NULL, NULL);

    AVS_UNIT_ASSERT_TRUE(_2 == AVS_RBTREE_DETACH(tree, _2));
    /* should be:
     *    1B
     *   *  *
     */

    assert_node_equal(_1, 1, BLACK, NULL, NULL, NULL);
    AVS_UNIT_ASSERT_TRUE(_1 == _AVS_RB_TREE(tree)->root);
    assert_rb_properties_hold(tree);

    assert_node_equal(_2, 2, DETACHED, NULL, NULL, NULL);

    AVS_RBTREE_ELEM_DELETE_DETACHED(&_2);
    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, delete_attached) {
    AVS_RBTREE(int) tree = make_tree(1, 2, 0);
    /*    1B
     *   *  2R
     */

    int *_1 = NULL;
    int *_2 = NULL;

    _1 = AVS_RBTREE_FIND(tree, &CONST_1);
    _2 = AVS_RBTREE_FIND(tree, &CONST_2);

    AVS_RBTREE_DELETE_ELEM(tree, &_1);
    AVS_UNIT_ASSERT_TRUE(_2 == _AVS_RB_TREE(tree)->root);
    AVS_UNIT_ASSERT_EQUAL(1, AVS_RBTREE_SIZE(tree));

    AVS_RBTREE_DELETE_ELEM(tree, &_2);
    AVS_UNIT_ASSERT_TRUE(NULL == _AVS_RB_TREE(tree)->root);
    AVS_UNIT_ASSERT_EQUAL(0, AVS_RBTREE_SIZE(tree));

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, fuzz1) {
    AVS_RBTREE(int) tree = make_tree(3, 1, 2, 0);
    int *_2 = NULL;

    assert_rb_properties_hold(tree);

    _2 = AVS_RBTREE_FIND(tree, &CONST_2);
    AVS_RBTREE_DELETE_ELEM(tree, &_2);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, fuzz2) {
    AVS_RBTREE(int) tree = make_tree(2, 5, 3, 1, 0);
    int *_3 = NULL;

    assert_rb_properties_hold(tree);

    _3 = AVS_RBTREE_FIND(tree, &CONST_3);
    AVS_RBTREE_DELETE_ELEM(tree, &_3);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_DELETE(&tree);
}
