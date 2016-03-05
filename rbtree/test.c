#include "rbtree.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <avsystem/commons/log.h>
#include <avsystem/commons/unit/test.h>

static void log_node(void *node) {
    struct rb_node *n = RB_NODE(node);
    avs_log(rb, ERROR, "%p: %s, parent %p, left %p, right %p",
            node, n->color == RED ? "RED" : "BLACK",
            n->parent, n->left, n->right);
}

static void dump_tree_recursive(void *node,
                                size_t node_size,
                                void (*print_node)(void *node, size_t size),
                                int level) {
    if (!node) {
        fprintf(stderr, "%*s(null)\n", level * 4, "");
    } else {
        fprintf(stderr, "%*s", level * 4, "");
        print_node(node, node_size);
        fprintf(stderr, "\n");

        if (RB_LEFT(node)) {
            AVS_UNIT_ASSERT_TRUE(RB_PARENT(RB_LEFT(node)) == node);
        }
        if (RB_RIGHT(node)) {
            AVS_UNIT_ASSERT_TRUE(RB_PARENT(RB_RIGHT(node)) == node);
        }
        dump_tree_recursive(RB_LEFT(node), node_size, print_node, level + 1);
        dump_tree_recursive(RB_RIGHT(node), node_size, print_node, level + 1);
    }
}

static void print_int(void *value,
                      size_t size) {
    (void)size;
    fprintf(stderr, "%d %s", *(int*)value,
            RB_NODE(value)->color == RED ? "R" : "B");
}

static void dump_tree(struct rb_tree *tree) {
    dump_tree_recursive(tree->root, sizeof(int), print_int, 0);
}

static void assert_rb_properties_hold_recursive(void *node,
                                                size_t *out_black_height) {
    *out_black_height = 1;
    if (!node) {
        return;
    }

    void *left = RB_LEFT(node);
    void *right = RB_RIGHT(node);

    size_t left_black_height = 0;
    if (left) {
        AVS_UNIT_ASSERT_TRUE(node == RB_PARENT(left));
        assert_rb_properties_hold_recursive(left, &left_black_height);
    }

    size_t right_black_height = 0;
    if (right) {
        AVS_UNIT_ASSERT_TRUE(node == RB_PARENT(right));
        assert_rb_properties_hold_recursive(right, &right_black_height);
    }

    AVS_UNIT_ASSERT_EQUAL(left_black_height, right_black_height);
    *out_black_height = left_black_height;

    if (rb_node_color(node) == RED) {
        AVS_UNIT_ASSERT_EQUAL(BLACK, rb_node_color(left));
        AVS_UNIT_ASSERT_EQUAL(BLACK, rb_node_color(right));
    } else {
        ++*out_black_height;
    }
}

static void assert_rb_properties_hold(struct rb_tree *tree) {
    AVS_UNIT_ASSERT_EQUAL(BLACK, rb_node_color(tree->root));
    if (tree->root) {
        AVS_UNIT_ASSERT_NULL(RB_PARENT(tree->root));
    }

    size_t black_height = 0;
    assert_rb_properties_hold_recursive(tree->root, &black_height);
}

// terminated with 0
static struct rb_tree *make_tree(int first, ...) {
    struct rb_tree *tree = rb_create(memcmp);
    AVS_UNIT_ASSERT_NOT_NULL(tree);

    va_list list;
    va_start(list, first);

    int value = first;
    while (value != 0) {
        int *elem = RB_TREE_NEW_ELEMENT(int);
        AVS_UNIT_ASSERT_NOT_NULL(elem);

        *elem = value;
        AVS_UNIT_ASSERT_SUCCESS(RB_INSERT(tree, elem));

        value = va_arg(list, int);
    }

    va_end(list);

    assert_rb_properties_hold(tree);

    return tree;
}

static void assert_node_equal(int *node,
                              int value,
                              enum rb_color color,
                              int *parent,
                              int *left,
                              int *right) {
    AVS_UNIT_ASSERT_EQUAL(value, *node);
    AVS_UNIT_ASSERT_EQUAL(color, RB_NODE(node)->color);
    AVS_UNIT_ASSERT_TRUE(parent == RB_PARENT(node));
    AVS_UNIT_ASSERT_TRUE(left == RB_LEFT(node));
    AVS_UNIT_ASSERT_TRUE(right == RB_RIGHT(node));
}

AVS_UNIT_TEST(rbtree, create) {
    struct rb_tree *tree = rb_create(memcmp);

    AVS_UNIT_ASSERT_TRUE(tree->cmp == memcmp);
    AVS_UNIT_ASSERT_NULL(tree->root);
}

AVS_UNIT_TEST(rbtree, create_element) {
    int *elem = RB_TREE_NEW_ELEMENT(int);

    assert_node_equal(elem, 0, RED, NULL, NULL, NULL);

    RB_TREE_DELETE(elem);
}

AVS_UNIT_TEST(rbtree, swap_nodes_unrelated) {
    struct rb_tree *tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);

    int *_1 = RB_FIND(tree, (int){1});
    int *_2 = RB_FIND(tree, (int){2});
    int *_3 = RB_FIND(tree, (int){3});
    int *_4 = RB_FIND(tree, (int){4});

    int *_8 = RB_FIND(tree, (int){8});
    int *_12 = RB_FIND(tree, (int){12});
    int *_10 = RB_FIND(tree, (int){10});
    int *_14 = RB_FIND(tree, (int){14});

    int *a = _2;
    int *b = _12;

    assert_node_equal(a, 2,  BLACK, _4, _1,  _3);
    assert_node_equal(b, 12, RED,   _8, _10, _14);

    swap_nodes(tree, a, b);

    assert_node_equal(a, 2,  RED,   _8, _10, _14);
    assert_node_equal(b, 12, BLACK, _4, _1,  _3);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, swap_nodes_parent_child) {
    struct rb_tree *tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);

    int *_1 = RB_FIND(tree, (int){1});
    int *_2 = RB_FIND(tree, (int){2});
    int *_3 = RB_FIND(tree, (int){3});
    int *_4 = RB_FIND(tree, (int){4});
    int *_6 = RB_FIND(tree, (int){6});
    int *_8 = RB_FIND(tree, (int){8});

    int *a = _2;
    int *b = _4;

    assert_node_equal(a, 2, BLACK, _4, _1, _3);
    assert_node_equal(b, 4, RED,   _8, _2, _6);

    swap_nodes(tree, a, b);

    assert_node_equal(a, 2, RED,   _8, _4, _6);
    assert_node_equal(b, 4, BLACK, _2, _1, _3);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, swap_nodes_parent_child_under_root) {
    struct rb_tree *tree = make_tree(
                  4,
              2,      6,
            1,  3,  5,  7, 0);

    int *_1 = RB_FIND(tree, (int){1});
    int *_2 = RB_FIND(tree, (int){2});
    int *_3 = RB_FIND(tree, (int){3});
    int *_4 = RB_FIND(tree, (int){4});
    int *_6 = RB_FIND(tree, (int){6});

    int *a = _2;
    int *b = _4;

    AVS_UNIT_ASSERT_TRUE(_4 == tree->root);
    assert_node_equal(a, 2, BLACK, _4,   _1, _3);
    assert_node_equal(b, 4, BLACK, NULL, _2, _6);

    swap_nodes(tree, a, b);

    AVS_UNIT_ASSERT_TRUE(_2 == tree->root);
    assert_node_equal(a, 2, BLACK, NULL, _4, _6);
    assert_node_equal(b, 4, BLACK, _2,   _1, _3);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, rotate_left) {
    struct rb_tree *tree = make_tree(3, 2, 5, 7, 4, 0);
    //          3B
    //     2B         5B
    //    *  *     4R    7R
    //            *  *  *  *

    int *three = (int*)tree->root;
    int *two = RB_LEFT(three);
    int *five = RB_RIGHT(three);
    int *four = RB_LEFT(five);
    int *seven = RB_RIGHT(five);

    assert_node_equal(three, 3, BLACK, NULL,   two,   five);
    assert_node_equal(two,   2, BLACK, three,  NULL,  NULL);
    assert_node_equal(five,  5, BLACK, three,  four, seven);
    assert_node_equal(four,  4, RED,   five,   NULL,  NULL);
    assert_node_equal(seven, 7, RED,   five,   NULL,  NULL);

    rb_rotate_left(tree, three);

    // should be:
    //          5B
    //     3B        7R
    //  2B    4R   *    *
    // *  *  *  *

    AVS_UNIT_ASSERT_TRUE(five == tree->root);
    assert_node_equal(five,  5, BLACK, NULL,   three, seven);
    assert_node_equal(three, 3, BLACK, five,   two,   four);
    assert_node_equal(seven, 7, RED,   five,   NULL,  NULL);
    assert_node_equal(two,   2, BLACK, three,  NULL,  NULL);
    assert_node_equal(four,  4, RED,   three,  NULL,  NULL);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, rotate_right) {
    struct rb_tree *tree = make_tree(5, 3, 7, 2, 4, 0);
    //          5B
    //     3B        7B
    //  2R    4R   *    *
    // *  *  *  *

    int *five = (int*)tree->root;
    int *three = RB_LEFT(five);
    int *seven = RB_RIGHT(five);
    int *two = RB_LEFT(three);
    int *four = RB_RIGHT(three);

    assert_node_equal(five,  5, BLACK, NULL,   three, seven);
    assert_node_equal(three, 3, BLACK, five,   two,   four);
    assert_node_equal(seven, 7, BLACK, five,   NULL,  NULL);
    assert_node_equal(two,   2, RED,   three,  NULL,  NULL);
    assert_node_equal(four,  4, RED,   three,  NULL,  NULL);

    rb_rotate_right(tree, five);

    // should be:
    //          3B
    //     2R         5B
    //    *  *     4R    7B
    //            *  *  *  *

    AVS_UNIT_ASSERT_TRUE(three == tree->root);
    assert_node_equal(three, 3, BLACK, NULL,   two,   five);
    assert_node_equal(two,   2, RED,   three,  NULL,  NULL);
    assert_node_equal(five,  5, BLACK, three,  four, seven);
    assert_node_equal(seven, 7, BLACK, five,   NULL,  NULL);
    assert_node_equal(four,  4, RED,   five,   NULL,  NULL);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, insert_case1_first) {
    struct rb_tree *tree = rb_create(memcmp);
    int *elem = RB_TREE_NEW_ELEMENT(int);

    AVS_UNIT_ASSERT_SUCCESS(RB_INSERT(tree, elem));

    AVS_UNIT_ASSERT_TRUE(tree->cmp == memcmp);
    AVS_UNIT_ASSERT_TRUE(tree->root == elem);

    assert_node_equal(elem, 0, BLACK, NULL, NULL, NULL);

    assert_rb_properties_hold(tree);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, insert_case2) {
    struct rb_tree *tree = make_tree(2, 0);
    //   2
    // *   *

    int *elem = RB_TREE_NEW_ELEMENT(int);
    *elem = 1;
    AVS_UNIT_ASSERT_SUCCESS(RB_INSERT(tree, elem));

    // should be:
    //    2
    //  1   *
    // * *

    AVS_UNIT_ASSERT_TRUE(tree->root == RB_PARENT(elem));
    AVS_UNIT_ASSERT_NULL(RB_LEFT(elem));
    AVS_UNIT_ASSERT_NULL(RB_RIGHT(elem));
    AVS_UNIT_ASSERT_EQUAL(BLACK, RB_NODE(tree->root)->color);

    AVS_UNIT_ASSERT_NULL(RB_PARENT(tree->root));
    AVS_UNIT_ASSERT_TRUE(elem == RB_LEFT(tree->root));
    AVS_UNIT_ASSERT_NULL(RB_RIGHT(tree->root));
    AVS_UNIT_ASSERT_EQUAL(RED, RB_NODE(elem)->color);

    assert_rb_properties_hold(tree);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, insert_case3) {
    struct rb_tree *tree = make_tree(5, 2, 7, 0);
    //     5
    //  2     7
    // * *   * *

    int *five = (int*)tree->root;
    int *two = RB_LEFT(five);
    int *seven = RB_RIGHT(five);

    int *one = RB_TREE_NEW_ELEMENT(int);
    *one = 1;
    AVS_UNIT_ASSERT_SUCCESS(RB_INSERT(tree, one));

    // should be:
    //          5
    //     2         7
    //  1     *     * *
    // * *

    AVS_UNIT_ASSERT_TRUE(five == tree->root);

    assert_node_equal(five, 5, BLACK, NULL, two, seven);
    assert_node_equal(two, 2, BLACK, five, one, NULL);
    assert_node_equal(one, 1, RED, two, NULL, NULL);
    assert_node_equal(seven, 7, BLACK, five, NULL, NULL);

    assert_rb_properties_hold(tree);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, insert_case4_5) {
    struct rb_tree *tree = make_tree(5, 4, 7, 2, 0);
    //          5B
    //     4B        7B
    //  2R    *    *    *
    // *  *

    int *five = (int*)tree->root;
    int *four = RB_LEFT(five);
    int *seven = RB_RIGHT(five);
    int *two = RB_LEFT(four);

    AVS_UNIT_ASSERT_TRUE(five == tree->root);

    assert_node_equal(five,  5, BLACK, NULL,   four,  seven);
    assert_node_equal(four,  4, BLACK, five,   two,  NULL);
    assert_node_equal(seven, 7, BLACK, five,   NULL, NULL);
    assert_node_equal(two,   2, RED,   four,  NULL, NULL);

    int *three = RB_TREE_NEW_ELEMENT(int);
    *three = 3;
    AVS_UNIT_ASSERT_SUCCESS(RB_INSERT(tree, three));

    // should be:
    //            5B
    //      3B          7B
    //   2R    4R      *  *
    //  *  *  *  *

    AVS_UNIT_ASSERT_TRUE(five == tree->root);
    assert_node_equal(five,  5, BLACK, NULL,  three, seven);
    assert_node_equal(three, 3, BLACK, five,  two,   four);
    assert_node_equal(seven, 7, BLACK, five,  NULL,  NULL);
    assert_node_equal(two,   2, RED,   three, NULL,  NULL);
    assert_node_equal(four,  4, RED,   three, NULL,  NULL);

    assert_rb_properties_hold(tree);

    rb_release(&tree);
}

static struct rb_tree *make_full_3level_tree(void) {
    struct rb_tree *tree = make_tree(4, 2, 6, 1, 3, 5, 7, 0);
    //            4B
    //      2B          6B
    //   1R    3R    5R    7R
    //  *  *  *  *  *  *  *  *

    int *four = (int*)tree->root;
    int *two = RB_LEFT(four);
    int *one = RB_LEFT(two);
    int *three = RB_RIGHT(two);
    int *six = RB_RIGHT(four);
    int *five = RB_LEFT(six);
    int *seven = RB_RIGHT(six);

    AVS_UNIT_ASSERT_TRUE(four == tree->root);
    assert_node_equal(four,  4, BLACK, NULL, two,  six);
    assert_node_equal(two,   2, BLACK, four, one,  three);
    assert_node_equal(one,   1, RED,   two,  NULL, NULL);
    assert_node_equal(three, 3, RED,   two,  NULL, NULL);
    assert_node_equal(six,   6, BLACK, four, five, seven);
    assert_node_equal(five,  5, RED,   six,  NULL, NULL);
    assert_node_equal(seven, 7, RED,   six,  NULL, NULL);

    assert_rb_properties_hold(tree);

    return tree;
}

AVS_UNIT_TEST(rbtree, traverse_forward) {
    struct rb_tree *tree = make_full_3level_tree();

    int *node = RB_FIRST((int*)tree->root);
    for (int i = 1; i <= 7; ++i) {
        AVS_UNIT_ASSERT_EQUAL(i, *node);
        node = RB_NEXT(node);
    }

    AVS_UNIT_ASSERT_NULL(node);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, traverse_backward) {
    struct rb_tree *tree = make_full_3level_tree();

    int *node = RB_LAST((int*)tree->root);
    for (int i = 7; i >= 1; --i) {
        AVS_UNIT_ASSERT_EQUAL(i, *node);
        node = RB_PREV(node);
    }

    AVS_UNIT_ASSERT_NULL(node);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, detach_root) {
    struct rb_tree *tree = make_tree(1, 0);
    //   1B
    //  *  *

    int *one = (int*)tree->root;
    assert_node_equal(one, 1, BLACK, NULL, NULL, NULL);
    assert_rb_properties_hold(tree);

    AVS_UNIT_ASSERT_TRUE(one == rb_detach(tree, one));
    // should be:
    //   *

    assert_node_equal(one, 1, BLACK, NULL, NULL, NULL);
    AVS_UNIT_ASSERT_NULL(tree->root);
    assert_rb_properties_hold(tree);

    RB_TREE_DELETE(one);
    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, detach_single_root_child) {
    struct rb_tree *tree = make_tree(1, 2, 0);
    //  1B
    // *  2R

    assert_rb_properties_hold(tree);

    int *one = (int*)tree->root;
    int *two = RB_RIGHT(one);

    AVS_UNIT_ASSERT_TRUE(two == rb_detach(tree, two));
    // should be:
    //  1B
    // *  *

    assert_node_equal(one, 1, BLACK, NULL, NULL, NULL);
    AVS_UNIT_ASSERT_TRUE(one == tree->root);
    assert_rb_properties_hold(tree);

    assert_node_equal(two, 2, RED, NULL, NULL, NULL);

    RB_TREE_DELETE(two);
    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, fuzz1) {
    struct rb_tree *tree = make_tree(3, 1, 2, 0);
    assert_rb_properties_hold(tree);

    const int two = 2;
    RB_TREE_DELETE(rb_detach(tree, RB_FIND(tree, two)));
    assert_rb_properties_hold(tree);

    rb_release(&tree);
}

AVS_UNIT_TEST(rbtree, fuzz2) {
    struct rb_tree *tree = make_tree(2, 5, 3, 1, 0);
    dump_tree(tree);
    assert_rb_properties_hold(tree);

    const int three = 3;
    RB_TREE_DELETE(rb_detach(tree, RB_FIND(tree, three)));
    dump_tree(tree);
    assert_rb_properties_hold(tree);

    rb_release(&tree);
}
