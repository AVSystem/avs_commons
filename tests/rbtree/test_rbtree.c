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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_unit_test.h>

static size_t test_rb_alloc_null_countdown = 0;

static void *test_rb_alloc(size_t num_bytes) {
    if (test_rb_alloc_null_countdown > 0) {
        if (--test_rb_alloc_null_countdown == 0) {
            return NULL;
        }
    }

    return avs_calloc(1, num_bytes);
}

static void test_rb_dealloc(void *ptr) {
    avs_free(ptr);
}

#ifdef __cplusplus
class IntptrHelper {
    int value;

public:
    IntptrHelper(int value) : value(value) {}
    int *ptr() {
        return &value;
    }
};
#    define INTPTR(Value) (IntptrHelper((Value)).ptr())
#else
#    define INTPTR(Value) (&(int[]){ (Value) }[0])
#endif

static int int_comparator(const void *a_, const void *b_) {
    int a = *(const int *) a_;
    int b = *(const int *) b_;
    return a < b ? -1 : (a == b ? 0 : 1);
}

static void assert_rb_properties_hold_recursive(void *node,
                                                size_t *out_black_height,
                                                size_t *out_size) {
    void *left = NULL;
    void *right = NULL;
    size_t left_black_height = 0;
    size_t right_black_height = 0;
    size_t left_size = 0;
    size_t right_size = 0;

    *out_black_height = 1;
    if (!node) {
        *out_size = 0;
        return;
    }

    left = _AVS_RB_LEFT(node);
    right = _AVS_RB_RIGHT(node);

    left_black_height = 0;
    if (left) {
        AVS_UNIT_ASSERT_TRUE(node == _AVS_RB_PARENT(left));
        assert_rb_properties_hold_recursive(left, &left_black_height,
                                            &left_size);
    }

    right_black_height = 0;
    if (right) {
        AVS_UNIT_ASSERT_TRUE(node == _AVS_RB_PARENT(right));
        assert_rb_properties_hold_recursive(right, &right_black_height,
                                            &right_size);
    }

    AVS_UNIT_ASSERT_EQUAL(left_black_height, right_black_height);
    *out_black_height = left_black_height;

    if (_avs_rb_node_color(node) == RED) {
        AVS_UNIT_ASSERT_EQUAL(BLACK, _avs_rb_node_color(left));
        AVS_UNIT_ASSERT_EQUAL(BLACK, _avs_rb_node_color(right));
    } else {
        ++*out_black_height;
    }
    *out_size = 1 + left_size + right_size;
}

static void assert_rb_properties_hold(AVS_RBTREE(int) tree_) {
    struct rb_tree *tree = _AVS_RB_TREE(tree_);
    size_t black_height = 0;

    AVS_UNIT_ASSERT_EQUAL(BLACK, _avs_rb_node_color(tree->root));
    if (tree->root) {
        AVS_UNIT_ASSERT_NULL(_AVS_RB_PARENT(tree->root));
    }

    size_t size;
    assert_rb_properties_hold_recursive(tree->root, &black_height, &size);
    AVS_UNIT_ASSERT_EQUAL(tree->size, size);
}

/* terminated with 0 */
static AVS_RBTREE(int) make_tree(int first, ...) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);
    va_list list;
    int value = first;
    size_t num_values = 0;

    AVS_UNIT_ASSERT_NOT_NULL(tree);
    va_start(list, first);

    while (value != 0) {
        AVS_RBTREE_ELEM(int) elem = AVS_RBTREE_ELEM_NEW(int);
        AVS_UNIT_ASSERT_NOT_NULL(elem);

        *elem = value;
        AVS_UNIT_ASSERT_TRUE(elem == AVS_RBTREE_INSERT(tree, elem));

        value = va_arg(list, int);
        ++num_values;
    }

    va_end(list);

    assert_rb_properties_hold(tree);
    AVS_UNIT_ASSERT_EQUAL(num_values, AVS_RBTREE_SIZE(tree));

    return tree;
}

static const char *get_color_name(enum rb_color color) {
    switch (color) {
    case DETACHED:
        return "DETACHED";
    case BLACK:
        return "BLACK";
    case RED:
        return "RED";
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
    AVS_UNIT_ASSERT_EQUAL((size_t) 0, AVS_RBTREE_SIZE(tree));

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, create_element) {
    AVS_RBTREE_ELEM(int) elem = AVS_RBTREE_ELEM_NEW(int);

    assert_node_equal(elem, 0, DETACHED, NULL, NULL, NULL);

    AVS_RBTREE_ELEM_DELETE_DETACHED(&elem);
}

AVS_UNIT_TEST(rbtree, clear) {
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);
    // clang-format on
    int expected_cleanup_order[] = { 1,  3,  2,  5,  7,  6,  4, 9,
                                     11, 10, 13, 15, 14, 12, 8 };

    size_t i = 0;
    AVS_RBTREE_CLEAR(tree) {
        AVS_UNIT_ASSERT_EQUAL(**tree, expected_cleanup_order[i++]);
    }
    AVS_UNIT_ASSERT_NOT_NULL(tree);
    AVS_UNIT_ASSERT_EQUAL(AVS_RBTREE_SIZE(tree), 0);

    AVS_RBTREE_ELEM(int) new_elem = AVS_RBTREE_ELEM_NEW(int);
    *new_elem = 42;
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_INSERT(tree, new_elem) == new_elem);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, delete) {
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);
    // clang-format on
    int expected_cleanup_order[] = { 1,  3,  2,  5,  7,  6,  4, 9,
                                     11, 10, 13, 15, 14, 12, 8 };

    size_t i = 0;
    AVS_RBTREE_DELETE(&tree) {
        AVS_UNIT_ASSERT_EQUAL(**tree, expected_cleanup_order[i++]);
    }
}

AVS_UNIT_TEST(rbtree, delete_null) {
    AVS_RBTREE(int) tree = NULL;
    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, delete_break_resume) {
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);
    // clang-format on
    int expected_cleanup_order[] = { 1,  3,  2,  5,  7,  6,  4, 9,
                                     11, 10, 13, 15, 14, 12, 8 };

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

AVS_UNIT_TEST(rbtree, simple_clone) {
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);
    // clang-format on
    AVS_RBTREE(int) clone = (AVS_RBTREE(int)) AVS_RBTREE_SIMPLE_CLONE(tree);
    AVS_UNIT_ASSERT_NOT_NULL(clone);
    assert_rb_properties_hold(clone);

    AVS_RBTREE_ELEM(int) it1 = AVS_RBTREE_FIRST(tree);
    AVS_RBTREE_ELEM(int) it2 = AVS_RBTREE_FIRST(clone);
    while (it1 && it2) {
        AVS_UNIT_ASSERT_TRUE(it1 != it2);
        AVS_UNIT_ASSERT_TRUE(*it1 == *it2);
        it1 = AVS_RBTREE_ELEM_NEXT(it1);
        it2 = AVS_RBTREE_ELEM_NEXT(it2);
    }

    AVS_RBTREE_DELETE(&tree);
    AVS_RBTREE_DELETE(&clone);
}

AVS_UNIT_TEST(rbtree, lower_bound) {
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                       80,
              40,              120,
          20,     60,     100,      140,
        10, 30, 50, 70, 90, 110, 130, 150, 0);
    // clang-format on
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(1))
                         == AVS_RBTREE_FIND(tree, INTPTR(10)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(10))
                         == AVS_RBTREE_FIND(tree, INTPTR(10)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(12))
                         == AVS_RBTREE_FIND(tree, INTPTR(20)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(20))
                         == AVS_RBTREE_FIND(tree, INTPTR(20)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(23))
                         == AVS_RBTREE_FIND(tree, INTPTR(30)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(30))
                         == AVS_RBTREE_FIND(tree, INTPTR(30)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(34))
                         == AVS_RBTREE_FIND(tree, INTPTR(40)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(40))
                         == AVS_RBTREE_FIND(tree, INTPTR(40)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(45))
                         == AVS_RBTREE_FIND(tree, INTPTR(50)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(50))
                         == AVS_RBTREE_FIND(tree, INTPTR(50)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(56))
                         == AVS_RBTREE_FIND(tree, INTPTR(60)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(60))
                         == AVS_RBTREE_FIND(tree, INTPTR(60)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(67))
                         == AVS_RBTREE_FIND(tree, INTPTR(70)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(70))
                         == AVS_RBTREE_FIND(tree, INTPTR(70)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(78))
                         == AVS_RBTREE_FIND(tree, INTPTR(80)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(80))
                         == AVS_RBTREE_FIND(tree, INTPTR(80)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(89))
                         == AVS_RBTREE_FIND(tree, INTPTR(90)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(90))
                         == AVS_RBTREE_FIND(tree, INTPTR(90)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(91))
                         == AVS_RBTREE_FIND(tree, INTPTR(100)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(100))
                         == AVS_RBTREE_FIND(tree, INTPTR(100)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(102))
                         == AVS_RBTREE_FIND(tree, INTPTR(110)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(110))
                         == AVS_RBTREE_FIND(tree, INTPTR(110)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(113))
                         == AVS_RBTREE_FIND(tree, INTPTR(120)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(120))
                         == AVS_RBTREE_FIND(tree, INTPTR(120)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(124))
                         == AVS_RBTREE_FIND(tree, INTPTR(130)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(130))
                         == AVS_RBTREE_FIND(tree, INTPTR(130)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(135))
                         == AVS_RBTREE_FIND(tree, INTPTR(140)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(140))
                         == AVS_RBTREE_FIND(tree, INTPTR(140)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(146))
                         == AVS_RBTREE_FIND(tree, INTPTR(150)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(150))
                         == AVS_RBTREE_FIND(tree, INTPTR(150)));
    AVS_UNIT_ASSERT_NULL(AVS_RBTREE_LOWER_BOUND(tree, INTPTR(157)));

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, upper_bound) {
    // clang-formt off
    AVS_RBTREE(int) tree = make_tree(80, 40, 120, 20, 60, 100, 140, 10, 30, 50,
                                     70, 90, 110, 130, 150, 0);
    // clang-format on
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(1))
                         == AVS_RBTREE_FIND(tree, INTPTR(10)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(10))
                         == AVS_RBTREE_FIND(tree, INTPTR(20)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(12))
                         == AVS_RBTREE_FIND(tree, INTPTR(20)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(20))
                         == AVS_RBTREE_FIND(tree, INTPTR(30)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(23))
                         == AVS_RBTREE_FIND(tree, INTPTR(30)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(30))
                         == AVS_RBTREE_FIND(tree, INTPTR(40)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(34))
                         == AVS_RBTREE_FIND(tree, INTPTR(40)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(40))
                         == AVS_RBTREE_FIND(tree, INTPTR(50)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(45))
                         == AVS_RBTREE_FIND(tree, INTPTR(50)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(50))
                         == AVS_RBTREE_FIND(tree, INTPTR(60)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(56))
                         == AVS_RBTREE_FIND(tree, INTPTR(60)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(60))
                         == AVS_RBTREE_FIND(tree, INTPTR(70)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(67))
                         == AVS_RBTREE_FIND(tree, INTPTR(70)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(70))
                         == AVS_RBTREE_FIND(tree, INTPTR(80)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(78))
                         == AVS_RBTREE_FIND(tree, INTPTR(80)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(80))
                         == AVS_RBTREE_FIND(tree, INTPTR(90)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(89))
                         == AVS_RBTREE_FIND(tree, INTPTR(90)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(90))
                         == AVS_RBTREE_FIND(tree, INTPTR(100)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(91))
                         == AVS_RBTREE_FIND(tree, INTPTR(100)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(100))
                         == AVS_RBTREE_FIND(tree, INTPTR(110)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(102))
                         == AVS_RBTREE_FIND(tree, INTPTR(110)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(110))
                         == AVS_RBTREE_FIND(tree, INTPTR(120)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(113))
                         == AVS_RBTREE_FIND(tree, INTPTR(120)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(120))
                         == AVS_RBTREE_FIND(tree, INTPTR(130)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(124))
                         == AVS_RBTREE_FIND(tree, INTPTR(130)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(130))
                         == AVS_RBTREE_FIND(tree, INTPTR(140)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(135))
                         == AVS_RBTREE_FIND(tree, INTPTR(140)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(140))
                         == AVS_RBTREE_FIND(tree, INTPTR(150)));
    AVS_UNIT_ASSERT_TRUE(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(146))
                         == AVS_RBTREE_FIND(tree, INTPTR(150)));
    AVS_UNIT_ASSERT_NULL(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(150)));
    AVS_UNIT_ASSERT_NULL(AVS_RBTREE_UPPER_BOUND(tree, INTPTR(157)));

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, swap_nodes_unrelated) {
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);
    // clang-format on
    int *_1 = AVS_RBTREE_FIND(tree, INTPTR(1));
    int *_2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    int *_3 = AVS_RBTREE_FIND(tree, INTPTR(3));
    int *_4 = AVS_RBTREE_FIND(tree, INTPTR(4));

    int *_8 = AVS_RBTREE_FIND(tree, INTPTR(8));
    int *_12 = AVS_RBTREE_FIND(tree, INTPTR(12));
    int *_10 = AVS_RBTREE_FIND(tree, INTPTR(10));
    int *_14 = AVS_RBTREE_FIND(tree, INTPTR(14));

    int *a = _2;
    int *b = _12;

    assert_node_equal(a, 2, BLACK, _4, _1, _3);
    assert_node_equal(b, 12, RED, _8, _10, _14);

    rb_swap_nodes(_AVS_RB_TREE(tree), a, b);

    assert_node_equal(a, 2, RED, _8, _10, _14);
    assert_node_equal(b, 12, BLACK, _4, _1, _3);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, swap_nodes_parent_child) {
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                      8,
              4,             12,
          2,      6,     10,     14,
        1,  3,  5,  7,  9, 11, 13, 15, 0);
    // clang-format on
    int *_1 = AVS_RBTREE_FIND(tree, INTPTR(1));
    int *_2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    int *_3 = AVS_RBTREE_FIND(tree, INTPTR(3));
    int *_4 = AVS_RBTREE_FIND(tree, INTPTR(4));
    int *_6 = AVS_RBTREE_FIND(tree, INTPTR(6));
    int *_8 = AVS_RBTREE_FIND(tree, INTPTR(8));

    int *a = _2;
    int *b = _4;

    assert_node_equal(a, 2, BLACK, _4, _1, _3);
    assert_node_equal(b, 4, RED, _8, _2, _6);

    rb_swap_nodes(_AVS_RB_TREE(tree), a, b);

    assert_node_equal(a, 2, RED, _8, _4, _6);
    assert_node_equal(b, 4, BLACK, _2, _1, _3);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, swap_nodes_parent_child_under_root) {
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                  4,
              2,      6,
            1,  3,  5,  7, 0);
    // clang-format on

    int *_1 = AVS_RBTREE_FIND(tree, INTPTR(1));
    int *_2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    int *_3 = AVS_RBTREE_FIND(tree, INTPTR(3));
    int *_4 = AVS_RBTREE_FIND(tree, INTPTR(4));
    int *_6 = AVS_RBTREE_FIND(tree, INTPTR(6));

    int *a = _2;
    int *b = _4;

    AVS_UNIT_ASSERT_TRUE(_4 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(a, 2, BLACK, _4, _1, _3);
    assert_node_equal(b, 4, BLACK, NULL, _2, _6);

    rb_swap_nodes(_AVS_RB_TREE(tree), a, b);

    AVS_UNIT_ASSERT_TRUE(_2 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(a, 2, BLACK, NULL, _4, _6);
    assert_node_equal(b, 4, BLACK, _2, _1, _3);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, rotate_left) {
    AVS_RBTREE(int) tree = make_tree(3, 2, 5, 7, 4, 0);
    /*          3B
     *     2B         5B
     *    *  *     4R    7R
     *            *  *  *  *
     */

    int *_3 = AVS_RBTREE_FIND(tree, INTPTR(3));
    int *_2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    int *_5 = AVS_RBTREE_FIND(tree, INTPTR(5));
    int *_4 = AVS_RBTREE_FIND(tree, INTPTR(4));
    int *_7 = AVS_RBTREE_FIND(tree, INTPTR(7));

    assert_node_equal(_3, 3, BLACK, NULL, _2, _5);
    assert_node_equal(_2, 2, BLACK, _3, NULL, NULL);
    assert_node_equal(_5, 5, BLACK, _3, _4, _7);
    assert_node_equal(_4, 4, RED, _5, NULL, NULL);
    assert_node_equal(_7, 7, RED, _5, NULL, NULL);

    rb_rotate_left(_AVS_RB_TREE(tree), _3);

    /* should be:
     *            5B
     *       3B        7R
     *    2B    4R   *    *
     *   *  *  *  *
     */

    AVS_UNIT_ASSERT_TRUE(_5 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(_5, 5, BLACK, NULL, _3, _7);
    assert_node_equal(_3, 3, BLACK, _5, _2, _4);
    assert_node_equal(_7, 7, RED, _5, NULL, NULL);
    assert_node_equal(_2, 2, BLACK, _3, NULL, NULL);
    assert_node_equal(_4, 4, RED, _3, NULL, NULL);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, rotate_right) {
    AVS_RBTREE(int) tree = make_tree(5, 3, 7, 2, 4, 0);
    /*           5B
     *      3B        7B
     *   2R    4R   *    *
     *  *  *  *  *
     */

    int *_5 = AVS_RBTREE_FIND(tree, INTPTR(5));
    int *_3 = AVS_RBTREE_FIND(tree, INTPTR(3));
    int *_7 = AVS_RBTREE_FIND(tree, INTPTR(7));
    int *_2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    int *_4 = AVS_RBTREE_FIND(tree, INTPTR(4));

    assert_node_equal(_5, 5, BLACK, NULL, _3, _7);
    assert_node_equal(_3, 3, BLACK, _5, _2, _4);
    assert_node_equal(_7, 7, BLACK, _5, NULL, NULL);
    assert_node_equal(_2, 2, RED, _3, NULL, NULL);
    assert_node_equal(_4, 4, RED, _3, NULL, NULL);

    rb_rotate_right(_AVS_RB_TREE(tree), _5);

    /* should be:
     *          3B
     *     2R         5B
     *    *  *     4R    7B
     *            *  *  *  *
     */

    AVS_UNIT_ASSERT_TRUE(_3 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(_3, 3, BLACK, NULL, _2, _5);
    assert_node_equal(_2, 2, RED, _3, NULL, NULL);
    assert_node_equal(_5, 5, BLACK, _3, _4, _7);
    assert_node_equal(_7, 7, BLACK, _5, NULL, NULL);
    assert_node_equal(_4, 4, RED, _5, NULL, NULL);

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

    int *_5 = AVS_RBTREE_FIND(tree, INTPTR(5));
    int *_2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    int *_7 = AVS_RBTREE_FIND(tree, INTPTR(7));

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

    assert_node_equal(_5, 5, BLACK, NULL, _2, _7);
    assert_node_equal(_2, 2, BLACK, _5, _1, NULL);
    assert_node_equal(_1, 1, RED, _2, NULL, NULL);
    assert_node_equal(_7, 7, BLACK, _5, NULL, NULL);

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

    int *_5 = AVS_RBTREE_FIND(tree, INTPTR(5));
    int *_4 = AVS_RBTREE_FIND(tree, INTPTR(4));
    int *_7 = AVS_RBTREE_FIND(tree, INTPTR(7));
    int *_2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    int *_3 = NULL;

    AVS_UNIT_ASSERT_TRUE(_5 == _AVS_RB_TREE(tree)->root);

    assert_node_equal(_5, 5, BLACK, NULL, _4, _7);
    assert_node_equal(_4, 4, BLACK, _5, _2, NULL);
    assert_node_equal(_7, 7, BLACK, _5, NULL, NULL);
    assert_node_equal(_2, 2, RED, _4, NULL, NULL);

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
    assert_node_equal(_5, 5, BLACK, NULL, _3, _7);
    assert_node_equal(_3, 3, BLACK, _5, _2, _4);
    assert_node_equal(_7, 7, BLACK, _5, NULL, NULL);
    assert_node_equal(_2, 2, RED, _3, NULL, NULL);
    assert_node_equal(_4, 4, RED, _3, NULL, NULL);

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
    // clang-format off
    AVS_RBTREE(int) tree = make_tree(
                4,
            2,      6,
          1,  3,  5,  7, 0);
    // clang-format on
    int *_4 = AVS_RBTREE_FIND(tree, INTPTR(4));
    int *_2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    int *_1 = AVS_RBTREE_FIND(tree, INTPTR(1));
    int *_3 = AVS_RBTREE_FIND(tree, INTPTR(3));
    int *_6 = AVS_RBTREE_FIND(tree, INTPTR(6));
    int *_5 = AVS_RBTREE_FIND(tree, INTPTR(5));
    int *_7 = AVS_RBTREE_FIND(tree, INTPTR(7));

    AVS_UNIT_ASSERT_TRUE(_4 == _AVS_RB_TREE(tree)->root);
    assert_node_equal(_4, 4, BLACK, NULL, _2, _6);
    assert_node_equal(_2, 2, BLACK, _4, _1, _3);
    assert_node_equal(_1, 1, RED, _2, NULL, NULL);
    assert_node_equal(_3, 3, RED, _2, NULL, NULL);
    assert_node_equal(_6, 6, BLACK, _4, _5, _7);
    assert_node_equal(_5, 5, RED, _6, NULL, NULL);
    assert_node_equal(_7, 7, RED, _6, NULL, NULL);

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

AVS_UNIT_TEST(rbtree, deletable_foreach) {
    AVS_RBTREE(int) tree = make_full_3level_tree();

    AVS_UNIT_ASSERT_EQUAL(AVS_RBTREE_SIZE(tree), 7);

    AVS_RBTREE_ELEM(int) node;
    AVS_RBTREE_ELEM(int) helper;
    int i = 1;
    AVS_RBTREE_DELETABLE_FOREACH(node, helper, tree) {
        AVS_UNIT_ASSERT_EQUAL(i++, *node);
        if (*node % 3 == 0) {
            AVS_RBTREE_DELETE_ELEM(tree, &node);
        }
    }

    AVS_UNIT_ASSERT_NULL(node);
    AVS_UNIT_ASSERT_NULL(helper);
    AVS_UNIT_ASSERT_EQUAL(8, i);

    AVS_UNIT_ASSERT_EQUAL(AVS_RBTREE_SIZE(tree), 5);

    static const int EXPECTED[] = { 1, 2, 4, 5, 7 };
    i = 0;
    AVS_RBTREE_FOREACH(node, tree) {
        AVS_UNIT_ASSERT_EQUAL(EXPECTED[i++], *node);
    }

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

AVS_UNIT_TEST(rbtree, deletable_foreach_reverse) {
    AVS_RBTREE(int) tree = make_full_3level_tree();

    AVS_UNIT_ASSERT_EQUAL(AVS_RBTREE_SIZE(tree), 7);

    AVS_RBTREE_ELEM(int) node;
    AVS_RBTREE_ELEM(int) helper;
    int i = 7;
    AVS_RBTREE_DELETABLE_FOREACH_REVERSE(node, helper, tree) {
        AVS_UNIT_ASSERT_EQUAL(i--, *node);
        if ((*node & 3) == 3) {
            AVS_RBTREE_DELETE_ELEM(tree, &node);
        }
    }

    AVS_UNIT_ASSERT_NULL(node);
    AVS_UNIT_ASSERT_NULL(helper);
    AVS_UNIT_ASSERT_EQUAL(0, i);

    AVS_UNIT_ASSERT_EQUAL(AVS_RBTREE_SIZE(tree), 5);

    static const int EXPECTED[] = { 1, 2, 4, 5, 6 };
    i = 0;
    AVS_RBTREE_FOREACH(node, tree) {
        AVS_UNIT_ASSERT_EQUAL(EXPECTED[i++], *node);
    }

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, foreach_empty) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);

    AVS_RBTREE_ELEM(int) node;
    AVS_RBTREE_FOREACH(node, tree) {
        AVS_UNIT_ASSERT_TRUE(0);
    }
    AVS_RBTREE_FOREACH_REVERSE(node, tree) {
        AVS_UNIT_ASSERT_TRUE(0);
    }

    AVS_RBTREE_ELEM(int) helper;
    AVS_RBTREE_DELETABLE_FOREACH(node, helper, tree) {
        AVS_UNIT_ASSERT_TRUE(0);
    }
    AVS_RBTREE_DELETABLE_FOREACH_REVERSE(node, helper, tree) {
        AVS_UNIT_ASSERT_TRUE(0);
    }

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, detach_root) {
    AVS_RBTREE(int) tree = make_tree(1, 0);
    /*   1B
     *  *  *
     */

    int *_1 = AVS_RBTREE_FIND(tree, INTPTR(1));
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

    _1 = AVS_RBTREE_FIND(tree, INTPTR(1));
    _2 = AVS_RBTREE_FIND(tree, INTPTR(2));

    assert_node_equal(_1, 1, BLACK, NULL, NULL, _2);
    assert_node_equal(_2, 2, RED, _1, NULL, NULL);

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

AVS_UNIT_TEST(rbtree, delete_detached_null) {
    AVS_RBTREE_ELEM(int) elem = NULL;
    AVS_RBTREE_ELEM_DELETE_DETACHED(&elem);
}

AVS_UNIT_TEST(rbtree, delete_attached) {
    AVS_RBTREE(int) tree = make_tree(1, 2, 0);
    /*    1B
     *   *  2R
     */

    int *_1 = NULL;
    int *_2 = NULL;

    _1 = AVS_RBTREE_FIND(tree, INTPTR(1));
    _2 = AVS_RBTREE_FIND(tree, INTPTR(2));

    AVS_RBTREE_DELETE_ELEM(tree, &_1);
    AVS_UNIT_ASSERT_TRUE(_2 == _AVS_RB_TREE(tree)->root);
    AVS_UNIT_ASSERT_EQUAL((size_t) 1, AVS_RBTREE_SIZE(tree));

    AVS_RBTREE_DELETE_ELEM(tree, &_2);
    AVS_UNIT_ASSERT_TRUE(NULL == _AVS_RB_TREE(tree)->root);
    AVS_UNIT_ASSERT_EQUAL((size_t) 0, AVS_RBTREE_SIZE(tree));

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, fuzz1) {
    AVS_RBTREE(int) tree = make_tree(3, 1, 2, 0);
    int *_2 = NULL;

    assert_rb_properties_hold(tree);

    _2 = AVS_RBTREE_FIND(tree, INTPTR(2));
    AVS_RBTREE_DELETE_ELEM(tree, &_2);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, fuzz2) {
    AVS_RBTREE(int) tree = make_tree(2, 5, 3, 1, 0);
    int *_3 = NULL;

    assert_rb_properties_hold(tree);

    _3 = AVS_RBTREE_FIND(tree, INTPTR(3));
    AVS_RBTREE_DELETE_ELEM(tree, &_3);

    assert_rb_properties_hold(tree);

    AVS_RBTREE_DELETE(&tree);
}

AVS_UNIT_TEST(rbtree, clone_segfault) {
    AVS_RBTREE(int) tree = make_tree(2, 5, 3, 1, 0);

    // return NULL for third allocation
    test_rb_alloc_null_countdown = 3;
    AVS_UNIT_ASSERT_NULL(AVS_RBTREE_SIMPLE_CLONE(tree));
    AVS_RBTREE_DELETE(&tree);
}
