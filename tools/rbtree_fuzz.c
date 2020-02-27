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

#include "src/rbtree.h"
#include <avsystem/commons/avs_rbtree.h>

#include <stdio.h>

VISIBILITY_SOURCE_BEGIN

static void assert_rb_properties_hold_recursive(void *node,
                                                size_t *out_black_height) {
    *out_black_height = 1;
    if (!node) {
        return;
    }

    void *left = _AVS_RB_LEFT(node);
    void *right = _AVS_RB_RIGHT(node);

    size_t left_black_height = 0;
    if (left) {
        assert(node == _AVS_RB_PARENT(left));
        assert_rb_properties_hold_recursive(left, &left_black_height);
    }

    size_t right_black_height = 0;
    if (right) {
        assert(node == _AVS_RB_PARENT(right));
        assert_rb_properties_hold_recursive(right, &right_black_height);
    }

    assert(left_black_height == right_black_height);
    *out_black_height = left_black_height;

    if (_avs_rb_node_color(node) == RED) {
        assert(BLACK == _avs_rb_node_color(left));
        assert(BLACK == _avs_rb_node_color(right));
    } else {
        ++*out_black_height;
    }
}

static void assert_rb_properties_hold(AVS_RBTREE(int) tree_) {
    struct rb_tree *tree = _AVS_RB_TREE(tree_);

    assert(BLACK == _avs_rb_node_color(tree->root));
    if (tree->root) {
        assert(_AVS_RB_PARENT(tree->root) == NULL);
    }

    size_t black_height = 0;
    assert_rb_properties_hold_recursive(tree->root, &black_height);
}

static int int_comparator(const void *a_, const void *b_) {
    int a = *(const int *) a_;
    int b = *(const int *) b_;
    return a < b ? -1 : (a == b ? 0 : 1);
}

int main(void) {
    AVS_RBTREE(int) tree = AVS_RBTREE_NEW(int, int_comparator);

    while (!feof(stdin)) {
        char op;
        int val;

        if (fread(&op, sizeof(op), 1, stdin) == 1
                && fread(&val, sizeof(val), 1, stdin) == 1) {
            switch (op) {
            case 0: {
                int *elem = AVS_RBTREE_ELEM_NEW(int);
                *elem = val;

                size_t prev_size = AVS_RBTREE_SIZE(tree);
                if (AVS_RBTREE_INSERT(tree, elem) != elem) {
                    assert(prev_size == AVS_RBTREE_SIZE(tree));
                    AVS_RBTREE_ELEM_DELETE_DETACHED(&elem);
                } else {
                    assert(prev_size + 1 == AVS_RBTREE_SIZE(tree));
                }
                assert(AVS_RBTREE_FIND(tree, &val));
                assert_rb_properties_hold(tree);
            } break;
            case 1: {
                size_t expected_size = AVS_RBTREE_SIZE(tree);
                if (AVS_RBTREE_FIND(tree, &val)) {
                    --expected_size;
                }

                int *elem = AVS_RBTREE_FIND(tree, &val);
                AVS_RBTREE_DELETE_ELEM(tree, &elem);

                assert(!AVS_RBTREE_FIND(tree, &val));
                assert(expected_size == AVS_RBTREE_SIZE(tree));
                assert_rb_properties_hold(tree);
            } break;
            default:
                break;
            }
        }
    }

    AVS_RBTREE_DELETE(&tree);
    return 0;
}
