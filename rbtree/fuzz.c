#include <avsystem/commons/rbtree.h>
#include "src/rbtree.h"

#include <stdio.h>

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

static void assert_rb_properties_hold(AVS_RB_TREE(int) tree_) {
    struct rb_tree *tree = _AVS_RB_TREE(tree_);

    assert(BLACK == _avs_rb_node_color(tree->root));
    if (tree->root) {
        assert(_AVS_RB_PARENT(tree->root) == NULL);
    }

    size_t black_height = 0;
    assert_rb_properties_hold_recursive(tree->root, &black_height);
}

int main(void) {
    AVS_RB_TREE(int) tree = AVS_RB_TREE_CREATE(int, memcmp);

    while (!feof(stdin)) {
        char op;
        int val;

        if (fread(&op, sizeof(op), 1, stdin) == 1
                && fread(&val, sizeof(val), 1, stdin) == 1) {
            switch (op) {
            case 0:
                {
                    int *elem = AVS_RB_NEW_ELEMENT(int);
                    *elem = val;

                    size_t prev_size = AVS_RB_TREE_SIZE(tree);
                    if (AVS_RB_TREE_INSERT(tree, elem)) {
                        assert(prev_size == AVS_RB_TREE_SIZE(tree));
                    } else {
                        assert(prev_size + 1 == AVS_RB_TREE_SIZE(tree));
                    }
                    assert(AVS_RB_TREE_FIND(tree, &val));
                    assert_rb_properties_hold(tree);
                }
                break;
            case 1:
                {
                    size_t expected_size = AVS_RB_TREE_SIZE(tree);
                    if (AVS_RB_TREE_FIND(tree, &val)) {
                        --expected_size;
                    }

                    int *elem = AVS_RB_TREE_FIND(tree, &val);
                    assert(elem == AVS_RB_TREE_DETACH(tree, elem));
                    AVS_RB_DELETE_ELEMENT(elem);

                    assert(!AVS_RB_TREE_FIND(tree, &val));
                    assert(expected_size == AVS_RB_TREE_SIZE(tree));
                    assert_rb_properties_hold(tree);
                }
                break;
            default:
                break;
            }
        }
    }

    AVS_RB_TREE_RELEASE(&tree);
    return 0;
}
