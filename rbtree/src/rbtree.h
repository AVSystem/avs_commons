/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_RBTREE_RBTREE_H
#define AVS_COMMONS_RBTREE_RBTREE_H

#include <stdint.h>
#include <assert.h>

#include <avsystem/commons/rbtree.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

enum rb_color {
    DETACHED = 0x50DD,
    RED = 0x50DE,
    BLACK = 0x50DF
};

struct rb_node {
    enum rb_color color;
    void *parent;
    void *left;
    void *right;
};

struct rb_tree {
    size_t size;
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
#define _AVS_RB_NODE_CONST(elem) \
    ((const struct rb_node*)((const char*)(elem) - _AVS_NODE_SPACE__))

#define _AVS_RB_TREE(ptr) \
    AVS_CONTAINER_OF((ptr), struct rb_tree, root)

#define _AVS_RB_ALLOC(size) calloc(1, size)
#define _AVS_RB_DEALLOC(ptr) free(ptr)

#define _AVS_RB_LEFT_PTR(elem) \
    ((AVS_TYPEOF_PTR(elem)*)&(_AVS_RB_NODE(elem)->left))
#define _AVS_RB_LEFT_PTR_CONST(elem) \
    ((AVS_TYPEOF_PTR(elem) const*)&(_AVS_RB_NODE_CONST(elem)->left))

#define _AVS_RB_LEFT(elem) (*_AVS_RB_LEFT_PTR(elem))
#define _AVS_RB_LEFT_CONST(elem) (*_AVS_RB_LEFT_PTR_CONST(elem))

#define _AVS_RB_RIGHT_PTR(elem) \
    ((AVS_TYPEOF_PTR(elem)*)&(_AVS_RB_NODE(elem)->right))
#define _AVS_RB_RIGHT_PTR_CONST(elem) \
    ((AVS_TYPEOF_PTR(elem) const*)&(_AVS_RB_NODE_CONST(elem)->right))

#define _AVS_RB_RIGHT(elem) (*_AVS_RB_RIGHT_PTR(elem))
#define _AVS_RB_RIGHT_CONST(elem) (*_AVS_RB_RIGHT_PTR_CONST(elem))

#define _AVS_RB_PARENT_PTR(elem) \
    ((AVS_TYPEOF_PTR(elem)*)&(_AVS_RB_NODE(elem)->parent))
#define _AVS_RB_PARENT_PTR_CONST(elem) \
    ((AVS_TYPEOF_PTR(elem) const*)&(_AVS_RB_NODE_CONST(elem)->parent))

#define _AVS_RB_PARENT(elem) (*_AVS_RB_PARENT_PTR(elem))
#define _AVS_RB_PARENT_CONST(elem) (*_AVS_RB_PARENT_PTR_CONST(elem))

enum rb_color _avs_rb_node_color(void *elem);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_RBTREE_RBTREE_H */
