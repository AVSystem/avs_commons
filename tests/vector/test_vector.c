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

#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_unit_test.h>

typedef struct {
    int *data;
} sample_nonpod_t;

static void make_sample_nonpod(size_t data_size, sample_nonpod_t *out) {
    AVS_UNIT_ASSERT_NOT_NULL((out->data = (int *) avs_malloc(data_size)));
}

AVS_UNIT_TEST(avs_vector, example_usage_nonpod) {
    AVS_VECTOR(sample_nonpod_t) u = AVS_VECTOR_NEW(sample_nonpod_t);
    sample_nonpod_t elem;
    sample_nonpod_t *elemptr;
    int i;

    AVS_UNIT_ASSERT_NOT_NULL(u);
    for (i = 0; i < 4; i++) {
        make_sample_nonpod((i + 1) * 256, &elem);
        AVS_VECTOR_PUSH(&u, &elem);
    }

    /**
     * Now AVS_VECTOR_DELETE would cause a large memory leak, but we can avoid
     * that elegantly:
     */
    AVS_VECTOR_CLEAR(&u, elemptr) {
        avs_free(elemptr->data);
    }
    /**
     * Vector now is empty, but it is not freed, i.e. its internal data storage
     * is still allocated, we shall free it.
     */
    AVS_VECTOR_DELETE(&u); /* and done! */
}

AVS_UNIT_TEST(avs_vector, example_usage_pod) {
    /* Necessary initialization */
    AVS_VECTOR(int) v = AVS_VECTOR_NEW(int);
    int i;
    int sum = 0;

    AVS_UNIT_ASSERT_NOT_NULL(v);
    for (i = 0; i < 129; i++) {
        AVS_VECTOR_PUSH(&v, &i);
    }
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 129);
    AVS_UNIT_ASSERT_TRUE(AVS_VECTOR_CAPACITY(v) > 129);
    /* Let's say we decided that vector uses too much memory */
    AVS_UNIT_ASSERT_SUCCESS(AVS_VECTOR_FIT(&v));
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_CAPACITY(v), 129);

    for (i = 0; i < 129; i++) {
        /* Yay, operator [] is available after dereferencing! */
        sum += (*v)[i];
    }
    AVS_UNIT_ASSERT_EQUAL(sum, (129) * (128) / 2);
    /**
     * Now we decide to finish our work quickly, without unnecessary cleanups
     * per element - they were just PODs after all.
     */
    AVS_VECTOR_DELETE(&v);
}

AVS_UNIT_TEST(avs_vector, initialization_and_clearance) {
    AVS_VECTOR(int) v = AVS_VECTOR_NEW(int);
    int x = 1;
    int *p;
    AVS_UNIT_ASSERT_NOT_NULL(v);
    AVS_VECTOR_PUSH(&v, &x);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 1);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_CAPACITY(v), 1);
    AVS_VECTOR_DELETE(&v);
    AVS_UNIT_ASSERT_NULL(v);

    v = AVS_VECTOR_NEW(int);
    AVS_UNIT_ASSERT_NOT_NULL(v);
    AVS_VECTOR_PUSH(&v, &x);
    AVS_VECTOR_CLEAR(&v, p);
    AVS_UNIT_ASSERT_NOT_NULL(v);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 0);
    AVS_VECTOR_DELETE(&v);
}

AVS_UNIT_TEST(avs_vector, capacity_and_size) {
    AVS_VECTOR(int) v = AVS_VECTOR_NEW(int);
    int x = 1;
    int *y;
    AVS_UNIT_ASSERT_NOT_NULL(v);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 0);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_CAPACITY(v), 0);
    AVS_VECTOR_PUSH(&v, &x);
    AVS_VECTOR_CLEAR(&v, y);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 0);
    AVS_UNIT_ASSERT_TRUE(AVS_VECTOR_CAPACITY(v) > 0);
    AVS_VECTOR_DELETE(&v);
}

AVS_UNIT_TEST(avs_vector, vector_remove) {
    AVS_VECTOR(int) v = AVS_VECTOR_NEW(int);
    int i, *elem;
    AVS_UNIT_ASSERT_NOT_NULL(v);
    for (i = 0; i < 5; ++i) {
        AVS_VECTOR_PUSH(&v, &i);
    }
    elem = AVS_VECTOR_REMOVE_AT(&v, 3);
    AVS_UNIT_ASSERT_EQUAL(*elem, 3);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 4);
    AVS_UNIT_ASSERT_EQUAL((*v)[0], 0);
    AVS_UNIT_ASSERT_EQUAL((*v)[1], 1);
    AVS_UNIT_ASSERT_EQUAL((*v)[2], 2);
    AVS_UNIT_ASSERT_EQUAL((*v)[3], 4);

    elem = AVS_VECTOR_REMOVE_AT(&v, 3);
    AVS_UNIT_ASSERT_EQUAL(*elem, 4);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 3);

    elem = AVS_VECTOR_REMOVE_AT(&v, 0);
    AVS_UNIT_ASSERT_EQUAL(*elem, 0);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 2);

    elem = AVS_VECTOR_REMOVE_AT(&v, 1);
    AVS_UNIT_ASSERT_EQUAL(*elem, 2);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 1);

    elem = AVS_VECTOR_REMOVE_AT(&v, 0);
    AVS_UNIT_ASSERT_EQUAL(*elem, 1);
    AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(v), 0);

    elem = AVS_VECTOR_REMOVE_AT(&v, 0);
    AVS_UNIT_ASSERT_NULL(elem);

    AVS_VECTOR_DELETE(&v);
}

static int decreasing(const void *a, const void *b) {
    const int *p = (const int *) a;
    const int *q = (const int *) b;
    return *p > *q ? -1 : *p == *q ? 0 : 1;
}

static int increasing(const void *a, const void *b) {
    return decreasing(b, a);
}

AVS_UNIT_TEST(avs_vector, sort) {
    AVS_VECTOR(int) u = AVS_VECTOR_NEW(int);
    int i;
    AVS_UNIT_ASSERT_NOT_NULL(u);
    for (i = 0; i < 64; i++) {
        AVS_VECTOR_PUSH(&u, &i);
    }
    AVS_VECTOR_SORT_RANGE(&u, 0, 5, decreasing);
    for (i = 0; i < 5; i++) {
        AVS_UNIT_ASSERT_EQUAL((*u)[i], 4 - i);
    }
    for (i = 5; i < 64; i++) {
        AVS_UNIT_ASSERT_EQUAL((*u)[i], i);
    }
    AVS_VECTOR_SORT(&u, increasing);
    for (i = 0; i < 64; i++) {
        AVS_UNIT_ASSERT_EQUAL((*u)[i], i);
    }
    AVS_VECTOR_SORT_RANGE(&u, 0, 1, increasing);
    for (i = 0; i < 64; i++) {
        AVS_UNIT_ASSERT_EQUAL((*u)[i], i);
    }
    AVS_VECTOR_DELETE(&u);
}

AVS_UNIT_TEST(avs_vector, reverse) {
    AVS_VECTOR(int) u = AVS_VECTOR_NEW(int);
    int i;
    AVS_UNIT_ASSERT_NOT_NULL(u);
    for (i = 0; i < 10; ++i) {
        AVS_VECTOR_PUSH(&u, &i);
    }
    AVS_VECTOR_REVERSE(&u);
    for (i = 0; i < 10; ++i) {
        AVS_UNIT_ASSERT_EQUAL((*u)[i], 9 - i);
    }
    AVS_VECTOR_DELETE(&u);
}

AVS_UNIT_TEST(avs_vector, reverse_range) {
    AVS_VECTOR(int) u = AVS_VECTOR_NEW(int);
    int i;
    AVS_UNIT_ASSERT_NOT_NULL(u);
    for (i = 0; i < 10; ++i) {
        AVS_VECTOR_PUSH(&u, &i);
    }
    AVS_VECTOR_REVERSE_RANGE(&u, 0, 1);
    for (i = 0; i < 10; ++i) {
        AVS_UNIT_ASSERT_EQUAL((*u)[i], i);
    }
    AVS_VECTOR_REVERSE_RANGE(&u, 0, 2);
    AVS_UNIT_ASSERT_EQUAL((*u)[0], 1);
    AVS_UNIT_ASSERT_EQUAL((*u)[1], 0);
    for (i = 2; i < 10; ++i) {
        AVS_UNIT_ASSERT_EQUAL((*u)[i], i);
    }
    AVS_VECTOR_DELETE(&u);

    u = AVS_VECTOR_NEW(int);
    AVS_UNIT_ASSERT_NOT_NULL(u);
    for (i = 0; i < 10; ++i) {
        AVS_VECTOR_PUSH(&u, &i);
    }
    AVS_VECTOR_REVERSE_RANGE(&u, 1, 5);
    AVS_UNIT_ASSERT_EQUAL((*u)[1], 4);
    AVS_UNIT_ASSERT_EQUAL((*u)[2], 3);
    AVS_UNIT_ASSERT_EQUAL((*u)[3], 2);
    AVS_UNIT_ASSERT_EQUAL((*u)[4], 1);
    AVS_VECTOR_DELETE(&u);
}

AVS_UNIT_TEST(avs_vector, push_is_idempotent) {
    AVS_VECTOR(int) vecs[10];
    AVS_VECTOR(int) *v;
    int data[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    int i;
    int *elem = &data[0];
    for (i = 0; i < 10; ++i) {
        AVS_UNIT_ASSERT_NOT_NULL((vecs[i] = AVS_VECTOR_NEW(int)));
    }
    v = &vecs[0];
    for (i = 0; i < 10; ++i) {
        AVS_VECTOR_PUSH(v++, elem++);
    }
    for (i = 0; i < 10; ++i) {
        AVS_UNIT_ASSERT_EQUAL(AVS_VECTOR_SIZE(vecs[i]), 1);
        AVS_UNIT_ASSERT_EQUAL((*(vecs[i]))[0], data[i]);
    }
    for (i = 0; i < 10; ++i) {
        AVS_VECTOR_DELETE(&vecs[i]);
    }
}
