/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/unit/test.h>
#include <avsystem/commons/unit/mock_helpers.h>

AVS_UNIT_MOCK_CREATE(calloc)
#define calloc(...) AVS_UNIT_MOCK_WRAPPER(calloc)(__VA_ARGS__)

#include <avsystem/commons/list.h>

AVS_UNIT_TEST(list, one_element) {
    size_t count = 0;
    size_t i = 0;
    int *list = NULL;
    int *element = NULL;
    AVS_UNIT_ASSERT_TRUE(AVS_LIST_INSERT_NEW(int, &list) == list);
    *list = 514;
    for (i = 0; i < 10; ++ i) {
        /* inserting NULL shall have no effect */
        AVS_UNIT_ASSERT_NULL(AVS_LIST_INSERT(&list, NULL));
    }
    AVS_LIST_FOREACH(element, list) {
        AVS_UNIT_ASSERT_EQUAL(*element, 514);
        ++count;
    }
    AVS_UNIT_ASSERT_EQUAL(count, 1);
    AVS_LIST_CLEAR(&list);
}

static void *failing_calloc(size_t nmemb, size_t size) {
    AVS_UNIT_ASSERT_EQUAL(nmemb, 1);
    AVS_UNIT_ASSERT_TRUE(size >= AVS_LIST_SPACE_FOR_NEXT__);
    return NULL;
}

AVS_UNIT_TEST(list, failing_alloc) {
    AVS_LIST(int) test_list = NULL;

    AVS_UNIT_MOCK(calloc) = failing_calloc;

    AVS_UNIT_ASSERT_NULL(AVS_LIST_NEW_BUFFER(42));
    AVS_UNIT_ASSERT_NULL(AVS_LIST_NEW_ELEMENT(int));

    AVS_UNIT_ASSERT_NULL(AVS_LIST_INSERT_NEW(int, &test_list));
    AVS_UNIT_ASSERT_NULL(test_list);
    AVS_UNIT_ASSERT_NULL(AVS_LIST_APPEND_NEW(int, &test_list));
    AVS_UNIT_ASSERT_NULL(test_list);
}

AVS_UNIT_TEST(list, middle_delete) {
    size_t i = 0;
    int *list = NULL;
    int *element = NULL;
    for (i = 0; i < 10; ++i) {
        element = AVS_LIST_APPEND_NEW(int, &list);
        *element = (int) (i + 1);
    }
    i = 0;
    AVS_LIST_FOREACH(element, list) {
        ++i;
        AVS_UNIT_ASSERT_EQUAL(*element, i);
    }
    AVS_UNIT_ASSERT_EQUAL(i, 10);
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(list), 10);

    element = AVS_LIST_NTH(list, 2);
    AVS_UNIT_ASSERT_TRUE(AVS_LIST_NTH_PTR(&list, 3) == &AVS_LIST_NEXT(element));
    AVS_UNIT_ASSERT_TRUE(AVS_LIST_FIND_PTR(&list, AVS_LIST_NTH(list, 3))
            == &AVS_LIST_NEXT(element));
    AVS_LIST_DELETE(&AVS_LIST_NEXT(element));

    i = 0;
    AVS_LIST_FOREACH(element, list) {
        ++i;
        AVS_UNIT_ASSERT_EQUAL(*element, i);
        if (i == 3) {
            break;
        }
    }
    ++i;
    element = AVS_LIST_NEXT(element);
    AVS_LIST_ITERATE(element) {
        ++i;
        AVS_UNIT_ASSERT_EQUAL(*element, i);
    }
    AVS_UNIT_ASSERT_EQUAL(i, 10);
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(list), 9);
    AVS_LIST_CLEAR(&list);
}

AVS_UNIT_TEST(list, deletable_foreach) {
    size_t i = 0;
    int *list = NULL;
    int **element_ptr = NULL, *helper = NULL;
    for (i = 0; i < 10; ++i) {
        int *element = AVS_LIST_NEW_ELEMENT(int);
        AVS_UNIT_ASSERT_NOT_NULL(element);
        *element = (int) (i + 1);
        AVS_LIST_APPEND(&list, element);
    }
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(list), 10);

    i = 0;
    AVS_LIST_DELETABLE_FOREACH_PTR(element_ptr, helper, &list) {
        ++i;
        AVS_UNIT_ASSERT_EQUAL(**element_ptr, i);
        AVS_LIST_DELETE(element_ptr);
    }
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(list), 0);
}

AVS_UNIT_TEST(list, find) {
    size_t i = 0;
    AVS_LIST(int) list = NULL;
    for (i = 0; i < 10; ++i) {
        int *element = AVS_LIST_NEW_ELEMENT(int);
        AVS_UNIT_ASSERT_NOT_NULL(element);
        *element = (int) (i + 1);
        AVS_LIST_APPEND(&list, element);
    }
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(list), 10);

    {
        int element = 5;

        int **element_ptr = AVS_LIST_FIND_BY_VALUE_PTR(&list, &element,
                                                        memcmp);
        AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t)element_ptr, (intptr_t)NULL);
        AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t)*element_ptr, (intptr_t)NULL);
        AVS_UNIT_ASSERT_EQUAL(**element_ptr, element);

        element_ptr = AVS_LIST_NEXT_PTR(element_ptr);
        AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t)element_ptr, (intptr_t)NULL);
        AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t)*element_ptr, (intptr_t)NULL);
        AVS_UNIT_ASSERT_EQUAL(**element_ptr, element + 1);
    }
    AVS_LIST_CLEAR(&list);
}

static int int_comparator(const void *left, const void *right, size_t sz) {
    (void) sz;
    return *((const int *) left) - *((const int *) right);
}

AVS_UNIT_TEST(list, sort) {
    int *list = NULL;
    int *element = NULL;
    size_t i;

    for (i = 0; i < 10; ++i) {
        AVS_UNIT_ASSERT_NOT_NULL((element = AVS_LIST_NEW_ELEMENT(int)));
        switch (i) {
        case 0: *element = 1; break;
        case 1: *element = 51; break;
        case 2: *element = 77; break;
        case 3: *element = 35; break;
        case 4: *element = 11; break;
        case 5: *element = 67; break;
        case 6: *element = 58; break;
        case 7: *element = 69; break;
        case 8: *element = 56; break;
        case 9: *element = 17; break;
        }
        AVS_LIST_APPEND(&list, element);
    }

    AVS_LIST_SORT(&list, int_comparator);

    i = 0;
    AVS_LIST_CLEAR(&list) {
        switch (i++) {
        case 0: AVS_UNIT_ASSERT_EQUAL(*list, 1); break;
        case 1: AVS_UNIT_ASSERT_EQUAL(*list, 11); break;
        case 2: AVS_UNIT_ASSERT_EQUAL(*list, 17); break;
        case 3: AVS_UNIT_ASSERT_EQUAL(*list, 35); break;
        case 4: AVS_UNIT_ASSERT_EQUAL(*list, 51); break;
        case 5: AVS_UNIT_ASSERT_EQUAL(*list, 56); break;
        case 6: AVS_UNIT_ASSERT_EQUAL(*list, 58); break;
        case 7: AVS_UNIT_ASSERT_EQUAL(*list, 67); break;
        case 8: AVS_UNIT_ASSERT_EQUAL(*list, 69); break;
        case 9: AVS_UNIT_ASSERT_EQUAL(*list, 77); break;
        }
    }
}

AVS_UNIT_TEST(list, is_cyclic) {
    int *elem = NULL;
    AVS_LIST(int) list = NULL;
    size_t i;
    AVS_UNIT_ASSERT_FALSE(AVS_LIST_IS_CYCLIC(list));
    elem = AVS_LIST_APPEND_NEW(int, &list);
    *elem = 1;
    AVS_UNIT_ASSERT_FALSE(AVS_LIST_IS_CYCLIC(list));
    elem = AVS_LIST_APPEND_NEW(int, &list);
    *elem = 2;
    AVS_UNIT_ASSERT_FALSE(AVS_LIST_IS_CYCLIC(list));
    elem = AVS_LIST_APPEND_NEW(int, &list);
    *elem = 3;
    AVS_UNIT_ASSERT_FALSE(AVS_LIST_IS_CYCLIC(list));

    for (i = 4; i < 10; ++i) {
        AVS_LIST(int) *ptr;
        elem = AVS_LIST_APPEND_NEW(int, &list);
        *elem = (int) i;
        ptr = AVS_LIST_APPEND_PTR(&list);
        /* (i-3) elements in loop */
        *ptr = AVS_LIST_NTH(list, 3);
        AVS_UNIT_ASSERT_TRUE(AVS_LIST_IS_CYCLIC(list));
        *ptr = NULL;
    }

    AVS_LIST_CLEAR(&list);
}

AVS_UNIT_TEST(list, simple_clone) {
    int *elem = NULL;
    AVS_LIST(int) list = NULL;
    AVS_LIST(int) cloned = NULL;
    AVS_LIST(int) it = NULL;
    int i;
    for (i = 0; i < 10; ++i) {
        elem = AVS_LIST_APPEND_NEW(int, &list);
        *elem = (int) i;
    }
    AVS_UNIT_ASSERT_NOT_NULL((cloned = AVS_LIST_SIMPLE_CLONE(list)));
    it = cloned;
    for (i = 0; i < 10; ++i) {
        AVS_UNIT_ASSERT_EQUAL(*it, i);
        it = AVS_LIST_NEXT(it);
    }
    AVS_LIST_CLEAR(&list);
    AVS_LIST_CLEAR(&cloned);
}
