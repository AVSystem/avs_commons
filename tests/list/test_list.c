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

#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_unit_mock_helpers.h>
#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_MOCK_CREATE(avs_calloc)
#define avs_calloc(...) AVS_UNIT_MOCK_WRAPPER(avs_calloc)(__VA_ARGS__)

#include <avsystem/commons/avs_list.h>

AVS_UNIT_TEST(list, one_element) {
    size_t count = 0;
    size_t i = 0;
    int *list = NULL;
    int *element = NULL;
    AVS_UNIT_ASSERT_TRUE(AVS_LIST_INSERT_NEW(int, &list) == list);
    *list = 514;
    for (i = 0; i < 10; ++i) {
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

    AVS_UNIT_MOCK(avs_calloc) = failing_calloc;

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

        int **element_ptr = AVS_LIST_FIND_BY_VALUE_PTR(&list, &element, memcmp);
        AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t) element_ptr, (intptr_t) NULL);
        AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t) *element_ptr, (intptr_t) NULL);
        AVS_UNIT_ASSERT_EQUAL(**element_ptr, element);

        element_ptr = (int **) AVS_LIST_NEXT_PTR(element_ptr);
        AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t) element_ptr, (intptr_t) NULL);
        AVS_UNIT_ASSERT_NOT_EQUAL((intptr_t) *element_ptr, (intptr_t) NULL);
        AVS_UNIT_ASSERT_EQUAL(**element_ptr, element + 1);
    }
    AVS_LIST_CLEAR(&list);
}

typedef struct {
    size_t orig_position;
    int value;
} test_elem_t;

static int
test_elem_comparator(const void *left, const void *right, size_t sz) {
    AVS_UNIT_ASSERT_EQUAL(sz, sizeof(test_elem_t));
    return ((const test_elem_t *) left)->value
           - ((const test_elem_t *) right)->value;
}

AVS_UNIT_TEST(list, sort) {
    AVS_LIST(test_elem_t) list = NULL;
    AVS_LIST(test_elem_t) element = NULL;
    size_t i;

    for (i = 0; i < 10; ++i) {
        AVS_UNIT_ASSERT_NOT_NULL((element = AVS_LIST_NEW_ELEMENT(test_elem_t)));
        element->orig_position = i;
        switch (i) {
        case 0:
            element->value = 11;
            break;
        case 1:
            element->value = 51;
            break;
        case 2:
            element->value = 77;
            break;
        case 3:
            element->value = 35;
            break;
        case 4:
            element->value = 11;
            break;
        case 5:
            element->value = 69;
            break;
        case 6:
            element->value = 58;
            break;
        case 7:
            element->value = 69;
            break;
        case 8:
            element->value = 56;
            break;
        case 9:
            element->value = 11;
            break;
        }
        AVS_LIST_APPEND(&list, element);
    }

    AVS_LIST_SORT(&list, test_elem_comparator);

    i = 0;
    AVS_LIST_CLEAR(&list) {
        switch (i++) {
        case 0:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 0);
            AVS_UNIT_ASSERT_EQUAL(list->value, 11);
            break;
        case 1:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 4);
            AVS_UNIT_ASSERT_EQUAL(list->value, 11);
            break;
        case 2:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 9);
            AVS_UNIT_ASSERT_EQUAL(list->value, 11);
            break;
        case 3:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 3);
            AVS_UNIT_ASSERT_EQUAL(list->value, 35);
            break;
        case 4:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 1);
            AVS_UNIT_ASSERT_EQUAL(list->value, 51);
            break;
        case 5:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 8);
            AVS_UNIT_ASSERT_EQUAL(list->value, 56);
            break;
        case 6:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 6);
            AVS_UNIT_ASSERT_EQUAL(list->value, 58);
            break;
        case 7:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 5);
            AVS_UNIT_ASSERT_EQUAL(list->value, 69);
            break;
        case 8:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 7);
            AVS_UNIT_ASSERT_EQUAL(list->value, 69);
            break;
        case 9:
            AVS_UNIT_ASSERT_EQUAL(list->orig_position, 2);
            AVS_UNIT_ASSERT_EQUAL(list->value, 77);
            break;
        }
    }
}

AVS_UNIT_TEST(list, sort_empty) {
    AVS_LIST(test_elem_t) empty_list = NULL;
    AVS_LIST_SORT(&empty_list, test_elem_comparator);
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
        ptr = (AVS_LIST(int) *) AVS_LIST_APPEND_PTR(&list);
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

AVS_UNIT_TEST(list, merge) {
    AVS_LIST(test_elem_t) first = NULL;
    AVS_LIST(test_elem_t) second = NULL;

    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 0, 1 };
    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 1, 3 };
    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 2, 4 };
    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 3, 5 };

    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 10, 0 };
    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 11, 2 };
    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 12, 3 };
    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 13, 4 };
    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 14, 6 };

    static const test_elem_t expected_elements_1[] = { { 10, 0 }, { 0, 1 },
                                                       { 11, 2 }, { 1, 3 },
                                                       { 12, 3 }, { 2, 4 },
                                                       { 13, 4 }, { 3, 5 },
                                                       { 14, 6 } };

    AVS_LIST_MERGE(&first, &second, test_elem_comparator);
    AVS_LIST(test_elem_t) it;
    int i = 0;
    AVS_LIST_FOREACH(it, first) {
        AVS_UNIT_ASSERT_EQUAL(it->orig_position,
                              expected_elements_1[i].orig_position);
        AVS_UNIT_ASSERT_EQUAL(it->value, expected_elements_1[i].value);
        ++i;
    }
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(second), 0);
    AVS_LIST_CLEAR(&second);
    AVS_LIST_CLEAR(&first);

    // Once again, but now let's merge `first` with the `second`
    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 0, 1 };
    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 1, 3 };
    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 2, 4 };
    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 3, 5 };

    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 10, 0 };
    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 11, 2 };
    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 12, 3 };
    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 13, 4 };
    *(test_elem_t *) AVS_LIST_APPEND(&second,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 14, 6 };

    static const test_elem_t expected_elements_2[] = { { 10, 0 }, { 0, 1 },
                                                       { 11, 2 }, { 12, 3 },
                                                       { 1, 3 },  { 13, 4 },
                                                       { 2, 4 },  { 3, 5 },
                                                       { 14, 6 } };

    AVS_LIST_MERGE(&second, &first, test_elem_comparator);
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(second), 9);
    i = 0;
    AVS_LIST_FOREACH(it, second) {
        AVS_UNIT_ASSERT_EQUAL(it->orig_position,
                              expected_elements_2[i].orig_position);
        AVS_UNIT_ASSERT_EQUAL(it->value, expected_elements_2[i].value);
        ++i;
    }
    AVS_LIST_CLEAR(&second);
    AVS_LIST_CLEAR(&first);
}

AVS_UNIT_TEST(list, merge_empty_lists) {
    AVS_LIST(test_elem_t) first = NULL;
    AVS_LIST(test_elem_t) second = NULL;
    AVS_LIST_MERGE(&first, &second, test_elem_comparator);
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(first), 0);
}

AVS_UNIT_TEST(list, merge_when_one_list_is_empty) {
    AVS_LIST(test_elem_t) first = NULL;
    AVS_LIST(test_elem_t) second = NULL;

    *(test_elem_t *) AVS_LIST_APPEND(&first,
                                     AVS_LIST_NEW_ELEMENT(test_elem_t)) =
            (test_elem_t) { 1, 1 };
    AVS_LIST_MERGE(&first, &second, test_elem_comparator);
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(first), 1);

    AVS_LIST_MERGE(&second, &first, test_elem_comparator);
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(first), 0);
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(second), 1);

    AVS_LIST_CLEAR(&first);
    AVS_LIST_CLEAR(&second);
}
