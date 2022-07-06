/*
 * Copyright 2022 AVSystem <avsystem@avsystem.com>
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

/* terminated with 0 */
static AVS_SORTED_SET(int) make_sorted_set(int first, ...) {
    AVS_SORTED_SET(int) sorted_set = AVS_SORTED_SET_NEW(int, int_comparator);
    va_list list;
    int value = first;
    size_t num_values = 0;

    AVS_UNIT_ASSERT_NOT_NULL(sorted_set);
    va_start(list, first);

    while (value != 0) {
        AVS_SORTED_SET_ELEM(int) elem = AVS_SORTED_SET_ELEM_NEW(int);
        AVS_UNIT_ASSERT_NOT_NULL(elem);

        *elem = value;
        AVS_UNIT_ASSERT_TRUE(elem == AVS_SORTED_SET_INSERT(sorted_set, elem));

        value = va_arg(list, int);
        ++num_values;
    }

    va_end(list);

    AVS_UNIT_ASSERT_EQUAL(num_values, AVS_SORTED_SET_SIZE(sorted_set));

    return sorted_set;
}

AVS_UNIT_TEST(sorted_set, create) {
    AVS_SORTED_SET(int) sorted_set = AVS_SORTED_SET_NEW(int, int_comparator);

    struct sorted_set *sorted_set_struct = _AVS_SORTED_SET(sorted_set);
    AVS_UNIT_ASSERT_TRUE(sorted_set_struct->cmp == int_comparator);
    AVS_UNIT_ASSERT_NULL(sorted_set_struct->head);
    AVS_UNIT_ASSERT_EQUAL((size_t) 0, AVS_SORTED_SET_SIZE(sorted_set));

    AVS_SORTED_SET_DELETE(&sorted_set);
}

AVS_UNIT_TEST(sorted_set, create_element) {
    AVS_SORTED_SET_ELEM(int) elem = AVS_SORTED_SET_ELEM_NEW(int);

    AVS_UNIT_ASSERT_TRUE(NULL == AVS_SORTED_SET_ELEM_NEXT(elem));
    AVS_UNIT_ASSERT_EQUAL(0, *elem);

    AVS_SORTED_SET_ELEM_DELETE_DETACHED(&elem);
}

AVS_UNIT_TEST(sorted_set, clear) {
    AVS_SORTED_SET(int) sorted_set = make_sorted_set(8, 7, 4, 3, 10, 5, 0);

    int expected_cleanup_order[] = { 3, 4, 5, 7, 8, 10 };

    size_t i = 0;
    AVS_SORTED_SET_CLEAR(sorted_set) {
        AVS_UNIT_ASSERT_EQUAL(**sorted_set, expected_cleanup_order[i++]);
    }

    AVS_UNIT_ASSERT_NOT_NULL(sorted_set);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 0);

    AVS_SORTED_SET_ELEM(int) new_elem = AVS_SORTED_SET_ELEM_NEW(int);
    *new_elem = 42;
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, new_elem)
                         == new_elem);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 1);

    AVS_SORTED_SET_DELETE(&sorted_set);
}

AVS_UNIT_TEST(sorted_set, first_last_element) {
    AVS_SORTED_SET(int) sorted_set =
            make_sorted_set(8, 7, 4, 3, 10, 5, 9, 18, 1, 16, 0);

    AVS_UNIT_ASSERT_EQUAL(1, *AVS_SORTED_SET_FIRST(sorted_set));
    AVS_UNIT_ASSERT_EQUAL(18, *AVS_SORTED_SET_LAST(sorted_set));

    AVS_SORTED_SET_DELETE(&sorted_set);
}

AVS_UNIT_TEST(sorted_set, lower_bound) {
    // clang-formt off
    AVS_SORTED_SET(int) sorted_set =
            make_sorted_set(80, 40, 120, 20, 60, 100, 140, 10, 30, 50, 70, 90,
                            110, 130, 150, 0);
    // clang-formt on

    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(1))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(10)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(10))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(10)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(12))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(20)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(20))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(20)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(23))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(30)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(30))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(30)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(34))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(40)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(40))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(40)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(45))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(50)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(50))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(50)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(56))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(60)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(60))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(60)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(67))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(70)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(70))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(70)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(78))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(80)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(80))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(80)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(89))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(90)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(90))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(90)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(91))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(100)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(100))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(100)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(102))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(110)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(110))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(110)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(113))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(120)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(120))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(120)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(124))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(130)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(130))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(130)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(135))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(140)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(140))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(140)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(146))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(150)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(150))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(150)));
    AVS_UNIT_ASSERT_NULL(AVS_SORTED_SET_LOWER_BOUND(sorted_set, INTPTR(157)));

    AVS_SORTED_SET_DELETE(&sorted_set);
}

AVS_UNIT_TEST(sorted_set, upper_bound) {
    // clang-formt off
    AVS_SORTED_SET(int) sorted_set =
            make_sorted_set(80, 40, 120, 20, 60, 100, 140, 10, 30, 50, 70, 90,
                            110, 130, 150, 0);
    // clang-format on
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(1))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(10)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(10))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(20)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(12))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(20)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(20))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(30)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(23))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(30)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(30))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(40)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(34))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(40)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(40))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(50)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(45))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(50)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(50))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(60)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(56))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(60)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(60))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(70)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(67))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(70)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(70))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(80)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(78))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(80)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(80))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(90)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(89))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(90)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(90))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(100)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(91))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(100)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(100))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(110)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(102))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(110)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(110))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(120)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(113))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(120)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(120))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(130)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(124))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(130)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(130))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(140)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(135))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(140)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(140))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(150)));
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(146))
                         == AVS_SORTED_SET_FIND(sorted_set, INTPTR(150)));
    AVS_UNIT_ASSERT_NULL(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(150)));
    AVS_UNIT_ASSERT_NULL(AVS_SORTED_SET_UPPER_BOUND(sorted_set, INTPTR(157)));

    AVS_SORTED_SET_DELETE(&sorted_set);
}

AVS_UNIT_TEST(sorted_set, find) {
    // clang-formt off
    AVS_SORTED_SET(int) sorted_set =
            make_sorted_set(80, 40, 120, 20, 60, 100, 140, 10, 30, 50, 70, 90,
                            110, 130, 150, 0);
    // clang-format on

    AVS_UNIT_ASSERT_EQUAL(10, *AVS_SORTED_SET_FIND(sorted_set, INTPTR(10)));
    AVS_UNIT_ASSERT_EQUAL(150, *AVS_SORTED_SET_FIND(sorted_set, INTPTR(150)));
    AVS_UNIT_ASSERT_EQUAL(50, *AVS_SORTED_SET_FIND(sorted_set, INTPTR(50)));

    /* elements not on list */
    AVS_UNIT_ASSERT_NULL(AVS_SORTED_SET_FIND(sorted_set, INTPTR(5)));
    AVS_UNIT_ASSERT_NULL(AVS_SORTED_SET_FIND(sorted_set, INTPTR(42)));
    AVS_UNIT_ASSERT_NULL(AVS_SORTED_SET_FIND(sorted_set, INTPTR(500)));

    AVS_SORTED_SET_DELETE(&sorted_set);
}

AVS_UNIT_TEST(sorted_set, double_insert) {
    AVS_SORTED_SET(int) sorted_set = AVS_SORTED_SET_NEW(int, int_comparator);

    AVS_UNIT_ASSERT_EQUAL((size_t) 0, AVS_SORTED_SET_SIZE(sorted_set));

    AVS_SORTED_SET_ELEM(int) new_elem = AVS_SORTED_SET_ELEM_NEW(int);
    *new_elem = 42;
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, new_elem)
                         == new_elem);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 1);

    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, new_elem)
                         == new_elem);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 1);

    AVS_SORTED_SET_ELEM(int) duplicate_elem = AVS_SORTED_SET_ELEM_NEW(int);
    *duplicate_elem = 42;

    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, duplicate_elem)
                         == new_elem);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 1);

    AVS_SORTED_SET_ELEM_DELETE_DETACHED(&duplicate_elem);
    AVS_SORTED_SET_DELETE(&sorted_set);
}

AVS_UNIT_TEST(sorted_set, delete_elem) {
    AVS_SORTED_SET(int) sorted_set = AVS_SORTED_SET_NEW(int, int_comparator);

    AVS_SORTED_SET_ELEM(int) elem_1 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_2 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_3 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_4 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_5 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_6 = AVS_SORTED_SET_ELEM_NEW(int);

    *elem_1 = 1;
    *elem_2 = 2;
    *elem_3 = 3;
    *elem_4 = 4;
    *elem_5 = 5;
    *elem_6 = 6;

    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_1) == elem_1);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_2) == elem_2);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_3) == elem_3);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_4) == elem_4);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_5) == elem_5);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_6) == elem_6);

    /* delete first element */
    AVS_SORTED_SET_DELETE_ELEM(sorted_set, &elem_1);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 5);

    /* delete last element */
    AVS_SORTED_SET_DELETE_ELEM(sorted_set, &elem_6);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 4);

    /* delete from the middle */
    AVS_SORTED_SET_DELETE_ELEM(sorted_set, &elem_3);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 3);
    AVS_SORTED_SET_DELETE_ELEM(sorted_set, &elem_4);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 2);

    /* delete last two elements */
    AVS_SORTED_SET_DELETE_ELEM(sorted_set, &elem_2);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 1);
    AVS_SORTED_SET_DELETE_ELEM(sorted_set, &elem_5);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 0);

    AVS_UNIT_ASSERT_NULL(elem_1);
    AVS_UNIT_ASSERT_NULL(elem_2);
    AVS_UNIT_ASSERT_NULL(elem_3);
    AVS_UNIT_ASSERT_NULL(elem_4);
    AVS_UNIT_ASSERT_NULL(elem_5);
    AVS_UNIT_ASSERT_NULL(elem_6);

    AVS_UNIT_ASSERT_NULL(*sorted_set);

    /* try to delete a NULL pointer*/
    AVS_SORTED_SET_DELETE_ELEM(sorted_set, &elem_5);

    AVS_SORTED_SET_DELETE(&sorted_set);
}

AVS_UNIT_TEST(sorted_set, detach_elem) {
    AVS_SORTED_SET(int) sorted_set = AVS_SORTED_SET_NEW(int, int_comparator);

    AVS_SORTED_SET_ELEM(int) elem_1 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_2 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_3 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_4 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_5 = AVS_SORTED_SET_ELEM_NEW(int);
    AVS_SORTED_SET_ELEM(int) elem_6 = AVS_SORTED_SET_ELEM_NEW(int);

    *elem_1 = 1;
    *elem_2 = 2;
    *elem_3 = 3;
    *elem_4 = 4;
    *elem_5 = 5;
    *elem_6 = 6;

    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_1) == elem_1);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_2) == elem_2);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_3) == elem_3);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_4) == elem_4);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_5) == elem_5);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_INSERT(sorted_set, elem_6) == elem_6);

    /* detach first element */
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_DETACH(sorted_set, elem_1) == elem_1);
    AVS_UNIT_ASSERT_TRUE(*sorted_set
                         == elem_2); // sorted_set points to elem_2 now
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 5);

    /* detach last element */
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_DETACH(sorted_set, elem_6) == elem_6);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 4);

    /* delete from the middle */
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_DETACH(sorted_set, elem_3) == elem_3);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 3);
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_DETACH(sorted_set, elem_4) == elem_4);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 2);

    /* detach the last two elements */
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_DETACH(sorted_set, elem_2) == elem_2);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 1);
    AVS_UNIT_ASSERT_TRUE(*sorted_set
                         == elem_5); // sorted_set points to elem_5 now
    AVS_UNIT_ASSERT_TRUE(AVS_SORTED_SET_DETACH(sorted_set, elem_5) == elem_5);
    AVS_UNIT_ASSERT_EQUAL(AVS_SORTED_SET_SIZE(sorted_set), 0);

    AVS_UNIT_ASSERT_NULL(*sorted_set);

    AVS_SORTED_SET_ELEM_DELETE_DETACHED(&elem_1);
    AVS_SORTED_SET_ELEM_DELETE_DETACHED(&elem_2);
    AVS_SORTED_SET_ELEM_DELETE_DETACHED(&elem_3);
    AVS_SORTED_SET_ELEM_DELETE_DETACHED(&elem_4);
    AVS_SORTED_SET_ELEM_DELETE_DETACHED(&elem_5);
    AVS_SORTED_SET_ELEM_DELETE_DETACHED(&elem_6);

    AVS_SORTED_SET_DELETE(&sorted_set);
}
