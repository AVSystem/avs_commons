/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <avsystem/commons/list.h>

void *avs_list_nth__(void *list, size_t n) {
    void *element = NULL;
    AVS_LIST_FOREACH(element, list) {
        if (n-- == 0) {
            break;
        }
    }
    return element;
}

void **avs_list_nth_ptr__(void **list_ptr, size_t n) {
    void **element_ptr = NULL;
    AVS_LIST_FOREACH_PTR(element_ptr, list_ptr) {
        if (n-- == 0) {
            return element_ptr;
        }
    }
    return NULL;
}

void **avs_list_find_ptr__(void **list_ptr, void *element) {
    void **element_ptr = NULL;
    AVS_LIST_FOREACH_PTR(element_ptr, list_ptr) {
        if (*element_ptr == element) {
            return element_ptr;
        }
    }
    return NULL;
}

void **avs_list_find_by_value_ptr__(void **list_ptr,
                                    void *value_ptr,
                                    avs_list_comparator_func_t comparator,
                                    size_t value_size) {
    void **element_ptr = NULL;
    AVS_LIST_FOREACH_PTR(element_ptr, list_ptr) {
        if (!comparator(*element_ptr, value_ptr, value_size)) {
            return element_ptr;
        }
    }
    return NULL;
}

void *avs_list_tail__(void *list) {
    void *element = NULL;
    AVS_LIST_FOREACH(element, list) {
        if (!AVS_LIST_NEXT(element)) {
            break;
        }
    }
    return element;
}

void *avs_list_detach__(void **to_detach_ptr) {
    void *retval = *to_detach_ptr;
    *to_detach_ptr = AVS_LIST_NEXT(*(to_detach_ptr));
    AVS_LIST_NEXT(retval) = NULL;
    return retval;
}


size_t avs_list_size__(const void *list) {
    size_t retval = 0;
    AVS_LIST_ITERATE(list) {
        ++retval;
    }
    return retval;
}

static void half_list(void *list, void **part2_ptr) {
    size_t length = AVS_LIST_SIZE(list);
    length /= 2;
    while (--length) {
        list = AVS_LIST_NEXT(list);
    }
    *part2_ptr = AVS_LIST_NEXT(list);
    AVS_LIST_NEXT(list) = NULL;
}

void avs_list_sort__(void **list_ptr,
                     avs_list_comparator_func_t comparator,
                     size_t element_size) {
    AVS_LIST(void) part1 = NULL;
    AVS_LIST(void) part2 = NULL;
    AVS_LIST(void) *list_end_ptr = NULL;
    if (!list_ptr || !*list_ptr || !AVS_LIST_NEXT(*list_ptr)) {
        /* zero or one element */
        return;
    }
    part1 = *list_ptr;
    half_list(part1, &part2);
    *list_ptr = NULL;
    list_end_ptr = list_ptr;
    avs_list_sort__(&part1, comparator, element_size);
    avs_list_sort__(&part2, comparator, element_size);
    while (part1 && part2) {
        if (comparator(part1, part2, element_size) <= 0) {
            AVS_LIST_INSERT(list_end_ptr, AVS_LIST_DETACH(&part1));
        } else {
            AVS_LIST_INSERT(list_end_ptr, AVS_LIST_DETACH(&part2));
        }
        list_end_ptr = AVS_LIST_NEXT_PTR(list_end_ptr);
    }
    if (part1) {
        *list_end_ptr = part1;
    } else {
        *list_end_ptr = part2;
    }
}

#ifdef AVS_UNIT_TESTING
#include "test/test_list.c"
#endif
