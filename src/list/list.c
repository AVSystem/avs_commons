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

#ifdef AVS_COMMONS_WITH_AVS_LIST

#    include <string.h>

/* We don't want avs_list_assert_acyclic__ called from our own internals */
#    ifndef NDEBUG
#        define NDEBUG
#    endif
#    include <avsystem/commons/avs_list.h>

#    ifdef NDEBUG
#        undef NDEBUG /* We want to call assert() in \
                       * avs_list_assert_acyclic__() \
                       */
#    endif
#    include <assert.h>

VISIBILITY_SOURCE_BEGIN

void *avs_list_adjust_allocated_ptr__(void *allocated) {
    if (allocated) {
        return (char *) allocated + AVS_LIST_SPACE_FOR_NEXT__;
    } else {
        return NULL;
    }
}

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

void **avs_list_append_ptr__(void **list_ptr) {
    AVS_LIST_ITERATE_PTR(list_ptr);
    return list_ptr;
}

void *avs_list_append__(void *element, void **list_ptr) {
    return (*avs_list_append_ptr__(list_ptr) = element);
}

void *avs_list_insert__(void *list_to_insert, void **insert_ptr) {
    if (list_to_insert) {
        void *next = *insert_ptr;
        *insert_ptr = list_to_insert;
        if (next) {
            *AVS_LIST_APPEND_PTR(&list_to_insert) = next;
        }
    }
    return list_to_insert;
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
    if (!list_ptr || !*list_ptr || !AVS_LIST_NEXT(*list_ptr)) {
        /* zero or one element */
        return;
    }
    part1 = *list_ptr;
    half_list(part1, &part2);
    avs_list_sort__(&part1, comparator, element_size);
    avs_list_sort__(&part2, comparator, element_size);
    avs_list_merge__(&part1, &part2, comparator, element_size);
    *list_ptr = part1;
}

int avs_list_is_cyclic__(const void *list) {
    const void *slow = list;
    const void *fast1 = list;
    const void *fast2 = list;
    while (slow && (fast1 = AVS_LIST_NEXT(fast2))
           && (fast2 = AVS_LIST_NEXT(fast1))) {
        if (fast1 == slow || fast2 == slow) {
            return 1;
        }
        slow = AVS_LIST_NEXT(slow);
    }
    return 0;
}

void *avs_list_assert_acyclic__(void *list) {
    assert(!avs_list_is_cyclic__(list));
    return list;
}

void *avs_list_simple_clone__(void *list, size_t elem_size) {
    AVS_LIST(void) retval = NULL;
    AVS_LIST(void) *last = &retval;
    AVS_LIST(void) it;

    AVS_LIST_FOREACH(it, list) {
        void *new_elem = AVS_LIST_NEW_BUFFER(elem_size);
        if (new_elem && AVS_LIST_INSERT(last, new_elem)) {
            memcpy(new_elem, it, elem_size);
            last = AVS_LIST_NEXT_PTR(last);
        } else {
            AVS_LIST_CLEAR(&retval);
            return NULL;
        }
    }
    return retval;
}

static int is_list_sorted(void *list,
                          avs_list_comparator_func_t comparator,
                          size_t element_size) {
    AVS_LIST(void) curr = list;
    AVS_LIST(void) next = list ? AVS_LIST_NEXT(list) : NULL;
    while (curr && next) {
        if (comparator(curr, next, element_size) > 0) {
            return 0;
        }
        curr = next;
        next = AVS_LIST_NEXT(next);
    }
    return 1;
}

void **avs_list_assert_sorted_ptr__(void **listptr,
                                    avs_list_comparator_func_t comparator,
                                    size_t element_size) {
    (void) comparator;
    (void) element_size;
    assert(is_list_sorted(*listptr, comparator, element_size));
    return listptr;
}

void avs_list_merge__(void **target,
                      void **source,
                      avs_list_comparator_func_t comparator,
                      size_t element_size) {
    while (*source) {
        while (*target && comparator(*target, *source, element_size) <= 0) {
            target = AVS_LIST_NEXT_PTR(target);
        }
        AVS_LIST_INSERT(target, AVS_LIST_DETACH(source));
        target = AVS_LIST_NEXT_PTR(target);
    }
}

#endif // AVS_COMMONS_WITH_AVS_LIST
