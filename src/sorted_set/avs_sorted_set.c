/*
 * Copyright 2024 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_WITH_AVS_RBTREE

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_sorted_set.h>

#    include <assert.h>

VISIBILITY_SOURCE_BEGIN

struct sorted_set {
    avs_sorted_set_element_comparator_t *cmp;
    void *head;
};

#    define _AVS_SORTED_SET(ptr) \
        AVS_CONTAINER_OF((ptr), struct sorted_set, head)

AVS_SORTED_SET(void)
avs_sorted_set_new__(avs_sorted_set_element_comparator_t *cmp) {
    struct sorted_set *ss =
            (struct sorted_set *) avs_calloc(1, sizeof(struct sorted_set));
    if (!ss) {
        return NULL;
    }

    ss->cmp = cmp;
    ss->head = NULL;

    return &ss->head;
}

AVS_SORTED_SET_ELEM(void)
avs_sorted_set_lower_bound__(AVS_SORTED_SET_CONST(void) sorted_set,
                             const void *value) {
    AVS_SORTED_SET_ELEM(void) curr;

    assert(sorted_set);
    assert(value);

    curr = *(AVS_SORTED_SET(void)) (intptr_t) sorted_set;
    while (curr) {
        if (_AVS_SORTED_SET(sorted_set)->cmp(value, curr) <= 0) {
            return curr;
        }
        curr = AVS_LIST_NEXT(curr);
    }

    return NULL;
}

AVS_SORTED_SET_ELEM(void)
avs_sorted_set_upper_bound__(AVS_SORTED_SET_CONST(void) sorted_set,
                             const void *value) {
    AVS_SORTED_SET_ELEM(void) curr;

    assert(sorted_set);
    assert(value);

    curr = *(AVS_SORTED_SET(void)) (intptr_t) sorted_set;
    while (curr) {
        if (_AVS_SORTED_SET(sorted_set)->cmp(value, curr) < 0) {
            return curr;
        }
        curr = AVS_LIST_NEXT(curr);
    }

    return NULL;
}

AVS_SORTED_SET_ELEM(void) avs_sorted_set_first__(AVS_SORTED_SET_CONST(void)
                                                         sorted_set) {
    if (!sorted_set) {
        return NULL;
    } else {
        return _AVS_SORTED_SET(sorted_set)->head;
    }
}

AVS_SORTED_SET_ELEM(void) avs_sorted_set_last__(AVS_SORTED_SET_CONST(void)
                                                        sorted_set) {
    if (!sorted_set) {
        return NULL;
    }

    AVS_SORTED_SET_ELEM(void) curr = _AVS_SORTED_SET(sorted_set)->head;
    while (curr && AVS_LIST_NEXT(curr)) {
        curr = AVS_LIST_NEXT(curr);
    }

    return curr;
}

AVS_SORTED_SET_ELEM(void)
avs_sorted_set_insert__(AVS_SORTED_SET(void) sorted_set, void *insert_ptr) {
    AVS_SORTED_SET_ELEM(void) tmp = NULL;

    if (!sorted_set) {
        return NULL;
    }

    tmp = avs_sorted_set_find__(sorted_set, insert_ptr);
    if (tmp) {
        /* already present */
        return tmp;
    }

    if (*sorted_set
            && _AVS_SORTED_SET(sorted_set)
                               ->cmp(insert_ptr,
                                     _AVS_SORTED_SET(sorted_set)->head)
                           > 0) {
        /* find place to add element and add it */
        AVS_SORTED_SET_ELEM(void) curr = _AVS_SORTED_SET(sorted_set)->head;

        while (AVS_LIST_NEXT(curr)) {
            if (_AVS_SORTED_SET(sorted_set)
                        ->cmp(insert_ptr, AVS_LIST_NEXT(curr))
                    <= 0) {
                break;
            }
            curr = AVS_LIST_NEXT(curr);
        }
        return AVS_LIST_INSERT(&AVS_LIST_NEXT(curr), insert_ptr);
    } else {
        /* add as a first element*/
        *sorted_set = AVS_LIST_INSERT(sorted_set, insert_ptr);
        return *sorted_set;
    }
}

AVS_SORTED_SET_ELEM(void) avs_sorted_set_find__(AVS_SORTED_SET(void) sorted_set,
                                                const void *element) {
    AVS_SORTED_SET_ELEM(void) curr;

    assert(sorted_set);
    assert(element);

    curr = *(AVS_SORTED_SET(void)) (intptr_t) sorted_set;
    while (curr) {
        int cmp = _AVS_SORTED_SET(sorted_set)->cmp(element, curr);

        if (cmp == 0) {
            return curr;
        } else if (cmp < 0) {
            /*
             * The elements are sorted, all of the elements on the list from
             * this point will be bigger then the element we are looking for.
             */
            break;
        } else {
            curr = AVS_LIST_NEXT(curr);
        }
    }

    return NULL;
}

void avs_sorted_set_delete__(AVS_SORTED_SET(void) *sorted_set_ptr) {
    struct sorted_set *ss;

    if (!sorted_set_ptr || !*sorted_set_ptr) {
        return;
    }

    assert(!**sorted_set_ptr); /* should only be called on empty sorted_set */
    ss = _AVS_SORTED_SET(*sorted_set_ptr);
    avs_free(ss);
    *sorted_set_ptr = NULL;
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/sorted_set/test_sorted_set.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_RBTREE
