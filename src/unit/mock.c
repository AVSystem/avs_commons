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

#define AVS_UNIT_SOURCE
#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_UNIT

#    include <stdio.h>
#    include <stdlib.h>

#    include <avsystem/commons/avs_list.h>

#    include <avsystem/commons/avs_unit_mock_helpers.h>

VISIBILITY_SOURCE_BEGIN

typedef struct {
    avs_unit_mock_func_ptr *mock_ptr;
    unsigned invocations;
} avs_unit_mock_t;

static AVS_LIST(avs_unit_mock_t) ALL_MOCKS;

void avs_unit_mock_add__(avs_unit_mock_func_ptr *new_mock_ptr) {
    avs_unit_mock_t *new_mock = AVS_LIST_NEW_ELEMENT(avs_unit_mock_t);
    if (!new_mock) {
        fprintf(stderr, "cannot add new mock function entry\n");
        exit(EXIT_FAILURE);
    }
    new_mock->mock_ptr = new_mock_ptr;
    AVS_LIST_INSERT(&ALL_MOCKS, new_mock);
}

void avs_unit_mock_reset_all__(void) {
    avs_unit_mock_t *mock_ptr;
    AVS_LIST_FOREACH(mock_ptr, ALL_MOCKS) {
        *mock_ptr->mock_ptr = NULL;
        mock_ptr->invocations = 0;
    }
}

void avs_unit_mock_cleanup__(void) {
    AVS_LIST_CLEAR(&ALL_MOCKS);
}

void avs_unit_mock_invoke__(avs_unit_mock_func_ptr *invoked_func) {
    avs_unit_mock_t *mock_ptr;
    AVS_LIST_FOREACH(mock_ptr, ALL_MOCKS) {
        if (mock_ptr->mock_ptr == invoked_func) {
            ++mock_ptr->invocations;
        }
    }
}

unsigned avs_unit_mock_invocations__(avs_unit_mock_func_ptr *invoked_func) {
    avs_unit_mock_t *mock_ptr;
    AVS_LIST_FOREACH(mock_ptr, ALL_MOCKS) {
        if (mock_ptr->mock_ptr == invoked_func) {
            return mock_ptr->invocations;
        }
    }
    return 0;
}

#endif // AVS_COMMONS_WITH_AVS_UNIT
