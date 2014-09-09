/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <avsystem/commons/list.h>

#include <avsystem/commons/unit/mock_helpers.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

typedef struct {
    avs_unit_mock_func_ptr *mock_ptr;
    unsigned invocations;
} avs_unit_mock_t;

static AVS_LIST(avs_unit_mock_t) ALL_MOCKS;

void avs_unit_mock_add__(avs_unit_mock_func_ptr *new_mock_ptr) {
    avs_unit_mock_t *new_mock = AVS_LIST_NEW_ELEMENT(avs_unit_mock_t);
    new_mock->mock_ptr = new_mock_ptr;
    AVS_LIST_INSERT(&ALL_MOCKS, new_mock);
}

void avs_unit_mock_reset_all__() {
    avs_unit_mock_t *mock_ptr;
    AVS_LIST_FOREACH(mock_ptr, ALL_MOCKS) {
        *mock_ptr->mock_ptr = NULL;
        mock_ptr->invocations = 0;
    }
}

void avs_unit_mock_cleanup__() {
    AVS_LIST_CLEAR(&ALL_MOCKS);
}

void avs_unit_mock_invoke__(avs_unit_mock_func_ptr *invoked_func) {
    avs_unit_mock_t *mock_ptr;
    AVS_LIST_FOREACH(mock_ptr, ALL_MOCKS) {
        if(mock_ptr->mock_ptr == invoked_func) {
            ++mock_ptr->invocations;
        }
    }
}

unsigned avs_unit_mock_invocations__(avs_unit_mock_func_ptr *invoked_func) {
    avs_unit_mock_t *mock_ptr;
    AVS_LIST_FOREACH(mock_ptr, ALL_MOCKS) {
        if(mock_ptr->mock_ptr == invoked_func) {
            return mock_ptr->invocations;
        }
    }
    return 0;
}
