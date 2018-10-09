/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_posix_config.h>

#define MODULE_NAME condvar_atomic_spinlock
#include <x_log_config.h>

#include <avsystem/commons/condvar.h>
#include <avsystem/commons/defs.h>
#include <avsystem/commons/memory.h>

#include "structs.h"

VISIBILITY_SOURCE_BEGIN

int avs_condvar_create(avs_condvar_t **out_condvar) {
    AVS_ASSERT(!*out_condvar,
               "possible attempt to reinitialize a condition variable");

    *out_condvar = (avs_condvar_t *) avs_calloc(1, sizeof(avs_condvar_t));
    return *out_condvar ? 0 : -1;
}

int avs_condvar_notify(avs_condvar_t *condvar) {
    condvar_waiter_node_t *waiter =
            (condvar_waiter_node_t *) atomic_load(&condvar->first_waiter);
    while (waiter) {
        // wake up the waiter
        atomic_flag_clear(&waiter->waiting);

        // Note that this is a race condition with avs_condvar_wait() if
        // avs_condvar_notify() is called without the corresponding mutex
        // locked. We might end up missing some waiters that are just
        // registering.
        waiter = (condvar_waiter_node_t *) atomic_load(&waiter->next);
    }
    return 0;
}

static void insert_new_waiter(avs_condvar_t *condvar,
                              condvar_waiter_node_t *waiter) {
    // Initialize the waiting flag to true
    atomic_flag_clear(&waiter->waiting);
    atomic_flag_test_and_set(&waiter->waiting);

    // Insert the  as the first element on the list
    intptr_t previous_first_waiter = atomic_load(&condvar->first_waiter);
    atomic_init(&waiter->next, previous_first_waiter);
    bool exchange_success =
            atomic_compare_exchange_strong(&condvar->first_waiter,
                                           &previous_first_waiter,
                                           (intptr_t) waiter);
    AVS_ASSERT(exchange_success,
               "waiter list modified during initialization - probably "
               "attempted to call avs_condvar_wait() without mutex locked");
    (void) exchange_success;
}

static void remove_waiter(avs_condvar_t *condvar,
                          condvar_waiter_node_t *waiter) {
    // the condvar waiter list might have been modified by another thread while
    // the mutex was unlocked, so find it before deleting
    atomic_intptr_t *waiter_node_ptr = &condvar->first_waiter;
    intptr_t waiter_node;
    while (true) {
        waiter_node = atomic_load(waiter_node_ptr);
        if (waiter_node == (intptr_t) waiter || !waiter_node) {
            break;
        }
        waiter_node_ptr = &((condvar_waiter_node_t *) waiter_node)->next;
    }
    AVS_ASSERT(waiter_node == (intptr_t) waiter,
               "waiter node inexplicably disappeared from condition variable");
    // detach it
    bool exchange_success = atomic_compare_exchange_strong(
            waiter_node_ptr, &waiter_node, atomic_load(&waiter->next));
    AVS_ASSERT(exchange_success,
               "waiter list modified during cleanup - probably incorrect use "
               "of the mutex");
    (void) exchange_success;
}

int avs_condvar_wait(avs_condvar_t *condvar,
                     avs_mutex_t *mutex,
                     avs_time_monotonic_t deadline) {
    // condvar->first_waiter and every condvar_waiter_node_t::next is only
    // written to when mutex is locked

    // Precondition: mutex is locked by the current thread
    // although we can't check if it's the current thread that locked it :(
    AVS_ASSERT(atomic_flag_test_and_set(&mutex->locked),
               "attempted to use a condition variable with an unlocked mutex");

    bool use_deadline = avs_time_monotonic_valid(deadline);
    bool flag_value;
    condvar_waiter_node_t waiter;
    insert_new_waiter(condvar, &waiter);

    avs_mutex_unlock(mutex);
    do {
        flag_value = atomic_flag_test_and_set(&waiter.waiting);
    } while (flag_value
            && (!use_deadline
                    || avs_time_monotonic_before(avs_time_monotonic_now(),
                                                 deadline)));
    avs_mutex_lock(mutex);

    remove_waiter(condvar, &waiter);

    // flag_value == 0 -> it means it was cleared, so we've been woken up
    // flag_value == 1 -> it mean we haven't, so timeout occurred
    return flag_value;
}

void avs_condvar_cleanup(avs_condvar_t **condvar) {
    if (!*condvar) {
        return;
    }

    AVS_ASSERT(!(*condvar)->first_waiter,
               "attempted to cleanup a condition variable some thread is "
               "waiting on");

    avs_free(*condvar);
    *condvar = NULL;
}
