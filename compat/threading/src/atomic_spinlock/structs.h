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

#ifndef AVS_COMMONS_COMPAT_THREADING_ATOMIC_SPINLOCK_STRUCTS_H
#define AVS_COMMONS_COMPAT_THREADING_ATOMIC_SPINLOCK_STRUCTS_H

#include <avsystem/commons/condvar.h>
#include <avsystem/commons/mutex.h>

#include <stdatomic.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

// we are not using AVS_LIST because we want to use stack allocation
typedef struct {
    volatile atomic_flag waiting;
    atomic_intptr_t next;
} condvar_waiter_node_t;

struct avs_condvar {
    atomic_intptr_t first_waiter;
};

struct avs_mutex {
    volatile atomic_flag locked;
};

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_COMPAT_THREADING_ATOMIC_SPINLOCK_STRUCTS_H */
