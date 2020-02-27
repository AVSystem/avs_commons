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

#ifndef AVS_COMMONS_CONDVAR_H
#define AVS_COMMONS_CONDVAR_H

#include <avsystem/commons/avs_mutex.h>
#include <avsystem/commons/avs_time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** A condition variable object. */
typedef struct avs_condvar avs_condvar_t;

/** Value returned from @ref avs_condvar_wait when it times out. */
#define AVS_CONDVAR_TIMEOUT 1

/**
 * Creates a condition variable object.
 *
 * @param[out] out_condvar Pointer to the condition variable handle to
 *                         initialize. Should point to NULL when the function is
 *                         called.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error.
 */
int avs_condvar_create(avs_condvar_t **out_condvar);

/**
 * Signals occurrence of an event to another thread that is waiting on the same
 * object in @ref avs_condvar_wait. If more than one thread is waiting on the
 * same variable, all of them are notified.
 *
 * NOTE: the behavior is undefined if @p condvar is not a condition variable
 * object previously created by @ref avs_condvar_create .
 *
 * @param condvar Condition variable to notify.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error.
 */
int avs_condvar_notify_all(avs_condvar_t *condvar);

/**
 * Waits for an event to occur in another thread. This call shall block until
 * another thread calls @ref avs_condvar_notify_all on the same condition
 * variable or timeout elapses.
 *
 * Spurious wakeups with return value of 0 may occur, so a condition predicate
 * needs to be manually checked regardless of the return value.

 * NOTE: the behavior is undefined if @p condvar is not a condition variable
 * object previously created by @ref avs_condvar_create .
 *
 * @param condvar  Condition variable to wait on.
 * @param mutex    Mutex to temporarily unlock while waiting on the variable.
 * @param deadline Point in time until which to wait for. Might be
 *                 @ref AVS_TIME_MONOTONIC_INVALID, in which case the timeout is
 *                 infinite.
 *
 * @returns @li 0 if event occurred
 *          @li @ref AVS_CONDVAR_TIMEOUT (1) if timeout elapsed
 *          @li Negative value in case of error
 */
int avs_condvar_wait(avs_condvar_t *condvar,
                     avs_mutex_t *mutex,
                     avs_time_monotonic_t deadline);

/**
 * Deletes a condition variable object. Does nothing if <c>*condvar</c> is NULL.
 *
 * NOTE: the behavior is undefined if @p condvar is not a condition variable
 * object previously created by @ref avs_condvar_create , <c>condvar == NULL</c>
 * or @p condvar points to a condition variable that is currently being waited
 * on.
 *
 * @param[inout] condvar Pointer to the condition variable handle to delete.
 *                       After a successful call to this function,
 *                       <c>*condvar</c> is set to NULL.
 */
void avs_condvar_cleanup(avs_condvar_t **condvar);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AVS_COMMONS_CONDVAR_H */
