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

#ifndef AVS_COMMONS_MUTEX_H
#define AVS_COMMONS_MUTEX_H

#ifdef __cplusplus
extern "C" {
#endif

/** A non-recursive mutex object. */
typedef struct avs_mutex avs_mutex_t;

/**
 * Creates a mutex object.
 *
 * @param[out] out_mutex Pointer to the mutex handle to initialize.
 *                       Should point to NULL when the function is called.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error.
 */
int avs_mutex_create(avs_mutex_t **out_mutex);

/**
 * Locks the mutex. Blocks until successful or an irrecoverable failure
 * happens.
 *
 * NOTE: the behavior is undefined if @p mutex is not a mutex object
 * previously created by @ref avs_mutex_create .
 *
 * WARNING: the mutex is NOT recursive. Locking an already held mutex
 * results in undefined behavior.
 *
 * @param mutex Mutex to lock.
 *
 * @returns @li 0 if the mutex was successfully locked,
 *          @li a negative value on failure.
 */
int avs_mutex_lock(avs_mutex_t *mutex);

/**
 * Attempts to lock the mutex, returning immediately if it is already locked.
 *
 * NOTE: the behavior is undefined if @p mutex is not a mutex object
 * previously created by @ref avs_mutex_create .
 *
 * @param mutex Mutex to lock.
 *
 * @returns @li 0 if the mutex was successfully locked,
 *          @li 1 if the mutex is already locked,
 *          @li a negative value on other kind of failure.
 */
int avs_mutex_try_lock(avs_mutex_t *mutex);

/**
 * Releases the mutex.
 *
 * NOTE: the behavior is undefined if @p mutex is not a mutex object
 * previously created by @ref avs_mutex_create .
 *
 * @param mutex Mutex to unlock. If not locked by currently executing thread,
 *              the behavior is undefined.
 *
 * @returns @li 0 if the mutex was successfully released,
 *          @li a negative value on failure.
 */
int avs_mutex_unlock(avs_mutex_t *mutex);

/**
 * Deletes a mutex object. Does nothing if <c>*mutex</c> is NULL.
 *
 * NOTE: the behavior is undefined if @p mutex is not a mutex object
 * previously created by @ref avs_mutex_create , <c>mutex == NULL</c>
 * or @p mutex points to a locked mutex.
 *
 * @param[inout] mutex Pointer to the mutex handle to delete.
 *                     After a successful call to this function, <c>*mutex</c>
 *                     is set to NULL.
 */
void avs_mutex_cleanup(avs_mutex_t **mutex);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AVS_COMMONS_MUTEX_H */
