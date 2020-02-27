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

#ifndef AVS_COMMONS_INIT_ONCE_H
#define AVS_COMMONS_INIT_ONCE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct avs_init_once_handle *avs_init_once_handle_t;

/**
 * Initialization function type.
 *
 * @param arg Opaque argument, as passed to @ref avs_init_once .
 *
 * @returns 0 on success, a negative value in case of error.
 */
typedef int avs_init_once_func_t(void *arg);

/**
 * Runs @p func if it was not yet called before with @p handle by any thread,
 * or all its previous calls failed.
 *
 * The implementation MUST ensure that even in the presence of multiple
 * parallel threads:
 * - @p func is never called after its first successful execution,
 * - two @ref avs_init_once calls with the same @p handle never call @p func
 *   in parallel.
 *
 * WARNING: calling @ref avs_unit_once with the same @p handle from within
 * @p func results in undefined behavior.
 *
 * @param[inout] handle   Implementation-specific data required to keep track
 *                        of whether @p func was already called successfully
 *                        or not. MUST be initialized to NULL at program start.
 * @param[in]    func     Function to call exactly once.
 *                        Should return 0 on success, non-zero on failure.
 * @param[in]    func_arg Arbitrary argument, passed to @p func.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error.
 */
int avs_init_once(volatile avs_init_once_handle_t *handle,
                  avs_init_once_func_t *func,
                  void *func_arg);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AVS_COMMONS_INIT_ONCE_H */
