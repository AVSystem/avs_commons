/*
 * Copyright 2018-2020 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_UTILS_CLEANUP_H
#define AVS_COMMONS_UTILS_CLEANUP_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Cleanups any global state created and used internally by AvsCommons.
 *
 * NOTE: The global state is initialized on demand, when certain operations are
 * performed by the user. Due to this, and care for backwards compatibility
 * there is no method for explicit initialization. The initialization itself is
 * thread-safe as long as threading layer is implemented correctly -- either by
 * means of AVS_COMMONS_WITH_AVS_COMPAT_THREADING configuration option, or by
 * the platform integrator.
 *
 * NOTE: Cleaning up resources leaves AvsCommons in an operational state.
 */
void avs_cleanup_global_state(void);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_UTILS_CLEANUP_H */
