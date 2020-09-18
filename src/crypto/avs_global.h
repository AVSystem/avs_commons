/*
 * Copyright 2020 AVSystem <avsystem@avsystem.com>
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

#ifndef CRYPTO_GLOBAL_H
#define CRYPTO_GLOBAL_H

#include <avsystem/commons/avs_errno.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

#ifndef WITHOUT_SSL
avs_error_t _avs_crypto_initialize_global_state(void);
void _avs_crypto_cleanup_global_state(void);
#else // WITHOUT_SSL
#    define _avs_crypto_initialize_global_state(...) AVS_OK
#    define _avs_crypto_cleanup_global_state(...) ((void) 0)
#endif // WITHOUT_SSL

avs_error_t _avs_crypto_ensure_global_state(void);

VISIBILITY_PRIVATE_HEADER_END

#endif // CRYPTO_GLOBAL_H
