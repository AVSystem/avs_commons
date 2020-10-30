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

#include <avs_commons_init.h>

#include "../avs_crypto_global.h"

VISIBILITY_SOURCE_BEGIN

#ifdef AVS_COMMONS_WITH_MBEDTLS

avs_error_t _avs_crypto_initialize_global_state() {
    return AVS_OK;
}

void _avs_crypto_cleanup_global_state() {
    return;
}

#endif // AVS_COMMONS_WITH_MBEDTLS