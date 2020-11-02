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

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO

#    include "avs_crypto_global.h"
#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_init_once.h>

#    define MODULE_NAME avs_crypto_aead
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static avs_init_once_handle_t g_crypto_init_handle;

static int initialize_global(void *err_ptr_) {
    avs_error_t *err_ptr = (avs_error_t *) err_ptr_;
    *err_ptr = _avs_crypto_initialize_global_state();
    return avs_is_ok(*err_ptr) ? 0 : -1;
}

avs_error_t _avs_crypto_ensure_global_state(void) {
    avs_error_t err = avs_errno(AVS_UNKNOWN_ERROR);
    if (avs_init_once(&g_crypto_init_handle, initialize_global, &err)) {
        assert(avs_is_err(err));
        LOG(ERROR, _("avs_crypto global state initialization error"));
        return err;
    } else {
        return AVS_OK;
    }
}

#endif // AVS_COMMONS_WITH_AVS_CRYPTO
