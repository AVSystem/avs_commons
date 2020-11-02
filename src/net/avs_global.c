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

#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_NET

#    include "avs_net_global.h"

#    include "crypto/avs_crypto_global.h"

#    include <avsystem/commons/avs_init_once.h>

#    include "avs_net_impl.h"

VISIBILITY_SOURCE_BEGIN

static avs_init_once_handle_t g_net_init_handle;

static int initialize_global(void *err_ptr_) {
    avs_error_t *err_ptr = (avs_error_t *) err_ptr_;
    *err_ptr = _avs_net_initialize_global_compat_state();
    if (avs_is_ok(*err_ptr)) {
        *err_ptr = _avs_net_initialize_global_ssl_state();
        if (avs_is_err(*err_ptr)) {
            _avs_net_cleanup_global_compat_state();
        }
    }
    return avs_is_ok(*err_ptr) ? 0 : -1;
}

void _avs_net_cleanup_global_state(void) {
    _avs_net_cleanup_global_ssl_state();
    _avs_net_cleanup_global_compat_state();
    g_net_init_handle = NULL;
}

avs_error_t _avs_net_ensure_global_state(void) {
#    ifndef WITHOUT_SSL
    avs_error_t err = _avs_crypto_ensure_global_state();
    if (avs_is_err(err)) {
        return err;
    }
#    else  // WITHOUT_SSL
    avs_error_t err = avs_errno(AVS_UNKNOWN_ERROR);
#    endif // WITHOUT_SSL

    if (avs_init_once(&g_net_init_handle, initialize_global, &err)) {
        assert(avs_is_err(err));
        return err;
    } else {
        return AVS_OK;
    }
}

#endif // AVS_COMMONS_WITH_AVS_NET
