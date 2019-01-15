/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#include <avs_commons_config.h>

#include "global.h"
#include "net_impl.h"

#include <avsystem/commons/init_once.h>

VISIBILITY_SOURCE_BEGIN

static avs_init_once_handle_t g_net_init_handle;

static int initialize_global(void *unused) {
    (void) unused;
    int result = _avs_net_initialize_global_compat_state();
    if (!result) {
        result = _avs_net_initialize_global_ssl_state();
        if (result) {
            _avs_net_cleanup_global_compat_state();
        }
    }
    return result;
}

void _avs_net_cleanup_global_state(void) {
    _avs_net_cleanup_global_ssl_state();
    _avs_net_cleanup_global_compat_state();
    g_net_init_handle = NULL;
}

int _avs_net_ensure_global_state(void) {
    return avs_init_once(&g_net_init_handle, initialize_global, NULL);
}
