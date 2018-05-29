/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#include <signal.h>

#ifdef HAVE_C11_STDATOMIC
#include <stdatomic.h>
#endif // HAVE_C11_STDATOMIC

#include "global.h"
#include "net_impl.h"

VISIBILITY_SOURCE_BEGIN

#ifndef HAVE_C11_STDATOMIC

#define atomic_flag bool
#define ATOMIC_FLAG_INIT false

#if defined(__GNUC__) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1))
// also works on Clang
#define atomic_flag_test_and_set(Ptr) (!__sync_bool_compare_and_swap((Ptr), false, true))
#else // __GNUC__
#warning "Atomic boolean operations not available. Initialization of SSL sockets will NOT be thread-safe!"
static bool atomic_flag_test_and_set(volatile bool *ptr) {
    if (!*ptr) {
        *ptr = true;
        return false;
    }
    return true;
}
#endif // __GNUC__

#endif // HAVE_C11_STDATOMIC

static int initialize_global(void) {
    int result = _avs_net_initialize_global_compat_state();
    if (!result) {
        result = _avs_net_initialize_global_ssl_state(); 
        if (result) {
            _avs_net_cleanup_global_compat_state();
        }
    }
    return result;
}

static void cleanup_global(void) {
    _avs_net_cleanup_global_ssl_state();
    _avs_net_cleanup_global_compat_state();
}

int _avs_net_ensure_global_state(void) {
    static volatile atomic_flag TOUCHED = ATOMIC_FLAG_INIT;
    static volatile sig_atomic_t RESULT = 0; // negative - error; positive - OK

    int result = 0;
    if (atomic_flag_test_and_set(&TOUCHED)) {
        // someone has already started initializing the state
        while (!result) {
            result = RESULT;
        }
        if (result > 0) {
            result = 0;
        }
    } else {
        // we need to initialize the global state
        int result = initialize_global();
        if (!result && atexit(cleanup_global)) {
            LOG(WARNING,
                "atexit() failed - global avs_net context will not be freed");
        }
        RESULT = (result < 0 ? result : result == 0 ? 1 : -1);
    }
    return result;
}
