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

#ifdef LOG
#    undef LOG
#endif

#ifndef MODULE_NAME
#    error "You need to define MODULE_NAME before including this header"
#endif

// enable short _() macro
#define _(Arg) AVS_DISPOSABLE_LOG(Arg)

#ifdef AVS_COMMONS_WITH_INTERNAL_LOGS

// these macros interfere with avs_log() macro implementation
#    ifdef TRACE
#        undef TRACE
#    endif
#    ifdef DEBUG
#        undef DEBUG
#    endif
#    ifdef INFO
#        undef INFO
#    endif
#    ifdef WARNING
#        undef WARNING
#    endif
#    ifdef ERROR
#        undef ERROR
#    endif

#    ifdef AVS_COMMONS_WITH_INTERNAL_TRACE
#        define AVS_LOG_WITH_TRACE
#    endif

#    include <avsystem/commons/avs_log.h>
#    define LOG(...) avs_log(MODULE_NAME, __VA_ARGS__)

#else

#    define LOG(...) ((void) 0)

#    ifdef AVS_UNIT_TESTING
// this should never be called by the library outside test suites
#        define avs_log_set_default_level(...) ((void) 0)
#    endif

#endif
