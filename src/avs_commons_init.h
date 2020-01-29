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

#include <avsystem/commons/defs.h>

#if defined(AVS_COMMONS_HAVE_VISIBILITY) && !defined(AVS_UNIT_TESTING)
/* set default visibility for external symbols */
#    pragma GCC visibility push(default)
#    define VISIBILITY_SOURCE_BEGIN _Pragma("GCC visibility push(hidden)")
#    define VISIBILITY_PRIVATE_HEADER_BEGIN \
        _Pragma("GCC visibility push(hidden)")
#    define VISIBILITY_PRIVATE_HEADER_END _Pragma("GCC visibility pop")
#else
#    define VISIBILITY_SOURCE_BEGIN
#    define VISIBILITY_PRIVATE_HEADER_BEGIN
#    define VISIBILITY_PRIVATE_HEADER_END
#endif

#if !defined(AVS_UNIT_TESTING) && !defined(AVS_SUPPRESS_POISONING)
#    include "avs_commons_poison.h"
#endif

#if !(defined(WITH_OPENSSL) || defined(WITH_MBEDTLS) || defined(WITH_TINYDTLS))
#    define WITHOUT_SSL
#endif

#if defined(AVS_COMMONS_WITH_AVS_NET) && defined(WITH_TLS_SESSION_PERSISTENCE) \
        && !defined(AVS_COMMONS_WITH_AVS_PERSISTENCE)
#    error "AVS_COMMONS_WITH_AVS_PERSISTENCE is required for WITH_TLS_SESSION_PERSISTENCE"
#endif
