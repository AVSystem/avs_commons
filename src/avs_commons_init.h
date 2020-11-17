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

#include <avsystem/commons/avs_defs.h>

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

#if !defined(AVS_SUPPRESS_POISONING)
#    include "avs_commons_poison.h"
#endif

#if !(defined(AVS_COMMONS_WITH_OPENSSL) || defined(AVS_COMMONS_WITH_MBEDTLS) \
      || defined(AVS_COMMONS_WITH_TINYDTLS))                                 \
        && !defined(WITHOUT_SSL)
#    define WITHOUT_SSL
#endif

#if defined(AVS_COMMONS_WITH_INTERNAL_LOGS) \
        && !defined(AVS_COMMONS_WITH_AVS_LOG)
#    error "AVS_COMMONS_WITH_AVS_LOG is required for AVS_COMMONS_WITH_INTERNAL_LOGS"
#endif

#if defined(AVS_COMMONS_WITH_AVS_NET)                            \
        && defined(AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE) \
        && !defined(AVS_COMMONS_WITH_AVS_PERSISTENCE)
#    error "AVS_COMMONS_WITH_AVS_PERSISTENCE is required for AVS_COMMONS_NET_WITH_TLS_SESSION_PERSISTENCE"
#endif

#if !defined(AVS_COMMONS_WITH_AVS_STREAM) \
        && defined(AVS_COMMONS_STREAM_WITH_FILE)
#    error "AVS_COMMONS_WITH_AVS_STREAM is required for AVS_COMMONS_STREAM_WITH_FILE"
#endif

#if !defined(AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE) \
        && defined(AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE)
#    error "AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE is required for AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE"
#endif

// Backwards compatibility with configuration macros that are no longer current
#ifdef AVS_COMMONS_NET_WITH_X509
#    warning \
            "AVS_COMMONS_NET_WITH_X509 is deprecated since avs_commons 4.2. Please update your avs_commons_config.h to use AVS_COMMONS_WITH_AVS_CRYPTO_PKI instead."
#    define AVS_COMMONS_WITH_AVS_CRYPTO_PKI
#endif // AVS_COMMONS_NET_WITH_X509

#ifdef AVS_COMMONS_NET_WITH_VALGRIND
#    warning \
            "AVS_COMMONS_NET_WITH_VALGRIND is deprecated since avs_commons 4.2. Please update your avs_commons_config.h to use AVS_COMMONS_WITH_AVS_CRYPTO_VALGRIND instead."
#    define AVS_COMMONS_WITH_AVS_CRYPTO_VALGRIND
#endif // AVS_COMMONS_NET_WITH_VALGRIND
