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
#ifndef AVS_COMMONS_CRYPTO_OPENSSL_COMMON_H
#define AVS_COMMONS_CRYPTO_OPENSSL_COMMON_H

#include <openssl/err.h>
#include <openssl/opensslv.h>

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_VALGRIND
#    include <stdint.h>
#    include <valgrind/helgrind.h>
#    include <valgrind/memcheck.h>
#    include <valgrind/valgrind.h>
extern void *sbrk(intptr_t __delta);
#else
#    define RUNNING_ON_VALGRIND 0
#    define VALGRIND_HG_DISABLE_CHECKING(addr, len) ((void) 0)
#    define VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(addr, len) ((void) 0)
#endif

VISIBILITY_PRIVATE_HEADER_BEGIN

#ifdef OPENSSL_VERSION_NUMBER
#    define MAKE_OPENSSL_VER(Major, Minor, Fix) \
        (((Major) << 28) | ((Minor) << 20) | ((Fix) << 12))

#    define OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix) \
        (OPENSSL_VERSION_NUMBER >= MAKE_OPENSSL_VER(Major, Minor, Fix))
#else
#    define OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix) 0
#endif

#define OPENSSL_VERSION_NUMBER_LT(Major, Minor, Fix) \
    (!OPENSSL_VERSION_NUMBER_GE(Major, Minor, Fix))

#ifdef AVS_COMMONS_WITH_INTERNAL_LOGS

#    define log_openssl_error()                                                \
        do {                                                                   \
            char error_buffer[256]; /* see 'man ERR_error_string' */           \
            LOG(ERROR, "%s", ERR_error_string(ERR_get_error(), error_buffer)); \
        } while (0)

#else // AVS_COMMONS_WITH_INTERNAL_LOGS

#    define log_openssl_error() ((void) ERR_get_error())

#endif // AVS_COMMONS_WITH_INTERNAL_LOGS

#if OPENSSL_VERSION_NUMBER_LT(1, 1, 0)
#    define EVP_PKEY_up_ref(Key) \
        CRYPTO_add(&(Key)->references, 1, CRYPTO_LOCK_EVP_PKEY)
#    define X509_up_ref(Cert) \
        CRYPTO_add(&(Cert)->references, 1, CRYPTO_LOCK_X509)
#endif

VISIBILITY_PRIVATE_HEADER_END

#endif // AVS_COMMONS_CRYPTO_OPENSSL_COMMON_H
