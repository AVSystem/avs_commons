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
#ifndef NET_OPENSSL_COMMON_H
#define NET_OPENSSL_COMMON_H

#include <openssl/err.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

#ifdef WITH_INTERNAL_LOGS

#define log_openssl_error() \
    do { \
        char error_buffer[256]; /* see 'man ERR_error_string' */ \
        LOG(ERROR, "%s", ERR_error_string(ERR_get_error(), error_buffer)); \
    } while (0)

#else // WITH_INTERNAL_LOGS

#define log_openssl_error() ((void) 0)

#endif // WITH_INTERNAL_LOGS

VISIBILITY_PRIVATE_HEADER_END

#endif // NET_OPENSSL_COMMON_H
