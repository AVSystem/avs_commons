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

#ifndef AVS_COMMONS_NET_MBEDTLS_PERSISTENCE_H
#define AVS_COMMONS_NET_MBEDTLS_PERSISTENCE_H

#include <stddef.h>

#include <mbedtls/ssl.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

avs_error_t _avs_net_mbedtls_session_save(mbedtls_ssl_session *session,
                                          void *out_buf,
                                          size_t out_buf_size);

avs_error_t _avs_net_mbedtls_session_restore(mbedtls_ssl_session *out_session,
                                             const void *buf,
                                             size_t buf_size);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_NET_MBEDTLS_PERSISTENCE_H */
