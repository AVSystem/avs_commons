/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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
#ifndef NET_OPENSSL_DATA_LOADER_H
#define NET_OPENSSL_DATA_LOADER_H

#include <openssl/ssl.h>

#include <avsystem/commons/socket.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

int _avs_net_openssl_load_ca_certs(SSL_CTX *ctx,
                                   const avs_net_trusted_cert_info_t *info);
int _avs_net_openssl_load_client_key(SSL_CTX *ctx,
                                     const avs_net_client_key_info_t *info);
int _avs_net_openssl_load_client_cert(SSL_CTX *ctx,
                                      const avs_net_client_cert_info_t *info);

VISIBILITY_PRIVATE_HEADER_END
#endif // NET_OPENSSL_DATA_LOADER_H
