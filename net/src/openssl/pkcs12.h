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
#ifndef NET_OPENSSL_PKCS12_H
#define NET_OPENSSL_PKCS12_H

#include <openssl/ssl.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef struct {
    EVP_PKEY *private_key;
    X509 *client_cert;
    STACK_OF(X509) *additional_ca_certs;
} pkcs12_unpacked_t;

pkcs12_unpacked_t *
_avs_net_openssl_unpack_pkcs12_from_file(const char *filename,
                                         const char *password);

pkcs12_unpacked_t *
_avs_net_openssl_unpack_pkcs12_from_buffer(const void *buffer,
                                           size_t len,
                                           const char *password);

void _avs_net_openssl_pkcs12_free(pkcs12_unpacked_t *pkcs12);

VISIBILITY_PRIVATE_HEADER_END

#endif // NET_OPENSSL_PKCS12_H
