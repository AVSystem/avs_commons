/*
 * Copyright 2020 AVSystem <avsystem@avsystem.com>
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
#ifndef CRYPTO_OPENSSL_GLOBAL_H
#define CRYPTO_OPENSSL_GLOBAL_H

#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#include <openssl/ssl.h>
#ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
#    include <libp11.h>
#    include <openssl/engine.h>
#endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE

#include <avs_commons_poison.h>

#include "../avs_global.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

#ifdef AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE
extern ENGINE *_avs_global_engine;
extern PKCS11_CTX *_avs_global_pkcs11_ctx;
extern PKCS11_SLOT *_avs_global_pkcs11_slots;
extern unsigned int _avs_global_pkcs11_slot_num;
#endif // AVS_COMMONS_WITH_OPENSSL_PKCS11_ENGINE

VISIBILITY_PRIVATE_HEADER_END

#endif // CRYPTO_OPENSSL_GLOBAL_H
