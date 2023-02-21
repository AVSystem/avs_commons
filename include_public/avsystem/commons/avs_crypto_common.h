/*
 * Copyright 2023 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_CRYPTO_COMMON_H
#define AVS_COMMONS_CRYPTO_COMMON_H

#include <avsystem/commons/avs_commons_config.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) \
        || defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE)
typedef struct {
    const char *query;
} avs_crypto_security_info_union_internal_engine_t;
#endif /* defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) || \
          defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE) */

typedef struct {
    const char *filename;
    const char *password;
} avs_crypto_security_info_union_internal_file_t;

typedef struct {
    const char *path;
} avs_crypto_security_info_union_internal_path_t;

typedef struct {
    const void *buffer;
    const char *password;
    size_t buffer_size;
} avs_crypto_security_info_union_internal_buffer_t;

typedef struct avs_crypto_security_info_union_struct
        avs_crypto_security_info_union_t;

typedef struct {
    const avs_crypto_security_info_union_t *array_ptr;
    size_t element_count;
} avs_crypto_security_info_union_internal_array_t;

typedef struct {
    avs_crypto_security_info_union_t *list_head;
} avs_crypto_security_info_union_internal_list_t;

typedef enum {
    AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN,
    AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY,
    AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST,
    AVS_CRYPTO_SECURITY_INFO_PSK_IDENTITY,
    AVS_CRYPTO_SECURITY_INFO_PSK_KEY
} avs_crypto_security_info_tag_t;

typedef enum {
    AVS_CRYPTO_DATA_SOURCE_EMPTY,
    AVS_CRYPTO_DATA_SOURCE_FILE,
    AVS_CRYPTO_DATA_SOURCE_PATH,
    AVS_CRYPTO_DATA_SOURCE_BUFFER,
    AVS_CRYPTO_DATA_SOURCE_ARRAY,
    AVS_CRYPTO_DATA_SOURCE_LIST,
#if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) \
        || defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE)
    AVS_CRYPTO_DATA_SOURCE_ENGINE
#endif /* defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) || \
          defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE) */
} avs_crypto_data_source_t;

/**
 * This struct is for internal use only and should not be filled manually. One
 * should construct appropriate instances of:
 * - @ref avs_crypto_certificate_chain_info_t,
 * - @ref avs_crypto_private_key_info_t
 * - @ref avs_crypto_cert_revocation_list_info_t
 * - @ref avs_crypto_psk_identity_info_t
 * - @ref avs_crypto_psk_key_info_t
 * using methods declared in @c avs_crypto_pki.h and @c avs_crypto_psk.h.
 */
struct avs_crypto_security_info_union_struct {
    avs_crypto_security_info_tag_t type;
    avs_crypto_data_source_t source;
    union {
        avs_crypto_security_info_union_internal_file_t file;
        avs_crypto_security_info_union_internal_path_t path;
        avs_crypto_security_info_union_internal_buffer_t buffer;
        avs_crypto_security_info_union_internal_array_t array;
        avs_crypto_security_info_union_internal_list_t list;
#if defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) \
        || defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE)
        avs_crypto_security_info_union_internal_engine_t engine;
#endif /* defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI_ENGINE) || \
          defined(AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE) */
    } info;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // AVS_COMMONS_CRYPTO_COMMON_H
