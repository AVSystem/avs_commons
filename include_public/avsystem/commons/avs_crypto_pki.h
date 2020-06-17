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

#ifndef AVS_COMMONS_CRYPTO_PKI_H
#define AVS_COMMONS_CRYPTO_PKI_H

#include <stdint.h>

#include <avsystem/commons/avs_commons_config.h>
#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_prng.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This struct is for internal use only and should not be filled manually. One
 * should construct appropriate instances of:
 * - @ref avs_crypto_trusted_cert_info_t,
 * - @ref avs_crypto_client_cert_info_t,
 * - @ref avs_crypto_client_key_info_t
 * using methods declared below.
 */
typedef struct {
    int type;
    int source;
    union {
        struct {
            const char *filename;
            const char *password;
        } file;
        struct {
            const char *path;
        } path;
        struct {
            const void *buffer;
            const char *password;
            size_t buffer_size;
        } buffer;
    } info;
} avs_crypto_security_info_union_t;

typedef struct {
    avs_crypto_security_info_union_t desc;
} avs_crypto_trusted_cert_info_t;

/**
 * Creates CA chain descriptor used later on to load CA chain from file @p
 * filename.
 *
 * NOTE: File loading is conducted by using: fopen(), fread(), ftell() and
 * fclose(), thus the platform shall implement them. On embededd platforms it
 * may be preferable to use @ref avs_crypto_trusted_cert_info_from_buffer()
 * instead.
 *
 * @param filename  File from which the CA chain shall be loaded.
 */
avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_file(const char *filename);

/**
 * Creates CA chain descriptor used later on to load CA chain from specified @p
 * path. The loading procedure attempts to treat each file as CA certificate,
 * attempts to load, and fails only if no CA certificate could be loaded.
 *
 * NOTE: File loading and discovery is conducted by using: fopen(), fseek(),
 * fread(), ftell(), fclose(), opendir(), readdir(), closedir() and stat(), thus
 * the platform shall implement them. On embededd platforms it may be preferable
 * to use @ref avs_crypto_trusted_cert_info_from_buffer() instead.
 *
 * @param path  Path from which the CA chain shall be loaded.
 *
 * WARNING: accepted file formats are backend-specific.
 */
avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_path(const char *path);

/**
 * Creates CA chain descriptor used later on to load CA chain from memory
 * @p buffer.
 *
 * NOTE: Lifetime of the @p buffer must be as long as lifetime of any (D)TLS
 * sockets that used this descriptor to perform configuration.
 *
 * @param buffer        Buffer where loaded CA chain is stored.
 * @param buffer_size   Size in bytes of the buffer.
 */
avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_buffer(const void *buffer,
                                         size_t buffer_size);

typedef struct {
    avs_crypto_security_info_union_t desc;
} avs_crypto_client_key_info_t;

/**
 * Creates private key descriptor used later on to load private key from
 * file @p filename.
 *
 * @param filename  Name of the file to be loaded.
 * @param password  Optional password if present, or NULL.
 */
avs_crypto_client_key_info_t
avs_crypto_client_key_info_from_file(const char *filename,
                                     const char *password);

/**
 * Creates private key descriptor used later on to load private key from
 * @p buffer.
 *
 * @param buffer      Buffer in which private key is stored.
 * @param buffer_size Size of the buffer contents in bytes.
 * @param password    Optional password if present, or NULL.
 */
avs_crypto_client_key_info_t avs_crypto_client_key_info_from_buffer(
        const void *buffer, size_t buffer_size, const char *password);

typedef struct {
    avs_crypto_security_info_union_t desc;
} avs_crypto_client_cert_info_t;

/**
 * Creates client certificate descriptor used later on to load client
 * certificate from file @p filename.
 *
 * @param filename  Name of the file to be loaded.
 */
avs_crypto_client_cert_info_t
avs_crypto_client_cert_info_from_file(const char *filename);

/**
 * Creates client certificate descriptor used later on to load client
 * certificate from buffer @p buffer.
 *
 * @param buffer      Buffer in which certificate is stored.
 * @param buffer_size Size of the buffer contents in bytes.
 */
avs_crypto_client_cert_info_t
avs_crypto_client_cert_info_from_buffer(const void *buffer, size_t buffer_size);

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES
avs_error_t avs_crypto_pki_ec_gen(avs_crypto_prng_ctx_t *prng_ctx,
                                  const void *ecp_group_asn1_oid,
                                  void *out_der_secret_key,
                                  size_t *inout_der_secret_key_size,
                                  void *out_der_public_key,
                                  size_t *inout_der_public_key_size);
#endif // AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // AVS_COMMONS_CRYPTO_PKI_H
