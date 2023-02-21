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

#ifndef AVS_COMMONS_CRYPTO_PSK_H
#define AVS_COMMONS_CRYPTO_PSK_H

#include <stdint.h>

#include <avsystem/commons/avs_crypto_common.h>
#include <avsystem/commons/avs_errno.h>

#ifdef AVS_COMMONS_WITH_AVS_PERSISTENCE
#    include <avsystem/commons/avs_persistence.h>
#endif // AVS_COMMONS_WITH_AVS_PERSISTENCE

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    avs_crypto_security_info_union_t desc;
} avs_crypto_psk_identity_info_t;

AVS_STATIC_ASSERT(sizeof(avs_crypto_psk_identity_info_t)
                          == sizeof(avs_crypto_security_info_union_t),
                  psk_identity_info_equivalent_to_union);

/**
 * Creates pre-shared key identity descriptor used later on to set pre-shared
 * key identity from @p buffer.
 *
 * @param buffer      Buffer in which the identity is stored.
 * @param buffer_size Size of the buffer contents in bytes.
 */
avs_crypto_psk_identity_info_t
avs_crypto_psk_identity_info_from_buffer(const void *buffer,
                                         size_t buffer_size);

/**
 * Copies any valid pre-shared key identity info structure.
 *
 * Any resources used by the source (query strings and buffers) are copied as
 * well, so the original entries can be freed.
 *
 * The resulting identity info structure is allocated in such a way that a
 * single @ref avs_free call is sufficient to free the key and all associated
 * resources.
 *
 * @param out_ptr           Pointer to a variable that, on entry, shall be a
 *                          NULL pointer, and on exit will be set to a pointer
 *                          to the newly allocated structure.
 *
 * @param psk_identity_info Pre-shared key information to copy.
 *
 * @returns AVS_OK for success, avs_errno(AVS_ENOMEM) for an out-of-memory
 *          condition, or avs_errno(AVS_EINVAL) if invalid arguments have been
 *          passed or invalid data has been encountered.
 */
avs_error_t avs_crypto_psk_identity_info_copy(
        avs_crypto_psk_identity_info_t **out_ptr,
        avs_crypto_psk_identity_info_t psk_identity_info);

typedef struct {
    avs_crypto_security_info_union_t desc;
} avs_crypto_psk_key_info_t;

AVS_STATIC_ASSERT(sizeof(avs_crypto_psk_key_info_t)
                          == sizeof(avs_crypto_security_info_union_t),
                  psk_key_info_equivalent_to_union);

/**
 * Creates pre-shared key descriptor used later on to load pre-shared key from
 * @p buffer.
 *
 * @param buffer      Buffer in which the key is stored.
 * @param buffer_size Size of the buffer contents in bytes.
 */
avs_crypto_psk_key_info_t
avs_crypto_psk_key_info_from_buffer(const void *buffer, size_t buffer_size);

/**
 * Copies any valid pre-shared key info structure.
 *
 * Any resources used by the source (query strings and buffers) are copied as
 * well, so the original entries can be freed.
 *
 * The resulting key info structure is allocated in such a way that a single
 * @ref avs_free call is sufficient to free the key and all associated
 * resources.
 *
 * @param out_ptr      Pointer to a variable that, on entry, shall be a NULL
 *                     pointer, and on exit will be set to a pointer to the
 *                     newly allocated structure.
 *
 * @param psk_key_info Pre-shared key information to copy.
 *
 * @returns AVS_OK for success, avs_errno(AVS_ENOMEM) for an out-of-memory
 *          condition, or avs_errno(AVS_EINVAL) if invalid arguments have been
 *          passed or invalid data has been encountered.
 */
avs_error_t
avs_crypto_psk_key_info_copy(avs_crypto_psk_key_info_t **out_ptr,
                             avs_crypto_psk_key_info_t psk_key_info);

#ifdef AVS_COMMONS_WITH_AVS_PERSISTENCE
/**
 * Persists or restores a pre-shared key identity info object.
 *
 * NOTE: When restoring, the resulting object will be allocated in the same way
 * as when using @ref avs_crypto_psk_identity_info_copy.
 *
 * @param ctx              Persistence context to use.
 *
 * @param psk_identity_ptr Pointer to a variable containing the pointer to the
 *                         pre-shared key info object. If restoring,
 *                         <c>*psk_identity_ptr</c> MUST be NULL on entry.
 *
 * @returns AVS_OK for success, or an error value. If restoring,
 *          <c>*psk_key_ptr</c> is guaranteed to be NULL on exit.
 */
avs_error_t avs_crypto_psk_identity_info_persistence(
        avs_persistence_context_t *ctx,
        avs_crypto_psk_identity_info_t **psk_identity_ptr);

/**
 * Persists or restores a pre-shared key info object.
 *
 * NOTE: When restoring, the resulting object will be allocated in the same way
 * as when using @ref avs_crypto_psk_key_info_copy.
 *
 * @param ctx         Persistence context to use.
 *
 * @param psk_key_ptr Pointer to a variable containing the pointer to the
 *                    pre-shared key info object. If restoring,
 *                    <c>*psk_key_ptr</c> MUST be NULL on entry.
 *
 * @returns AVS_OK for success, or an error value. If restoring,
 *          <c>*psk_key_ptr</c> is guaranteed to be NULL on exit.
 */
avs_error_t
avs_crypto_psk_key_info_persistence(avs_persistence_context_t *ctx,
                                    avs_crypto_psk_key_info_t **psk_key_ptr);
#endif // AVS_COMMONS_WITH_AVS_PERSISTENCE

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE
/**
 * Creates pre-shared key descriptor used later on to load pre-shared key from
 * the engine.
 *
 * @param query  A query passed to the engine to get the key
 *
 * @returns A config needed to load the key from the engine.
 */
avs_crypto_psk_key_info_t
avs_crypto_psk_key_info_from_engine(const char *query);

/**
 * Stores a PSK key given as @ref avs_crypto_psk_key_info_t in a hardware
 * security engine.
 *
 * @param query    Engine-specific query string (e.g. a PKCS#11 URI) of the key.
 *
 * @param key_info Reference to a key to store.
 */
avs_error_t
avs_crypto_psk_engine_key_store(const char *query,
                                const avs_crypto_psk_key_info_t *key_info);

/**
 * Removes a PSK key from a hardware security engine.
 *
 * @param query Engine-specific query string (e.g. a PKCS#11 URI) of the key.
 */
avs_error_t avs_crypto_psk_engine_key_rm(const char *query);

/**
 * Creates pre-shared key identity descriptor used later on to load pre-shared
 * key identity from the engine.
 *
 * @param query  A query passed to the engine to get the identity
 *
 * @returns A config needed to load the identity from the engine.
 */
avs_crypto_psk_identity_info_t
avs_crypto_psk_identity_info_from_engine(const char *query);

/**
 * Stores a PSK identity given as @ref avs_crypto_psk_identity_info_t in a
 * hardware security engine.
 *
 * @param query    Engine-specific query string (e.g. a PKCS#11 URI) of the
 *                 identity.
 *
 * @param identity_info Reference to a identity to store.
 */
avs_error_t avs_crypto_psk_engine_identity_store(
        const char *query, const avs_crypto_psk_identity_info_t *identity_info);

/**
 * Removes a PSK identity from a hardware security engine.
 *
 * @param query Engine-specific query string (e.g. a PKCS#11 URI) of the
 * identity.
 */
avs_error_t avs_crypto_psk_engine_identity_rm(const char *query);
#endif // AVS_COMMONS_WITH_AVS_CRYPTO_PSK_ENGINE

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // AVS_COMMONS_CRYPTO_PSK_H
