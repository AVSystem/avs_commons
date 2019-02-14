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

#ifndef AVS_COAP_MSG_CACHE_H
#define AVS_COAP_MSG_CACHE_H

#include <stddef.h>
#include <stdint.h>

#include <avsystem/commons/coap/msg.h>
#include <avsystem/commons/coap/tx_params.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

typedef struct coap_msg_cache coap_msg_cache_t;

#define AVS_COAP_MSG_CACHE_DUPLICATE (-2)

#ifdef WITH_AVS_COAP_MESSAGE_CACHE

/**
 * Creates a message cache object.
 *
 * @param capacity Number of bytes the cache should be able to hold.
 *
 * @return Created msg_cache object, or NULL if there is not enough memory
 *         or @p capacity is 0.
 *
 * NOTE: NULL @ref coap_msg_cache_t objects is equivalent to a correct,
 * always-empty cache object.
 */
coap_msg_cache_t *_avs_coap_msg_cache_create(size_t capacity);

/**
 * Frees any resources used by given @p cache_ptr and sets <c>*cache_ptr</c>
 * to NULL.
 *
 * @param cache_ptr Pointer to the cache object to free. May be NULL, or point
 *                  to NULL, in which case a call to this function is a no-op.
 */
void _avs_coap_msg_cache_release(coap_msg_cache_t **cache_ptr);

/**
 * Adds a message to cache. Drops oldest cache entries if needed to fit
 * @p msg, even if they did not expire yet.
 *
 * Cached message expires after EXCHANGE_LIFETIME from being added to the cache.
 *
 * @param cache       Cache object to put message in.
 * @param remote_addr Message recipient address. Messages sent to one recipient
 *                    will not be considered valid for another one.
 * @param remote_port Message recipient port.
 * @param msg         Message to cache.
 * @param tx_params   Transmission params. Determine cached message lifetime.
 *
 * @return 0 on success, a negative value if:
 *         @li @p cache is NULL,
 *         @li there was not enough memory to allocate endpoint data,
 *         @li @p cache is too small to fit @p msg,
 *         @li @p cache already contains a message with the same remote endpoint
 *             and message ID (@ref AVS_COAP_MSG_CACHE_DUPLICATE).
 *
 * NOTE: this function intentionally fails if a message with the same remote
 * endpoint and message ID is already present. If there is a valid one in the
 * cache, we should have used it instead of preparing a new response, so that
 * indicates a bug hiding somewhere.
 */
int _avs_coap_msg_cache_add(coap_msg_cache_t *cache,
                            const char *remote_addr,
                            const char *remote_port,
                            const avs_coap_msg_t *msg,
                            const avs_coap_tx_params_t *tx_params);

/**
 * Looks up @p cache for a message with given @p msg_id and returns it if found.
 *
 * @param cache       Cache object to look into, or NULL.
 * @param remote_addr Message recipient address. Messages sent to one recipient
 *                    will not be considered valid for another one.
 * @param remote_port Message recipient port.
 * @param msg_id      CoAP message ID to look for.
 *
 * @return Found cached message, or NULL if it was not found
 *         or @p cache is NULL.
 */
const avs_coap_msg_t *_avs_coap_msg_cache_get(coap_msg_cache_t *cache,
                                              const char *remote_addr,
                                              const char *remote_port,
                                              uint16_t msg_id);

/**
 * Prints @p cache contents to log output.
 *
 * @p cache Cache object to print.
 */
void _avs_coap_msg_cache_debug_print(const coap_msg_cache_t *cache);

/**
 * @return Extra overhead, in bytes, required to put @p msg in cache. Total
 *         number of bytes used by a message is:
 *         <c>_avs_coap_msg_cache_overhead(msg)
 *         + msg->length + offsetof(avs_coap_msg_t, content)</c>
 */
size_t _avs_coap_msg_cache_overhead(const avs_coap_msg_t *msg);

#else // WITH_AVS_COAP_MESSAGE_CACHE

#define _avs_coap_msg_cache_create(...) \
    (LOG(ERROR, "message cache support disabled"), (coap_msg_cache_t *) NULL)
#define _avs_coap_msg_cache_release(...) (void)0
#define _avs_coap_msg_cache_add(...) (void)(-1)
#define _avs_coap_msg_cache_get(...) ((avs_coap_msg_t *) NULL)
#define _avs_coap_msg_cache_debug_print(...) (void)0
#define _avs_coap_msg_cache_overhead(...) 0

#endif // WITH_AVS_COAP_MESSAGE_CACHE

VISIBILITY_PRIVATE_HEADER_END

#endif // AVS_COAP_MSG_CACHE_H
