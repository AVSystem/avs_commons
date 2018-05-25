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

#include <avs_commons_config.h>

#include <avsystem/commons/buffer.h>
#include <avsystem/commons/defs.h>
#include <avsystem/commons/list.h>
#include <avsystem/commons/time.h>
#include <avsystem/commons/utils.h>

#include <avsystem/commons/coap/msg.h>

#include "coap_log.h"
#include "msg_cache.h"

#include <assert.h>
#include <inttypes.h>

VISIBILITY_SOURCE_BEGIN

typedef struct endpoint {
    uint16_t refcount;
    char addr[AVS_ADDRSTRLEN];
    char port[sizeof("65535")];
} endpoint_t;

struct coap_msg_cache {
    AVS_LIST(endpoint_t) endpoints; // sorted by id

    // priority queue of cache_entry_t, sorted by expiration_time
    avs_buffer_t *buffer;
};

typedef struct cache_entry {
    endpoint_t *endpoint;
    avs_time_monotonic_t expiration_time;
    const char data[1]; // actually a FAM: avs_coap_msg_t + padding
} cache_entry_t;

/* Ensure that if cache_entry_t is properly aligned, one can safely cast
 * entry.data to avs_coap_msg_t* */
AVS_STATIC_ASSERT(AVS_ALIGNOF(cache_entry_t)
                      % AVS_ALIGNOF(avs_coap_msg_t) == 0,
                  cache_entry_alignment_not_a_multiple_of_msg_alignment);
AVS_STATIC_ASSERT(offsetof(cache_entry_t, data)
                      % AVS_ALIGNOF(avs_coap_msg_t) == 0,
                  invalid_msg_alignment_in_cache_entry_t);

coap_msg_cache_t *_avs_coap_msg_cache_create(size_t capacity) {
    if (capacity == 0) {
        return NULL;
    }

    coap_msg_cache_t *cache = (coap_msg_cache_t *)
            calloc(1, sizeof(coap_msg_cache_t));
    if (!cache) {
        return NULL;
    }

    if (avs_buffer_create(&cache->buffer, capacity)) {
        free(cache);
        return NULL;
    }

    assert((size_t)(uintptr_t)avs_buffer_raw_insert_ptr(cache->buffer)
           % AVS_ALIGNOF(cache_entry_t) == 0);
    return cache;
}

void _avs_coap_msg_cache_release(coap_msg_cache_t **cache_ptr) {
    if (cache_ptr && *cache_ptr) {
        avs_buffer_free(&(*cache_ptr)->buffer);
        AVS_LIST_CLEAR(&(*cache_ptr)->endpoints);
        free(*cache_ptr);
        *cache_ptr = NULL;
    }
}

static endpoint_t *cache_endpoint_add_ref(coap_msg_cache_t *cache,
                                          const char *remote_addr,
                                          const char *remote_port) {
    assert(remote_addr);
    assert(remote_port);

    AVS_LIST(endpoint_t) *ep_ptr;
    AVS_LIST_FOREACH_PTR(ep_ptr, &cache->endpoints) {
        if (!strcmp(remote_addr, (*ep_ptr)->addr)
                && !strcmp(remote_port, (*ep_ptr)->port)) {
            ++(*ep_ptr)->refcount;
            return *ep_ptr;
        }
    }

    AVS_LIST(endpoint_t) new_ep = AVS_LIST_NEW_ELEMENT(endpoint_t);
    if (!new_ep) {
        LOG(DEBUG, "out of memory");
        return NULL;
    }

    if (avs_simple_snprintf(new_ep->addr, sizeof(new_ep->addr), "%s",
                            remote_addr) < 0
            || avs_simple_snprintf(new_ep->port, sizeof(new_ep->port), "%s",
                                   remote_port) < 0) {
        LOG(WARNING, "endpoint address or port too long: addr = %s, "
                     "port = %s",
            remote_addr, remote_port);
        AVS_LIST_DELETE(&new_ep);
        return NULL;
    }

    new_ep->refcount = 1;
    AVS_LIST_INSERT(&cache->endpoints, new_ep);

    LOG(TRACE, "added cache endpoint: %s:%s", new_ep->addr, new_ep->port);
    return new_ep;
}

static void cache_endpoint_del_ref(coap_msg_cache_t *cache,
                                   endpoint_t *endpoint) {
    if (--endpoint->refcount == 0) {
        AVS_LIST(endpoint_t) *ep_ptr = (AVS_LIST(endpoint_t) *)
                AVS_LIST_FIND_PTR(&cache->endpoints, endpoint);
        LOG(TRACE, "removed cache endpoint: %s:%s", (*ep_ptr)->addr,
            (*ep_ptr)->port);
        AVS_LIST_DELETE(ep_ptr);
    }
}

static size_t padding_bytes_after_msg(const avs_coap_msg_t *msg) {
    static const size_t entry_alignment = AVS_ALIGNOF(cache_entry_t);
    const size_t entry_length = offsetof(cache_entry_t, data)
            + offsetof(avs_coap_msg_t, content) + msg->length;
    if (entry_length % entry_alignment) {
        return entry_alignment - entry_length % entry_alignment;
    } else {
        return 0;
    }
}

/**
 * @return Extra overhead, in bytes, required to put @p msg in cache. Total
 *         number of bytes used by a message is:
 *         <c>_avs_coap_msg_cache_overhead(msg)
 *         + msg->length + offsetof(avs_coap_msg_t, content)</c>
 */
static inline size_t cache_msg_overhead(const avs_coap_msg_t *msg) {
    return offsetof(cache_entry_t, data) + padding_bytes_after_msg(msg);
}

static void cache_put_entry(coap_msg_cache_t *cache,
                            const avs_time_monotonic_t *expiration_time,
                            endpoint_t *endpoint,
                            const avs_coap_msg_t *msg) {
    size_t msg_size = offsetof(avs_coap_msg_t, content) + msg->length;

    cache_entry_t entry = {
        .endpoint = endpoint,
        .expiration_time = *expiration_time
    };

    assert(avs_buffer_data_size(cache->buffer) % AVS_ALIGNOF(cache_entry_t)
            == 0);
    int res;
    res = avs_buffer_append_bytes(cache->buffer, &entry,
                                  offsetof(cache_entry_t, data));
    assert(!res);
    res = avs_buffer_append_bytes(cache->buffer, msg, msg_size);
    assert(!res);
    res = avs_buffer_fill_bytes(cache->buffer, '\xDD',
                                padding_bytes_after_msg(msg));
    assert(!res);
    assert(avs_buffer_data_size(cache->buffer) % AVS_ALIGNOF(cache_entry_t)
            == 0);
    (void) res;
}

static const cache_entry_t *entry_first(const coap_msg_cache_t *cache) {
    const cache_entry_t *result =
            (const cache_entry_t *) avs_buffer_data(cache->buffer);
    assert((size_t)(uintptr_t) result % AVS_ALIGNOF(cache_entry_t) == 0);
    return result;
}

static bool entry_valid(const coap_msg_cache_t *cache,
                        const cache_entry_t *entry) {
    assert((const char*) entry >= avs_buffer_data(cache->buffer));
    size_t entry_offset =
            (size_t) ((const char *) entry - avs_buffer_data(cache->buffer));
    assert(entry_offset % AVS_ALIGNOF(cache_entry_t) == 0);
    // NOTE: NEVER use avs_buffer_raw_insert_ptr() during iteration,
    // as it may defragment the buffer and cause UB
    return entry_offset < avs_buffer_data_size(cache->buffer);
}

static const avs_coap_msg_t *entry_msg(const cache_entry_t *entry) {
    return (const avs_coap_msg_t *) entry->data;
}

static bool entry_expired(const cache_entry_t *entry,
                          const avs_time_monotonic_t *now) {
    return avs_time_monotonic_before(entry->expiration_time, *now);
}

/* returns total size of avs_coap_msg_t, including length field
 * and padding after the message */
static size_t entry_msg_size(const cache_entry_t *entry) {
    const avs_coap_msg_t *msg = entry_msg(entry);
    return offsetof(avs_coap_msg_t, content)
            + msg->length
            + padding_bytes_after_msg(msg);
}

/* returns total size of cache entry, including header, message, and
 * and padding */
static size_t entry_size(const cache_entry_t *entry) {
    size_t result = offsetof(cache_entry_t, data) + entry_msg_size(entry);
    assert(result % AVS_ALIGNOF(cache_entry_t) == 0);
    return result;
}

static uint16_t entry_id(const cache_entry_t *entry) {
    return avs_coap_msg_get_id(entry_msg(entry));
}

static const cache_entry_t *entry_next(const cache_entry_t *entry) {
    const cache_entry_t *result = (const cache_entry_t *)
            ((const char*)entry + entry_size(entry));
    assert((size_t)(uintptr_t) result % AVS_ALIGNOF(cache_entry_t) == 0);
    return result;
}

static void cache_free_bytes(coap_msg_cache_t *cache,
                             size_t bytes_required) {
    assert(bytes_required <= avs_buffer_capacity(cache->buffer));

    size_t bytes_free = avs_buffer_space_left(cache->buffer);

    const cache_entry_t *entry;
    for (entry = entry_first(cache);
            bytes_free < bytes_required;
            entry = entry_next(entry)) {
        assert(entry_valid(cache, entry));

        LOG(TRACE, "msg_cache: dropping msg (id = %u) to make room for"
                   " a new one (size = %lu)",
            entry_id(entry), (unsigned long) bytes_required);
        cache_endpoint_del_ref(cache, entry->endpoint);
        bytes_free += entry_size(entry);
    }

    size_t expired_bytes = (uintptr_t)entry - (uintptr_t)entry_first(cache);
    int res = avs_buffer_consume_bytes(cache->buffer, expired_bytes);
    assert(!res);
    (void) res;
}

static void cache_drop_expired(coap_msg_cache_t *cache,
                               const avs_time_monotonic_t *now) {
    const cache_entry_t *entry;
    for (entry = entry_first(cache);
            entry_valid(cache, entry);
            entry = entry_next(entry)) {
        if (entry_expired(entry, now)) {
            LOG(TRACE, "msg_cache: dropping expired msg (id = %u)",
                entry_id(entry));
            cache_endpoint_del_ref(cache, entry->endpoint);
        } else {
            break;
        }
    }

    size_t expired_bytes = (uintptr_t)entry - (uintptr_t)entry_first(cache);
    int res = avs_buffer_consume_bytes(cache->buffer, expired_bytes);
    assert(!res);
    (void) res;
}

static const cache_entry_t *find_entry(const coap_msg_cache_t *cache,
                                       const char *remote_addr,
                                       const char *remote_port,
                                       uint16_t msg_id) {
    for (const cache_entry_t *entry = entry_first(cache);
            entry_valid(cache, entry);
            entry = entry_next(entry)) {
        if (entry_id(entry) == msg_id
                && !strcmp(entry->endpoint->addr, remote_addr)
                && !strcmp(entry->endpoint->port, remote_port)) {
            return entry;
        }
    }

    return NULL;
}

int _avs_coap_msg_cache_add(coap_msg_cache_t *cache,
                            const char *remote_addr,
                            const char *remote_port,
                            const avs_coap_msg_t *msg,
                            const avs_coap_tx_params_t *tx_params) {
    if (!cache) {
        return -1;
    }

    size_t cap_req = cache_msg_overhead(msg)
                   + offsetof(avs_coap_msg_t, content)
                   + msg->length;
    if (avs_buffer_capacity(cache->buffer) < cap_req) {
        LOG(DEBUG, "msg_cache: not enough space for %" PRIu32 " B message",
            msg->length);
        return -1;
    }

    avs_time_monotonic_t now = avs_time_monotonic_now();
    cache_drop_expired(cache, &now);

    uint16_t msg_id = avs_coap_msg_get_id(msg);
    if (find_entry(cache, remote_addr, remote_port, msg_id)) {
        LOG(DEBUG, "msg_cache: message ID %u already in cache", msg_id);
        return AVS_COAP_MSG_CACHE_DUPLICATE;
    }

    endpoint_t *ep = cache_endpoint_add_ref(cache, remote_addr, remote_port);
    if (!ep) {
        return -1;
    }

    cache_free_bytes(cache, cap_req);

    const avs_time_duration_t exchange_lifetime =
            avs_coap_exchange_lifetime(tx_params);
    avs_time_monotonic_t expiration_time =
            avs_time_monotonic_add(now, exchange_lifetime);

    cache_put_entry(cache, &expiration_time, ep, msg);
    return 0;
}

const avs_coap_msg_t *_avs_coap_msg_cache_get(coap_msg_cache_t *cache,
                                              const char *remote_addr,
                                              const char *remote_port,
                                              uint16_t msg_id) {
    if (!cache) {
        return NULL;
    }

    avs_time_monotonic_t now = avs_time_monotonic_now();
    cache_drop_expired(cache, &now);

    const cache_entry_t *entry = find_entry(cache, remote_addr, remote_port,
                                            msg_id);
    if (!entry) {
        return NULL;
    }

    assert(!entry_expired(entry, &now));

    LOG(TRACE, "msg_cache hit (id = %u)", msg_id);
    return entry_msg(entry);
}

void _avs_coap_msg_cache_debug_print(const coap_msg_cache_t *cache) {
    if (!cache) {
        LOG(DEBUG, "msg_cache: NULL");
        return;
    }

    LOG(DEBUG, "msg_cache: %lu/%lu bytes used",
        (unsigned long) avs_buffer_data_size(cache->buffer),
        (unsigned long) avs_buffer_capacity(cache->buffer));

    AVS_LIST(endpoint_t) ep;
    AVS_LIST_FOREACH(ep, cache->endpoints) {
        LOG(DEBUG, "endpoint: refcount %u, addr %s, port %s", ep->refcount,
            ep->addr, ep->port);
    }

    for (const cache_entry_t *entry = entry_first(cache);
            entry_valid(cache, entry);
            entry = entry_next(entry)) {
        LOG(DEBUG, "entry: %p, msg padding: %lu", (const void *) entry,
            (unsigned long) padding_bytes_after_msg(entry_msg(entry)));
        LOG(DEBUG, "endpoint: %s:%s", entry->endpoint->addr,
            entry->endpoint->port);
        LOG(DEBUG, "expiration time: %" PRId64 ":%09" PRId32,
            entry->expiration_time.since_monotonic_epoch.seconds,
            entry->expiration_time.since_monotonic_epoch.nanoseconds);
        avs_coap_msg_debug_print(entry_msg(entry));
    }
}

#ifdef AVS_UNIT_TESTING
#include "test/msg_cache.c"
#endif // AVS_UNIT_TESTING
