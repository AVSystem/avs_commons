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

#include <avs_commons_posix_config.h>

#include <time.h>

#include <avsystem/commons/defs.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/unit/test.h>

#include "src/coap/coap_log.h"
#include "src/coap/msg_cache.h"
#include "utils.h"

/* minimum size of a valid avs_coap_msg_t */
#define MIN_MSG_OBJECT_SIZE \
    (offsetof(avs_coap_msg_t, content) + AVS_COAP_MSG_MIN_SIZE)

static const avs_coap_tx_params_t tx_params = {
    .ack_timeout = { 2, 0 },
    .ack_random_factor = 1.5,
    .max_retransmit = 4
};

static avs_coap_msg_t *
setup_msg_with_id(void *buffer, uint16_t msg_id, const char *payload) {
    avs_coap_msg_t *msg = (avs_coap_msg_t *) buffer;
    setup_msg(msg, (const uint8_t *) payload, strlen(payload));
    _avs_coap_header_set_id(msg, msg_id);
    return msg;
}

static avs_time_real_t MOCK_CLOCK = { { 0, 0 } };

static void clock_advance(avs_time_duration_t t) {
    AVS_UNIT_ASSERT_TRUE(avs_time_real_valid(MOCK_CLOCK));
    AVS_UNIT_ASSERT_TRUE(avs_time_duration_valid(t));
    MOCK_CLOCK = avs_time_real_add(MOCK_CLOCK, t);
}

/**
 * NOTE: This overrides the standard library's clock_gettime(). It's safe
 * though, because it affects a coap_test executable only.
 */
int clock_gettime(clockid_t clock, struct timespec *t) {
    (void) clock;
    t->tv_sec = (time_t) MOCK_CLOCK.since_real_epoch.seconds;
    t->tv_nsec = MOCK_CLOCK.since_real_epoch.nanoseconds;
    MOCK_CLOCK =
            avs_time_real_add(MOCK_CLOCK,
                              avs_time_duration_from_scalar(1, AVS_TIME_NS));
    return 0;
}

AVS_UNIT_TEST(coap_msg_cache, null) {
    static const uint16_t id = 123;
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id, "");

    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_create(0));
    AVS_UNIT_ASSERT_FAILED(
            _avs_coap_msg_cache_add(NULL, "host", "port", msg, &tx_params));
    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_get(NULL, "host", "port", id));

    // these should not crash
    _avs_coap_msg_cache_release(&(coap_msg_cache_t *) { NULL });
    _avs_coap_msg_cache_debug_print(NULL);
}

AVS_UNIT_TEST(coap_msg_cache, hit_single) {
    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(1024);

    static const uint16_t id = 123;
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id, "");

    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg, &tx_params));

    // request message existing in cache
    const avs_coap_msg_t *cached_msg =
            _avs_coap_msg_cache_get(cache, "host", "port", id);
    AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg, cached_msg, MIN_MSG_OBJECT_SIZE);

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, hit_multiple) {
    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(1024);

    static const uint16_t id = 123;
    avs_coap_msg_t *msg[] __attribute__((cleanup(free_msg_array))) = {
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), (uint16_t) (id + 0),
                          ""),
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), (uint16_t) (id + 1),
                          ""),
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), (uint16_t) (id + 2),
                          ""),
        NULL
    };

    for (size_t i = 0; i < AVS_ARRAY_SIZE(msg) - 1; ++i) {
        AVS_UNIT_ASSERT_SUCCESS(_avs_coap_msg_cache_add(cache, "host", "port",
                                                        msg[i], &tx_params));
    }

    // request message existing in cache
    for (uint16_t i = 0; i < AVS_ARRAY_SIZE(msg) - 1; ++i) {
        const avs_coap_msg_t *cached_msg =
                _avs_coap_msg_cache_get(cache, "host", "port",
                                        (uint16_t) (id + i));
        AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
        AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg[i], cached_msg,
                                          MIN_MSG_OBJECT_SIZE);
    }

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, hit_expired) {
    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(1024);

    static const uint16_t id = 123;
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id, "");

    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg, &tx_params));
    clock_advance(avs_time_duration_from_scalar(247, AVS_TIME_S));

    // request expired message existing in cache
    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_get(cache, "host", "port", id));

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, hit_after_expiration) {
    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(1024);

    static const uint16_t id1 = 123;
    static const uint16_t id2 = 321;

    avs_coap_msg_t *msg1 __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id1, "");
    avs_coap_msg_t *msg2 __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id2, "");

    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg1, &tx_params));
    clock_advance(avs_time_duration_from_scalar(60, AVS_TIME_S));
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg2, &tx_params));
    clock_advance(avs_time_duration_from_scalar(60, AVS_TIME_S));

    // request expired message existing in cache
    const avs_coap_msg_t *cached_msg =
            _avs_coap_msg_cache_get(cache, "host", "port", id2);
    AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg2, cached_msg, MIN_MSG_OBJECT_SIZE);

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, miss_empty) {
    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(1024);
    static const uint16_t id = 123;

    // request message from empty cache
    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_get(cache, "host", "port", id));

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, miss_non_empty) {
    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(1024);

    static const uint16_t id = 123;
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id, "");

    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg, &tx_params));

    // request message not in cache
    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_get(cache, "host", "port",
                                                 (uint16_t) (id + 1)));

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, add_existing) {
    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(1024);

    static const uint16_t id = 123;
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id, "");

    // replacing existing non-expired cached messages with updated ones
    // is not allowed
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg, &tx_params));
    AVS_UNIT_ASSERT_FAILED(
            _avs_coap_msg_cache_add(cache, "host", "port", msg, &tx_params));

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, add_existing_expired) {
    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(1024);

    static const uint16_t id = 123;
    avs_coap_msg_t *msg __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id, "");

    // replacing existing expired cached messages is not allowed
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg, &tx_params));
    clock_advance(avs_time_duration_from_scalar(247, AVS_TIME_S));
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg, &tx_params));

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, add_evict) {
    static const uint16_t id = 123;
    avs_coap_msg_t *msg[] __attribute__((cleanup(free_msg_array))) = {
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), (uint16_t) (id + 0),
                          ""),
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), (uint16_t) (id + 1),
                          ""),
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), (uint16_t) (id + 2),
                          ""),
        NULL
    };
    const avs_coap_msg_t *cached_msg;

    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(
            (_avs_coap_msg_cache_overhead(msg[0]) + MIN_MSG_OBJECT_SIZE) * 2);

    // message with another ID removes oldest existing entry if extra space
    // is required
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg[0], &tx_params));
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg[1], &tx_params));
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg[2], &tx_params));

    // oldest entry was removed
    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_get(cache, "host", "port", id));

    // newer entry still exists
    cached_msg =
            _avs_coap_msg_cache_get(cache, "host", "port", (uint16_t) (id + 1));
    AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg[1], cached_msg, MIN_MSG_OBJECT_SIZE);

    // newest entry was inserted
    cached_msg =
            _avs_coap_msg_cache_get(cache, "host", "port", (uint16_t) (id + 2));
    AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg[2], cached_msg, MIN_MSG_OBJECT_SIZE);

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, add_evict_multiple) {
    static const uint16_t id = 123;
    avs_coap_msg_t *msg[] __attribute((cleanup(free_msg_array))) = {
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), (uint16_t) (id + 0),
                          ""),
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), (uint16_t) (id + 1),
                          ""),
        setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE
                                     + sizeof("\xFF"
                                              "foobarbaz")
                                     - 1),
                          (uint16_t) (id + 2),
                          "\xFF"
                          "foobarbaz"),
        NULL
    };

    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(
            (_avs_coap_msg_cache_overhead(msg[0]) + MIN_MSG_OBJECT_SIZE) * 2);

    // message with another ID removes oldest existing entries if extra space
    // is required
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg[0], &tx_params));
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg[1], &tx_params));
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", msg[2], &tx_params));

    // oldest entries were removed
    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_get(cache, "host", "port", id));
    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_get(cache, "host", "port",
                                                 (uint16_t) (id + 1)));

    // newest entry was inserted
    const avs_coap_msg_t *cached_msg =
            _avs_coap_msg_cache_get(cache, "host", "port", (uint16_t) (id + 2));
    AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(msg[2], cached_msg,
                                      MIN_MSG_OBJECT_SIZE
                                              + sizeof("\xFF"
                                                       "foo")
                                              - 1);

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, add_too_big) {
    static const uint16_t id = 123;
    avs_coap_msg_t *m1 __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE),
                              (uint16_t) (id + 0), "");
    avs_coap_msg_t *m2 __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE
                                         + sizeof("\xFF"
                                                  "foobarbaz")
                                         - 1),
                              (uint16_t) (id + 1),
                              "\xFF"
                              "foobarbaz");

    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(
            _avs_coap_msg_cache_overhead(m1) + MIN_MSG_OBJECT_SIZE);

    // message too long to put into cache should be ignored
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "host", "port", m1, &tx_params));
    AVS_UNIT_ASSERT_FAILED(
            _avs_coap_msg_cache_add(cache, "host", "port", m2, &tx_params));

    // previously-added entry is still there
    const avs_coap_msg_t *cached_msg =
            _avs_coap_msg_cache_get(cache, "host", "port", id);
    AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(m1, cached_msg, MIN_MSG_OBJECT_SIZE);

    // "too big" entry was not inserted
    AVS_UNIT_ASSERT_NULL(_avs_coap_msg_cache_get(cache, "host", "port",
                                                 (uint16_t) (id + 1)));

    _avs_coap_msg_cache_release(&cache);
}

AVS_UNIT_TEST(coap_msg_cache, multiple_hosts_same_ids) {
    static const uint16_t id = 123;
    avs_coap_msg_t *m1 __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE), id, "");
    avs_coap_msg_t *m2 __attribute__((cleanup(free_msg))) =
            setup_msg_with_id(avs_malloc(MIN_MSG_OBJECT_SIZE
                                         + sizeof("\xFF"
                                                  "foobarbaz")
                                         - 1),
                              id,
                              "\xFF"
                              "foobarbaz");

    coap_msg_cache_t *cache = _avs_coap_msg_cache_create(4096);

    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "h1", "port", m1, &tx_params));
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_coap_msg_cache_add(cache, "h2", "port", m2, &tx_params));

    // both entries should be present despite having identical IDs
    const avs_coap_msg_t *cached_msg =
            _avs_coap_msg_cache_get(cache, "h1", "port", id);
    AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(m1, cached_msg, MIN_MSG_OBJECT_SIZE);

    cached_msg = _avs_coap_msg_cache_get(cache, "h2", "port", id);
    AVS_UNIT_ASSERT_NOT_NULL(cached_msg);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(m2, cached_msg,
                                      MIN_MSG_OBJECT_SIZE
                                              + sizeof("\xFF"
                                                       "foobarbaz")
                                              - 1);

    _avs_coap_msg_cache_release(&cache);
}
