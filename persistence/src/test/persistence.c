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

#include <avsystem/commons/list.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/persistence.h>
#include <avsystem/commons/stream.h>
#include <avsystem/commons/stream/stream_membuf.h>
#include <avsystem/commons/unit/test.h>

#include <string.h>

static const char BUFFER[] = "No alarms and no surprises";

typedef struct {
    AVS_LIST(avs_persistence_context_t) contexts;
    avs_stream_abstract_t *stream;
} persistence_test_env_t;

typedef enum {
    CONTEXT_STORE = 0,
    CONTEXT_RESTORE,
    CONTEXT_IGNORE
} persistence_context_type_t;

typedef avs_persistence_context_t
persistence_context_constructor_t(avs_stream_abstract_t *);

#define SCOPED_PERSISTENCE_TEST_ENV(Name)                      \
    __attribute__((__cleanup__(persistence_test_env_destroy))) \
            persistence_test_env_t *Name = persistence_test_env_create()

static persistence_test_env_t *persistence_test_env_create(void) {
    persistence_test_env_t *env =
            (persistence_test_env_t *) avs_calloc(1, sizeof(*env));
    AVS_UNIT_ASSERT_NOT_NULL(env);
    env->stream = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_NOT_NULL(env->stream);
    return env;
}

static void persistence_test_env_destroy(persistence_test_env_t **env) {
    AVS_LIST_CLEAR(&(*env)->contexts);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&(*env)->stream));
    avs_free(*env);
}

static avs_persistence_context_t *
persistence_create_context(persistence_test_env_t *env,
                           persistence_context_type_t type) {
    static persistence_context_constructor_t *constructors[] = {
        [CONTEXT_STORE] = avs_persistence_store_context_create,
        [CONTEXT_RESTORE] = avs_persistence_restore_context_create,
        [CONTEXT_IGNORE] = avs_persistence_ignore_context_create
    };

    avs_persistence_context_t *ctx =
            AVS_LIST_INSERT_NEW(avs_persistence_context_t, &env->contexts);
    *ctx = constructors[type](env->stream);
    return ctx;
}

AVS_UNIT_TEST(persistence, bytes_store_restore) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *restore_ctx =
            persistence_create_context(env, CONTEXT_RESTORE);

    uint32_t buffer_size = sizeof(BUFFER);
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(store_ctx, &buffer_size));
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_bytes(
            store_ctx, (uint8_t *) (intptr_t) BUFFER, buffer_size));

    uint8_t result[128];
    uint32_t result_size;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(restore_ctx, &result_size));
    AVS_UNIT_ASSERT_EQUAL(result_size, buffer_size);

    AVS_UNIT_ASSERT_SUCCESS(
            avs_persistence_bytes(restore_ctx, result, result_size));
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(result, BUFFER, buffer_size);
}

AVS_UNIT_TEST(persistence, bytes_restore_too_much) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *restore_ctx =
            persistence_create_context(env, CONTEXT_RESTORE);

    uint32_t buffer_size = sizeof(BUFFER);
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(store_ctx, &buffer_size));
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_bytes(
            store_ctx, (uint8_t *) (intptr_t) BUFFER, buffer_size));

    uint8_t result[128];
    uint32_t result_size;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(restore_ctx, &result_size));
    AVS_UNIT_ASSERT_EQUAL(result_size, buffer_size);

    AVS_UNIT_ASSERT_FAILED(
            avs_persistence_bytes(restore_ctx, result, result_size + 1));
}

AVS_UNIT_TEST(persistence, bytes_ignore) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *ignore_ctx =
            persistence_create_context(env, CONTEXT_IGNORE);

    uint32_t buffer_size = sizeof(BUFFER);
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(store_ctx, &buffer_size));
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_bytes(
            store_ctx, (uint8_t *) (intptr_t) BUFFER, buffer_size));

    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(ignore_ctx, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_persistence_bytes(ignore_ctx, NULL, buffer_size));
}

AVS_UNIT_TEST(persistence, bytes_ignore_multiphase) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *restore_ctx =
            persistence_create_context(env, CONTEXT_RESTORE);
    avs_persistence_context_t *ignore_ctx =
            persistence_create_context(env, CONTEXT_IGNORE);

    // Test that ignoring in chunks of 512 bytes actually works.
    uint8_t buffer[2 * PERSISTENCE_IGNORE_BYTES_BUFSIZE + 1];
    uint32_t buffer_size = sizeof(buffer);
    uint32_t magic = 0xF00BAA;
    memset(buffer, 0, buffer_size);

    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(store_ctx, &buffer_size));
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_bytes(
            store_ctx, (uint8_t *) (intptr_t) buffer, buffer_size));
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(store_ctx, &magic));

    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(ignore_ctx, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_persistence_bytes(ignore_ctx, NULL, buffer_size));
    uint32_t retrieved_value;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(restore_ctx, &retrieved_value));
    AVS_UNIT_ASSERT_EQUAL(magic, retrieved_value);
}

AVS_UNIT_TEST(persistence, bytes_ignore_too_much) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *ignore_ctx =
            persistence_create_context(env, CONTEXT_IGNORE);

    uint32_t buffer_size = sizeof(BUFFER);
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(store_ctx, &buffer_size));
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_bytes(
            store_ctx, (uint8_t *) (intptr_t) BUFFER, buffer_size));

    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_u32(ignore_ctx, NULL));
    AVS_UNIT_ASSERT_FAILED(
            avs_persistence_bytes(ignore_ctx, NULL, buffer_size + 1));
}
