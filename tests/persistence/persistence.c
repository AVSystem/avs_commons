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

#include <avsystem/commons/avs_list.h>
#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_persistence.h>
#include <avsystem/commons/avs_stream.h>
#include <avsystem/commons/avs_stream_membuf.h>
#include <avsystem/commons/avs_unit_test.h>

#include <string.h>

static const char BUFFER[] = "No alarms and no surprises";

typedef struct {
    AVS_LIST(avs_persistence_context_t) contexts;
    avs_stream_t *stream;
} persistence_test_env_t;

typedef enum { CONTEXT_STORE = 0, CONTEXT_RESTORE } persistence_context_type_t;

typedef avs_persistence_context_t
persistence_context_constructor_t(avs_stream_t *);

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
    bool message_finished;
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_read((*env)->stream, &(size_t[]){ 0 }[0],
                                            &message_finished, NULL, 0));
    AVS_UNIT_ASSERT_TRUE(message_finished);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&(*env)->stream));
    avs_free(*env);
}

static avs_persistence_context_t *
persistence_create_context(persistence_test_env_t *env,
                           persistence_context_type_t type) {
    static persistence_context_constructor_t *constructors[] = {
        [CONTEXT_STORE] = avs_persistence_store_context_create,
        [CONTEXT_RESTORE] = avs_persistence_restore_context_create
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

AVS_UNIT_TEST(persistence, magic) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *restore_ctx =
            persistence_create_context(env, CONTEXT_RESTORE);

    char MAGIC[] = { 'M', '\0', 'A', '\0', 'G', '\0', 'I', '\0', 'C' };

    AVS_UNIT_ASSERT_SUCCESS(
            avs_persistence_magic(store_ctx, MAGIC, sizeof(MAGIC)));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_persistence_magic(restore_ctx, MAGIC, sizeof(MAGIC)));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_persistence_magic(store_ctx, MAGIC, sizeof(MAGIC)));
    MAGIC[1] = 'm';
    AVS_UNIT_ASSERT_FAILED(
            avs_persistence_magic(restore_ctx, MAGIC, sizeof(MAGIC)));
}

AVS_UNIT_TEST(persistence, version) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *restore_ctx =
            persistence_create_context(env, CONTEXT_RESTORE);

    static uint8_t SUPPORTED[] = { 0, 1, 3, 42 };

    uint8_t version = 0;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_version(
            store_ctx, &version, SUPPORTED, AVS_ARRAY_SIZE(SUPPORTED)));
    --version;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_version(
            restore_ctx, &version, SUPPORTED, AVS_ARRAY_SIZE(SUPPORTED)));
    AVS_UNIT_ASSERT_EQUAL(version, 0);

    version = 5;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_version(
            store_ctx, &version, SUPPORTED, AVS_ARRAY_SIZE(SUPPORTED)));
    --version;
    AVS_UNIT_ASSERT_FAILED(avs_persistence_version(
            restore_ctx, &version, SUPPORTED, AVS_ARRAY_SIZE(SUPPORTED)));

    version = 42;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_version(
            store_ctx, &version, SUPPORTED, AVS_ARRAY_SIZE(SUPPORTED)));
    --version;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_version(
            restore_ctx, &version, SUPPORTED, AVS_ARRAY_SIZE(SUPPORTED)));
    AVS_UNIT_ASSERT_EQUAL(version, 42);
}

static avs_error_t persistence_list_element_handler(
        avs_persistence_context_t *ctx, void *element, void *user_data) {
    AVS_UNIT_ASSERT_NULL(user_data);
    return avs_persistence_i32(ctx, (int32_t *) element);
}

static int
int32_comparator(const void *a_, const void *b_, size_t element_size) {
    (void) element_size;
    const int32_t *a = (const int32_t *) a_;
    const int32_t *b = (const int32_t *) b_;
    return *a - *b;
}

AVS_UNIT_TEST(persistence, list_store_restore) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *restore_ctx =
            persistence_create_context(env, CONTEXT_RESTORE);

    const int32_t integer_array[] = { 12, 34, 56 };
    AVS_LIST(int32_t) integer_list = NULL;
    for (size_t i = 0; i < AVS_ARRAY_SIZE(integer_array); i++) {
        int32_t *new_element = AVS_LIST_APPEND_NEW(int32_t, &integer_list);
        AVS_UNIT_ASSERT_NOT_NULL(new_element);
        *new_element = integer_array[i];
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_list(
            store_ctx, (AVS_LIST(void) *) &integer_list, sizeof(*integer_list),
            persistence_list_element_handler, NULL, NULL));

    AVS_LIST(int32_t) restored_integer_list = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_list(
            restore_ctx, (AVS_LIST(void) *) &restored_integer_list,
            sizeof(*restored_integer_list), persistence_list_element_handler,
            NULL, NULL));
    AVS_UNIT_ASSERT_EQUAL_LIST(integer_list, restored_integer_list,
                               sizeof(int32_t), int32_comparator);

    AVS_LIST_CLEAR(&integer_list);
    AVS_LIST_CLEAR(&restored_integer_list);
}

AVS_UNIT_TEST(persistence, restore_from_nonempty_list) {
    SCOPED_PERSISTENCE_TEST_ENV(env);

    avs_persistence_context_t *store_ctx =
            persistence_create_context(env, CONTEXT_STORE);
    avs_persistence_context_t *restore_ctx =
            persistence_create_context(env, CONTEXT_RESTORE);

    const int32_t integer_array[] = { 12, 34, 56 };
    AVS_LIST(int32_t) integer_list = NULL;
    for (size_t i = 0; i < AVS_ARRAY_SIZE(integer_array); i++) {
        int32_t *new_element = AVS_LIST_APPEND_NEW(int32_t, &integer_list);
        AVS_UNIT_ASSERT_NOT_NULL(new_element);
        *new_element = integer_array[i];
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_persistence_list(
            store_ctx, (AVS_LIST(void) *) &integer_list, sizeof(*integer_list),
            persistence_list_element_handler, NULL, NULL));

    // Try to restore to the same, non-empty list
    AVS_UNIT_ASSERT_FAILED(
            avs_persistence_list(restore_ctx, (AVS_LIST(void) *) &integer_list,
                                 sizeof(*integer_list),
                                 persistence_list_element_handler, NULL, NULL));

    // Restore again to the empty list
    AVS_LIST_CLEAR(&integer_list);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_persistence_list(restore_ctx, (AVS_LIST(void) *) &integer_list,
                                 sizeof(*integer_list),
                                 persistence_list_element_handler, NULL, NULL));

    AVS_LIST_CLEAR(&integer_list);
}
