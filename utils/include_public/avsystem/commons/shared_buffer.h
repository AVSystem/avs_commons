/*
 * Copyright 2018-2019 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_UTILS_SHARED_BUFFER_H
#define AVS_COMMONS_UTILS_SHARED_BUFFER_H

#include <string.h>

#include <avsystem/commons/defs.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/log.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A heap-allocated sized buffer object shared between multiple entities.
 *
 * Before using it, user is supposed to acquire exclusive ownership of the
 * buffer with @ref avs_shared_buffer_acquire , and return it with
 * @ref avs_shared_buffer_release after it is no longer needed.
 *
 * This allows for detecting cases where a shared buffer would be concurrently
 * used in two different places, resulting in data corruption.
 *
 * For efficiency, the usage check is only performed in debug builds.
 */
typedef struct {
#ifndef NDEBUG
    struct {
        const char *file;
        const char *func;
        unsigned line;
    } avs_shared_buffer_private_data;
#endif // NDEBUG
    const size_t capacity;
    const avs_max_align_t data[];
} avs_shared_buffer_t;

/**
 * Creates a new shared buffer allocated with avs_calloc.
 *
 * Returned pointer should later be deleted with avs_free.
 *
 * @param capacity Desired buffer capacity in bytes.
 */
static inline avs_shared_buffer_t *avs_shared_buffer_new(size_t capacity) {
    avs_shared_buffer_t *buf = (avs_shared_buffer_t *)
            avs_calloc(1, sizeof(avs_shared_buffer_t) + capacity);

    if (buf) {
        memcpy((void *) (intptr_t) &buf->capacity, &capacity, sizeof(capacity));
    }

    return buf;
}

#ifdef NDEBUG

/** See debug versions below */
static inline uint8_t *avs_shared_buffer_acquire(avs_shared_buffer_t *buf) {
    return (uint8_t *) (uintptr_t) buf->data;
}

static inline void avs_shared_buffer_release(avs_shared_buffer_t *buf) {
    (void) buf;
}

#else // NDEBUG

/**
 * Internal function. Use @ref avs_shared_buffer_acqiure instead.
 */
static inline uint8_t *
_avs_shared_buffer_acquire(avs_shared_buffer_t *buf,
                           const char *func,
                           const char *file,
                           unsigned line) {
    if (buf->avs_shared_buffer_private_data.file) {
        avs_log(shared_buffer, ERROR,
                "double use of a shared buffer in %s (%s:%u); last acquired "
                "in %s (%s:%u) and not released yet", func, file, line,
                buf->avs_shared_buffer_private_data.func,
                buf->avs_shared_buffer_private_data.file,
                buf->avs_shared_buffer_private_data.line);
        AVS_UNREACHABLE("double use of a shared buffer");
    }

    buf->avs_shared_buffer_private_data.func = func;
    buf->avs_shared_buffer_private_data.file = file;
    buf->avs_shared_buffer_private_data.line = line;
    return (uint8_t *) (uintptr_t) buf->data;
}

/**
 * Marks the shared buffer as used, and returns a mutable pointer to buffer
 * data. Implemented as a macro for extra debug information.
 */
#define avs_shared_buffer_acquire(Buf) \
    _avs_shared_buffer_acquire((Buf), __func__, __FILE__, __LINE__)

/**
 * Marks the shared buffer as free for reuse.
 */
static inline void avs_shared_buffer_release(avs_shared_buffer_t *buf) {
    buf->avs_shared_buffer_private_data.func = NULL;
    buf->avs_shared_buffer_private_data.file = NULL;
    buf->avs_shared_buffer_private_data.line = 0;
}
#endif // NDEBUG

#ifndef AVS_UNIT_TESTING
AVS_POISON(avs_shared_buffer_private_data)
#endif

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_UTILS_SHARED_BUFFER_H */
