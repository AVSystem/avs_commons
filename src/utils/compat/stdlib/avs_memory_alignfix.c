/*
 * Copyright 2022 AVSystem <avsystem@avsystem.com>
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

#define AVS_UTILS_COMPAT_STDLIB_MEMORY_C
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_UTILS) \
        && defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR)

#    include <avsystem/commons/avs_memory.h>

#    include <assert.h>
#    include <stdlib.h>
#    include <string.h>

VISIBILITY_SOURCE_BEGIN

#    define MAX_PADDING AVS_ALIGNOF(avs_max_align_t)

static inline unsigned char calculate_necessary_padding(void *real_ptr) {
    return (unsigned char) (MAX_PADDING - ((uintptr_t) real_ptr) % MAX_PADDING);
}

static inline unsigned char get_padding(void *ptr) {
    if (!ptr) {
        return 0;
    }
    return ((unsigned char *) ptr)[-1];
}

static inline void *get_real_ptr(void *ptr) {
    return (unsigned char *) ptr - get_padding(ptr);
}

void *avs_malloc(size_t size) {
    if (!size || size > SIZE_MAX - MAX_PADDING) {
        return NULL;
    }
    unsigned char *real_ptr = (unsigned char *) malloc(size + MAX_PADDING);
    if (!real_ptr) {
        return NULL;
    }
    unsigned char padding = calculate_necessary_padding(real_ptr);
    assert(padding > 0);
    real_ptr[padding - 1] = padding;
    return &real_ptr[padding];
}

void avs_free(void *ptr) {
    free(get_real_ptr(ptr));
}

void *avs_calloc(size_t nmemb, size_t size) {
    if (!nmemb || !size) {
        return NULL;
    }
    size_t full_size = nmemb * size;
    if (full_size / size != nmemb || full_size / nmemb != size) {
        // overflow
        return NULL;
    }
    void *result = avs_malloc(full_size);
    if (result) {
        memset(result, 0, full_size);
    }
    return result;
}

void *avs_realloc(void *ptr, size_t size) {
    if (!size) {
        avs_free(ptr);
        return NULL;
    }
    if (size > SIZE_MAX - MAX_PADDING) {
        return NULL;
    }
    void *old_real_ptr = get_real_ptr(ptr);
    unsigned char old_padding = get_padding(ptr);
    unsigned char *new_real_ptr =
            (unsigned char *) realloc(old_real_ptr, size + MAX_PADDING);
    if (!new_real_ptr) {
        return NULL;
    }
    unsigned char new_padding = calculate_necessary_padding(new_real_ptr);
    assert(new_padding > 0);
    if (old_real_ptr && old_padding != new_padding) {
        memmove(new_real_ptr + new_padding, new_real_ptr + old_padding, size);
    }
    new_real_ptr[new_padding - 1] = new_padding;
    return &new_real_ptr[new_padding];
}

#endif // defined(AVS_COMMONS_WITH_AVS_UTILS) &&
       // defined(AVS_COMMONS_UTILS_WITH_ALIGNFIX_ALLOCATOR)
