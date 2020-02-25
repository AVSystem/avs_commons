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

#define AVS_UTILS_COMPAT_STDLIB_MEMORY_C
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_UTILS) \
        && defined(AVS_COMMONS_UTILS_WITH_STANDARD_ALLOCATOR)

#    include <avsystem/commons/avs_memory.h>

#    include <stdlib.h>

VISIBILITY_SOURCE_BEGIN

void *avs_malloc(size_t size) {
    return malloc(size);
}

void avs_free(void *ptr) {
    free(ptr);
}

void *avs_calloc(size_t nmemb, size_t size) {
    return calloc(nmemb, size);
}

void *avs_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

#endif // defined(AVS_COMMONS_WITH_AVS_UTILS) &&
       // defined(AVS_COMMONS_UTILS_WITH_STANDARD_ALLOCATOR)
