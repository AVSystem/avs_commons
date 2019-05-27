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

#define AVS_SHARED_BUFFER_IMPL

#include <avs_commons_config.h>

#include <avsystem/commons/shared_buffer.h>

#define MODULE_NAME shared_buffer
#include <x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#ifndef NDEBUG

uint8_t * _avs_shared_buffer_acquire(avs_shared_buffer_t *buf,
                                     const char *func,
                                     const char *file,
                                     unsigned line) {
    if (buf->avs_shared_buffer_private_data.file) {
        LOG(ERROR,
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

#endif
