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

#ifndef AVS_COMMONS_STREAM_STREAM_OUTBUF_H
#define AVS_COMMONS_STREAM_STREAM_OUTBUF_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_errno.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const void *const vtable;
    void *buffer;
    size_t buffer_size;
    size_t buffer_offset;
    char message_finished;
} avs_stream_outbuf_t;

extern const avs_stream_outbuf_t AVS_STREAM_OUTBUF_STATIC_INITIALIZER;

size_t avs_stream_outbuf_offset(avs_stream_outbuf_t *stream);

avs_error_t avs_stream_outbuf_set_offset(avs_stream_outbuf_t *stream,
                                         size_t offset);

void avs_stream_outbuf_set_buffer(avs_stream_outbuf_t *stream,
                                  void *buffer,
                                  size_t buffer_size);

#ifdef __cplusplus
}
#endif
#endif /* STREAM_STREAM_OUTBUF_H */
