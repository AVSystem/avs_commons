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

#ifndef MD5_COMMON_H
#define MD5_COMMON_H

#include <avsystem/commons/avs_stream.h>
#include <avsystem/commons/avs_stream_v_table.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

#define MD5_LENGTH 16

typedef struct {
    const avs_stream_v_table_t *const vtable;
    unsigned char result[MD5_LENGTH];
    size_t out_ptr;
} avs_stream_md5_common_t;

avs_error_t _avs_stream_md5_common_read(avs_stream_t *stream,
                                        size_t *out_bytes_read,
                                        bool *out_message_finished,
                                        void *buffer,
                                        size_t buffer_length);

char _avs_stream_md5_common_is_finalized(avs_stream_md5_common_t *stream);
void _avs_stream_md5_common_init(avs_stream_md5_common_t *stream,
                                 const avs_stream_v_table_t *const vtable);
void _avs_stream_md5_common_finalize(avs_stream_md5_common_t *stream);
void _avs_stream_md5_common_reset(avs_stream_md5_common_t *stream);

VISIBILITY_PRIVATE_HEADER_END

#endif /* MD5_COMMON_H */
