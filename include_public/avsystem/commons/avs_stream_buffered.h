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

#ifndef AVS_COMMONS_STREAM_BUFFERED_H
#define AVS_COMMONS_STREAM_BUFFERED_H

#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates buffered stream wrapping some previously created underlying stream.
 * Newly created stream can be used to perform buffered reads and writes using
 * underlying stream's read and write functions.
 * If buffers sizes are non-zero, data will be written as chunks of
 * @p out_buffer_size size and read as chunks of @p in_buffer_size size.
 * After use the stream has to be deleted using avs_stream_cleanup(). An
 * underlying stream is deleted automatically.
 *
 * @param *inout_stream   Pointer to an underlying stream which implements at
 *                        least write or read operation. After successful
 *                        return, it will points to an address of newly created
 *                        buffered stream. If NULL, this function returns
 *                        negative value.
 * @param in_buffer_size  Size of input buffer. May be set to 0 if underlying
 *                        stream cannot perform reads or reads can be
 *                        non-buffered. The maximum allowed size is
 *                        SIZE_MAX / 2.
 * @param out_buffer_size Size of output buffer. May be set to 0 if underlying
 *                        stream cannot perform writes or writes can be
 *                        non-buffered. The maximum allowed size is
 *                        SIZE_MAX / 2.
 *
 * @return 0 on success, negative value in case of error. If it fails,
 *         @p inout_stream is not affected and underlying stream should be
 *         deleted manually.
 */
int avs_stream_buffered_create(avs_stream_t **inout_stream,
                               size_t in_buffer_size,
                               size_t out_buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_BUFFERED_H */
