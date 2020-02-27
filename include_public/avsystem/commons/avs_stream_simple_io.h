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

#ifndef AVS_COMMONS_STREAM_SIMPLE_IO_H
#define AVS_COMMONS_STREAM_SIMPLE_IO_H

#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Appends @p *inout_size or less bytes to an implementation-specific stream.
 *
 * @param context    Opaque pointer to an underlying context.
 * @param buffer     Buffer to consume (never NULL).
 * @param inout_size Pointer to a variable that on input contains the number of
 *                   bytes in buffer (never 0). After successful return, it
 *                   should contain the number of bytes actually written.
 *
 * @return Non-negative if write of some or all the passed data suceeded,
 *         negative value otherwise. Partial write is allowed only if it is
 *         impossible to write full buffer content to the destination.
 */
typedef int avs_simple_io_stream_writer_t(void *context,
                                          const void *buffer,
                                          size_t *inout_size);

/**
 * Consumes up to @p *inout_size bytes from an implementation-specific stream.
 * If the amount of bytes read is smaller than the @p *inout_size, then it MUST
 * mean there is nothing more to read - i.e. next call to this callback would
 * result in 0 bytes being read.
 *
 * @param context    Opaque pointer to an underlying context.
 * @param buffer     Buffer to write into (never NULL).
 * @param inout_size Pointer to a variable that on input contains size of the
 *                   buffer (never 0). After successful return, it should
 *                   contain the number of bytes actually read.
 *
 * @return Non-negative if some data have been successfully read, negative value
 *         otherwise.
 */
typedef int
avs_simple_io_stream_reader_t(void *context, void *buffer, size_t *inout_size);

/**
 * Creates simple output stream. After use the stream has to be deleted using
 * avs_stream_cleanup().
 *
 * @param writer  Function that will be called to perform write to the
 *                implementation-specific destination.
 * @param context Opaque pointer passed to writer implementation.
 *
 * @return Pointer to newly created stream or NULL in case of failure.
 */
avs_stream_t *
avs_stream_simple_output_create(avs_simple_io_stream_writer_t *writer,
                                void *context);

/**
 * Creates simple input stream. After use the stream has to be deleted using
 * avs_stream_cleanup().
 *
 * @param reader  Function that will be called to perform read from the
 *                implementation-specific source.
 * @param context Opaque pointer passed to reader implementation.
 *
 * @return Pointer to newly created stream or NULL in case of failure.
 */
avs_stream_t *
avs_stream_simple_input_create(avs_simple_io_stream_reader_t *reader,
                               void *context);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_SIMPLE_IO_H */
