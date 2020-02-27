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

#ifndef AVS_COMMONS_BUFFER_H
#define AVS_COMMONS_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file avs_buffer.h
 *
 * Implementation of a byte buffer with circular semantics.
 *
 * <example>
 * @code
 * #include <stdio.h>
 * #include <string.h>
 * #include <avsystem/commons/avs_buffer.h>
 *
 * int main() {
 *     avs_buffer_t *buffer;
 *     avs_buffer_create(&buffer, 1024);
 *
 *     // append immediate data
 *     avs_buffer_append_bytes(buffer, "Hello! ", 7);
 *
 *     // pass to library function
 *     const char *read_data =
 *             fgets(avs_buffer_raw_insert_ptr(buffer),
 *                   avs_buffer_space_left(buffer),
 *                   stdin);
 *     avs_buffer_advance_ptr(buffer, strlen(read_data));
 *
 *     while (avs_buffer_data_size(buffer) > 0) {
 *         size_t printed_bytes =
 *                 fwrite(avs_buffer_data(buffer), 1,
 *                        avs_buffer_data_size(buffer),
 *                        stdout);
 *         avs_buffer_consume_bytes(buffer, printed_bytes);
 *     }
 *
 *     avs_buffer_free(&buffer);
 * }
 * @endcode
 * </example>
 */

struct avs_buffer_struct;
typedef struct avs_buffer_struct avs_buffer_t;
/**<
 * Circular byte buffer object type.
 */

/**
 * Allocates a new buffer with a specified size (capacity).
 *
 * @param buffer Pointer to a variable which will be updated with the newly
 *               allocated buffer object.
 *
 * @param size   Desired capacity of the buffer, in bytes.
 *
 * @return 0 for success, or -1 in case of error.
 */
int avs_buffer_create(avs_buffer_t **buffer, size_t size);

/**
 * Destroys a buffer object, freeing any used resources.
 *
 * @param buffer Pointer to a variable containing a buffer to free. It will be
 *               reset to <c>NULL</c> afterwards.
 */
void avs_buffer_free(avs_buffer_t **buffer);

/**
 * Clears the buffer, making all its capacity available to data.
 *
 * @param buffer Buffer object to operate on.
 */
void avs_buffer_reset(avs_buffer_t *buffer);

/**
 * Returns the amount of data currently contained in the buffer.
 *
 * @param buffer Buffer object to operate on.
 *
 * @return Number of bytes ready to consume in the buffer.
 */
size_t avs_buffer_data_size(const avs_buffer_t *buffer);

/**
 * Returns the capacity of the buffer.
 *
 * @param buffer Buffer object to operate on.
 *
 * @return Total number of all bytes usable by the buffer.
 */
size_t avs_buffer_capacity(const avs_buffer_t *buffer);

/**
 * Returns the size of free space in the buffer.
 *
 * @param buffer Buffer object to operate on.
 *
 * @return Number of bytes that can currently be appended to the buffer.
 */
size_t avs_buffer_space_left(const avs_buffer_t *buffer);

/**
 * Returns a raw pointer to consumable data in the buffer.
 *
 * <strong>CAUTION:</strong> The pointer returned by this function may be
 * invalidated during calls to other functions, as <c>avs_buffer_t</c> may move
 * the data to ensure its integrity.
 *
 * List of functions that may invalidate the pointer returned from this
 * function:
 * - @ref avs_buffer_advance_ptr
 * - @ref avs_buffer_append_bytes
 * - @ref avs_buffer_fill_bytes
 * - @ref avs_buffer_raw_insert_ptr
 *
 * @param buffer Buffer object to operate on.
 *
 * @return Pointer to a contiguous array of @ref avs_buffer_data_size bytes of
 *         data that has been appended but not yet consumed.
 */
const char *avs_buffer_data(const avs_buffer_t *buffer);

/**
 * Return a raw pointer to free space in the buffer.
 *
 * This can be used to pass the buffer to external functions such as receiving
 * from a network socket.
 *
 * After filling the buffer, @ref avs_buffer_advance_ptr shall be called with
 * the number of bytes filled.
 *
 * <strong>CAUTION:</strong> This function is desgined for appending new data
 * to the buffer and shall be used <strong>only</strong> for that purpose. In
 * particular, calling it may invalidate any pointer previously returned by
 * @ref avs_buffer_data or previous call to @ref avs_buffer_raw_insert_ptr.
 *
 * @param buffer Buffer object to operate on.
 *
 * @return Pointer to a contiguous array of @ref avs_buffer_space_left bytes
 *         (which may already contain some bogus data) that can be filled with
 *         new input data.
 */
char *avs_buffer_raw_insert_ptr(avs_buffer_t *buffer);

/**
 * Marks some amount of data as consumed, freeing portion of the available
 * capacity.
 *
 * @param buffer      Buffer object to operate on.
 *
 * @param bytes_count Number of bytes to mark as consumed.
 *
 * @return 0 for success, or -1 in case of error (not enough data in buffer).
 */
int avs_buffer_consume_bytes(avs_buffer_t *buffer, size_t bytes_count);

/**
 * Appends bytes to the end of the buffer, making them (eventually) available
 * for consumption.
 *
 * Provided that the arguments are valid, it is semantically equivalent to:
 *
 * @code
 * memcpy(avs_buffer_raw_insert_ptr(buffer), data, data_length);
 * avs_buffer_advance_ptr(buffer, data_length);
 * @endcode
 *
 * However, in many cases this function will execute faster than the above
 * block, so it is preferable to use it whenever possible.
 *
 * @param buffer      Buffer object to operate on.
 *
 * @param data        Pointer to data to append.
 *
 * @param data_length Number of bytes to append.
 *
 * @return 0 for success, or -1 in case of error (not enough free space in
 *         buffer).
 */
int avs_buffer_append_bytes(avs_buffer_t *buffer,
                            const void *data,
                            size_t data_length);

/**
 * Marks some amount of data as appended.
 *
 * This function is complementary to @ref avs_buffer_raw_insert_ptr, both
 * functions together can be used to replicate functionality of
 * @ref avs_buffer_append_bytes in cases where raw pointer to input data cannot
 * be obtained.
 *
 * @param buffer Buffer object to operate on.
 *
 * @param count  Number of bytes to mark as appended.
 *
 * @return 0 for success, or -1 in case of error (not enough free space in
 *         buffer).
 */
int avs_buffer_advance_ptr(avs_buffer_t *buffer, size_t count);

/**
 * Appends a number of bytes with a specified value to the buffer.
 *
 * Provided that the arguments are valid, it is semantically equivalent to:
 *
 * @code
 * memset(avs_buffer_raw_insert_ptr(buffer), value, bytes_count);
 * avs_buffer_advance_ptr(buffer, bytes_count);
 * @endcode
 *
 * However, in many cases this function will execute faster than the above
 * block, so it is preferable to use it whenever possible.
 *
 * @param buffer      Buffer object to operate on.
 *
 * @param value       <c>unsigned char</c> value of constant byte to fill the
 *                    data, cast to <c>int</c>. This usage is analogous to the
 *                    interface used by <c>memset()</c>.
 *
 * @param bytes_count Number of bytes to append.
 *
 * @return 0 for success, or -1 in case of error (not enough free space in
 *         buffer).
 */
int avs_buffer_fill_bytes(avs_buffer_t *buffer, int value, size_t bytes_count);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_BUFFER_H */
