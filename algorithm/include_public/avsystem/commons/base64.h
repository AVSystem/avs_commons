/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_ALGORITHM_BASE64_H
#define AVS_COMMONS_ALGORITHM_BASE64_H

#include <avsystem/commons/defs.h>

#include <stddef.h>
#include <stdint.h>


/**
 * @file base64.h
 *
 * Base64 encoder / decoder.
 */

/**
 * Returns amount of bytes required to store input encoded in base64.
 *
 * @param input_length Length of input in bytes.
 *
 * @returns length of base64 encoded input of length @p input_length.
 */
size_t avs_base64_encoded_size(size_t input_length);

/**
 * Returns amount of bytes that would be sufficient to store input encoded from
 * base64.
 *
 * Warning: this function computes just a rough estimate of amount of bytes that
 * are actually necessary by taking 3 * (input_length / 4) as a approximation.
 * Therefore the returned value is always an upper bound.
 *
 * @param input_length  Length of base64 encoded input.
 *
 * @returns estimate of the length of buffer required to store decoded input.
 */
size_t avs_base64_estimate_decoded_size(size_t input_length);

/**
 * Encodes specified input into base64.
 *
 * Note: this function fails if @p out_length is too small to encode @p input,
 * to predict buffer requirements use @ref avs_base64_encoded_size .
 *
 * @param out           Pointer to user-allocated array where encoded data will
 *                      be written.
 * @param out_length    Length of user-allocated array.
 * @param input         Input to encode.
 * @param input_length  Length of the input.
 *
 * @returns 0 on success, negative value in case of error.
 */
int avs_base64_encode(char *out,
                      size_t out_length,
                      const uint8_t *input,
                      size_t input_length);

/**
 * Decodes specified base64 input.
 *
 * Note:
 * 1. It does not accept inputs with whitespace characters of any kind.
 * 2. It does not accept inputs with with superflous padding characters.
 * 3. It does not accept inputs that are not padded properly.
 * 4. As a consequence it does not accepts inputs whose length is not a multiple
 *    of four.
 *
 * Moreover, this function fails if @p out_length is too small. To predict
 * buffer requirements use @ref avs_base64_estimate_decoded_size (which, for
 * inputs accepted by this function will return the exact amount of bytes
 * needed).
 *
 * @param out           Pointer to user-allocated array where decoded data
 *                      will be stored.
 * @param out_length    Length of user-allocated array.
 * @param input         Null terminated input to decode.
 *
 * @returns length of decoded data in bytes, negative value in case of error.
 */
ssize_t
avs_base64_decode_strict(uint8_t *out, size_t out_length, const char *input);

/**
 * Does the same as @ref avs_base64_decode_strict except that it ignores
 * superflous whitespaces and padding characters.
 *
 * Note that this function fails if @p out_length is too small. To predict
 * buffer requirements use @ref avs_base64_estimate_decoded_size .
 *
 * @param out           Pointer to user-allocated array where decoded data will be
 *                      stored.
 * @param out_length    Length of user-allocated array.
 * @param input         Null terminated input to decode.
 *
 * @returns length of decoded data in bytes, negative value in case of error.
 */
ssize_t avs_base64_decode(uint8_t *out, size_t out_length, const char *input);

#endif /* AVS_COMMONS_ALGORITHM_BASE64_H */
