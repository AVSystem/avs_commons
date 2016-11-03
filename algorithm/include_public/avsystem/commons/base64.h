/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_ALGORITHM_BASE64_H
#define AVS_COMMONS_ALGORITHM_BASE64_H

#include <avsystem/commons/defs.h>

#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

/**
 * @file base64.h
 *
 * Base64 encoder / decoder.
 */

/**
 * Encodes specified input into base64.
 *
 * Note: this function fails if @p out_length is too small to encode @p input .
 *
 * @param input         Input to encode.
 * @param input_length  Length of the input.
 * @param out           Pointer to user-allocated array where encoded data will
 *                      be written.
 * @param out_length    Length of user-allocated array.
 *
 * @returns 0 on success, negative value in case of error.
 */
int avs_base64_encode(const uint8_t *input,
                      size_t input_length,
                      char *out,
                      size_t out_length);

/**
 * Decodes specified input from base64.
 *
 * @param input     Null terminated input to decode.
 * @param out       Pointer to user-allocated array where decoded data will be
 *                  stored.
 * @param size      Length of user-allocated array.
 *
 * @returns length of decoded data in bytes, negative value in case of error.
 */
ssize_t avs_base64_decode(const char *input, uint8_t *out, size_t out_length);

#endif /* AVS_COMMONS_ALGORITHM_BASE64_H */

