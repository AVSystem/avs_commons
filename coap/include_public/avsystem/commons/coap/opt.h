/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_COAP_OPT_H
#define AVS_COMMONS_COAP_OPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @{
 * CoAP option numbers, as defined in RFC7252/RFC7641/RFC7959.
 */
#define AVS_COAP_OPT_IF_MATCH 1
#define AVS_COAP_OPT_URI_HOST 3
#define AVS_COAP_OPT_ETAG 4
#define AVS_COAP_OPT_IF_NONE_MATCH 5
#define AVS_COAP_OPT_OBSERVE 6
#define AVS_COAP_OPT_URI_PORT 7
#define AVS_COAP_OPT_LOCATION_PATH 8
#define AVS_COAP_OPT_URI_PATH 11
#define AVS_COAP_OPT_CONTENT_FORMAT 12
#define AVS_COAP_OPT_MAX_AGE 14
#define AVS_COAP_OPT_URI_QUERY 15
#define AVS_COAP_OPT_ACCEPT 17
#define AVS_COAP_OPT_LOCATION_QUERY 20
#define AVS_COAP_OPT_BLOCK2 23
#define AVS_COAP_OPT_BLOCK1 27
#define AVS_COAP_OPT_PROXY_URI 35
#define AVS_COAP_OPT_PROXY_SCHEME 39
#define AVS_COAP_OPT_SIZE1 60
/** @} */

/**
 * Maximum size, in bytes, required for encoding a BLOCK1/BLOCK2 option.
 *
 * Technically, CoAP options may contain up to 2 bytes of extended option number
 * and up to 2 bytes of extended length. This should never be required for BLOCK
 * options. Why? 2-byte extended values are required for interpreting values
 * >= 269. BLOCK uses 23/27 option numbers and allows up to 3 content bytes.
 * Therefore correct BLOCK options will use at most 1 byte for extended number
 * (since wrapping is not allowed) and will never use extended length field.
 */
#define AVS_COAP_OPT_BLOCK_MAX_SIZE \
    (1    /* option header   */     \
     + 1  /* extended number */     \
     + 3) /* block option value */

/**
 * Maximum size, in bytes, required for encoding an option with 64-bit
 * integer value.
 */
#define AVS_COAP_OPT_INT_MAX_SIZE \
    (1   /* option header */      \
     + 2 /* extended number */    \
     + 2 /* extended length */    \
     + sizeof(uint64_t))

/**
 * Maximum size, in bytes, required for encoding an ETag option.
 *
 * ETag option has number 4, which means it will never use "extended number"
 * format. Since the maximum allowed option size is 8, it won't ever use the
 * "extended length" either.
 */
#define AVS_COAP_OPT_ETAG_MAX_SIZE \
    (1    /* option header */      \
     + 8) /* max ETag length */

/** Serialized CoAP option. */
typedef struct avs_coap_opt {
    /**
     * Note: when working with CoAP options do not access these fields directly,
     * since they may not represent the actual encoded values. Use
     * @ref avs_coap_opt_value, @ref avs_coap_opt_delta and
     * @ref avs_coap_opt_content_length instead.
     */
    uint8_t delta_length;
    uint8_t content[];
} avs_coap_opt_t;

/**
 * @param opt Option to operate on.
 *
 * @returns Pointer to the start of the option content.
 */
const uint8_t *avs_coap_opt_value(const avs_coap_opt_t *opt);

/**
 * Low-level API for accessing an integer option value.
 *
 * @param[in]  opt            CoAP option to retrieve value from.
 * @param[out] out_value      Buffer to store the option value in. Retrieved
 *                            value is always in host byte order.
 * @param[in]  out_value_size Number of bytes available in @p out_value .
 *
 * @returns 0 on success, a negative value if @p out_value is too small
 *          to hold the integer value of @p opt .
 */
int avs_coap_opt_uint_value(const avs_coap_opt_t *opt,
                            void *out_value,
                            size_t out_value_size);

/**
 * Convenience function for retrieving the value of an option as a 32-bit
 * unsigned integer.
 *
 * @returns See @ref avs_coap_opt_uint_value .
 */
static inline int avs_coap_opt_u32_value(const avs_coap_opt_t *opt,
                                         uint32_t *out_value) {
    return avs_coap_opt_uint_value(opt, out_value, sizeof(*out_value));
}

/**
 * Retrieves an CoAP option value as a zero-terminated string.
 *
 * @param[in]  opt            Option to retrieve value from.
 * @param[out] out_bytes_read Number of bytes successfully written to
 *                            @p buffer, including terminating nullbyte.
 * @param[out] buffer         Buffer to store the retrieved value in.
 * @param[in]  buffer_size    Number of bytes available in @p buffer .
 *
 * @returns @li 0 on success, in which case @p out_bytes_read contains
 *              the number of bytes successfully written to @p buffer .
 *              String written to @p buffer is guaranteed to be zero-terminated.
 *          @li A negative value if @p buffer is too small to hold the option
 *              value. In such case, @p buffer contents are not modified and
 *              @p out_bytes_read is not set.
 */
int avs_coap_opt_string_value(const avs_coap_opt_t *opt,
                              size_t *out_bytes_read,
                              char *buffer,
                              size_t buffer_size);

/**
 * Retrieves a BLOCK sequence number from a CoAP option.
 *
 * Note: the function does not check whether @p opt is indeed a BLOCK option.
 * Calling this function on non-BLOCK options causes undefined behavior.
 *
 * @param[in]  opt         CoAP option to read sequence number from.
 * @param[out] out_seq_num Read BLOCK sequence number.
 *
 * @returns @li 0 on success, in which case @p out_seq_num is set,
 *          @li -1 if the option value is too big to be a correct BLOCK option.
 */
int avs_coap_opt_block_seq_number(const avs_coap_opt_t *opt,
                                  uint32_t *out_seq_num);

/**
 * Retrieves a "More" marker from a CoAP BLOCK option.
 *
 * Note: the function does not check whether @p opt is indeed a BLOCK option.
 * Calling this function on non-BLOCK options causes undefined behavior.
 *
 * @param[in]  opt          CoAP option to read sequence number from.
 * @param[out] out_has_more Value of the "More" flag of a BLOCK option.
 *
 * @returns @li 0 on success, in which case @p out_has_more is set,
 *          @li -1 if the option value is too big to be a correct BLOCK option.
 */
int avs_coap_opt_block_has_more(const avs_coap_opt_t *opt, bool *out_has_more);

/**
 * Retrieves a block size from a CoAP BLOCK option.
 *
 * Note: the function does not check whether @p opt is indeed a BLOCK option.
 * Calling this function on non-BLOCK options causes undefined behavior.
 *
 * @param[in]  opt      CoAP option to read sequence number from.
 * @param[out] out_size Block size, in bytes, encoded in the option.
 *
 * @returns @li 0 on success, in which case @p out_has_more is set,
 *          @li -1 if the option value is too big to be a correct BLOCK option
 *              or if the option is malformed.
 */
int avs_coap_opt_block_size(const avs_coap_opt_t *opt, uint16_t *out_size);

/**
 * @param opt Option to operate on.
 *
 * @returns Option Delta (as per RFC7252 section 3.1).
 */
uint32_t avs_coap_opt_delta(const avs_coap_opt_t *opt);

/**
 * @param opt Option to operate on.
 *
 * @returns Length of the option content, in bytes.
 */
uint32_t avs_coap_opt_content_length(const avs_coap_opt_t *opt);

/**
 * @param opt           Option to operate on.
 * @param max_opt_bytes Number of valid bytes available for the @p opt.
 *                      Used to prevent out-of-bounds buffer access.
 *
 * @returns True if the option has a valid format, false otherwise.
 */
bool avs_coap_opt_is_valid(const avs_coap_opt_t *opt, size_t max_opt_bytes);

/**
 * @param opt Option to operate on.
 *
 * @returns Total size of the option including content, in bytes.
 */
size_t avs_coap_opt_sizeof(const avs_coap_opt_t *opt);

/**
 * Prints contents of a CoAP option.
 *
 * @param opt CoAP option to print.
 */
void avs_coap_opt_debug_print(const avs_coap_opt_t *opt);

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_OPT_H
