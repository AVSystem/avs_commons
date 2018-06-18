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

#ifndef AVS_COMMONS_COAP_MSG_OPT_H
#define AVS_COMMONS_COAP_MSG_OPT_H

#include <avsystem/commons/coap/msg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Constant returned from some of option-retrieving functions, indicating
 * the absence of requested option.
 */
#define AVS_COAP_OPTION_MISSING 1

/**
 * Finds a unique CoAP option with given @p opt_number in @p msg.
 *
 * @param[in]  msg        CoAP message to look for the option in.
 * @param[in]  opt_number CoAP option number to find.
 * @param[out] out_opt    Pointer the found option.
 *
 * @returns @li 0 if exactly one option with given @p opt_number was found.
 *              In such case, <c>*out_opt</c> is set to a pointer to the
 *              found option, whose lifetime is equal to the lifetime
 *              of @p msg .
 *          @li a negative value if there is no such option, or there is more
 *              than one. These cases can be distinguished by the value of
 *              <c>*out_opt</c>: if it is NULL, no option was found. If it is
 *              not NULL, <c>*out_opt</c> contains a valid pointer to the first
 *              encountered option with @p opt_number.
 */
int avs_coap_msg_find_unique_opt(const avs_coap_msg_t *msg,
                                 uint16_t opt_number,
                                 const avs_coap_opt_t **out_opt);

/**
 * Finds a unique CoAP option with integer value.
 *
 * This is a low-level function, use @ref avs_coap_msg_get_option_u16 or
 * @ref avs_coap_msg_get_option_u32 instead.
 *
 * @param[in]  msg           CoAP message to look for the option in.
 * @param[in]  option_number CoAP option number to find.
 * @param[out] out_fmt       Buffer for the integer value in host byte order.
 * @param[out] out_fmt_size  Number of bytes available in @p out_fmt .
 *
 * @returns @li 0 if exactly one option with given @p option_number was found,
 *              and its integer value was successfully put into @p out_fmt
 *              buffer,
 *          @li AVS_COAP_OPTION_MISSING if @p msg does not contain any option
 *              with given @p option_number ,
 *          @li a negative value if multiple options with given @p option_number
 *              were found or @p out_fmt buffer is too small to hold the value.
 */
int avs_coap_msg_get_option_uint(const avs_coap_msg_t *msg,
                                 uint16_t option_number,
                                 void *out_fmt,
                                 size_t out_fmt_size);

/**
 * Finds a unique CoAP option with a 16-bit unsigned integer value.
 *
 * See @ref avs_coap_msg_get_option_uint for a description of possible return
 * values.
 */
static inline int avs_coap_msg_get_option_u16(const avs_coap_msg_t *msg,
                                              uint16_t option_number,
                                              uint16_t *out_value) {
    return avs_coap_msg_get_option_uint(msg, option_number, out_value,
                                        sizeof(*out_value));
}

/**
 * Finds a unique CoAP option with a 32-bit unsigned integer value.
 *
 * See @ref avs_coap_msg_get_option_uint for a description of possible return
 * values.
 */
static inline int avs_coap_msg_get_option_u32(const avs_coap_msg_t *msg,
                                              uint16_t option_number,
                                              uint32_t *out_value) {
    return avs_coap_msg_get_option_uint(msg, option_number, out_value,
                                        sizeof(*out_value));
}

/**
 * Iterates over CoAP options from @p msg that match given @p option_number ,
 * yielding their values as zero-terminated strings.
 *
 * @param[in]    msg            CoAP message to retrieve options from.
 * @param[in]    option_number  CoAP option number to look for.
 * @param[inout] it             Option iterator object that holds iteration
 *                              state. When starting the iteration, it MUST
 *                              be set with @ref AVS_COAP_OPT_ITERATOR_EMPTY .
 * @param[out]   out_bytes_read Number of bytes successfully put into
 *                              @p buffer, including terminating nullbyte.
 * @param[out]   buffer         Buffer to put option value into.
 * @param[in]    buffer_size    Number of bytes available in @p buffer .
 *
 * NOTES:
 * - When iterating over options using this function, @p option_number MUST
 *   remain unchanged, otherwise the behavior is undefined.
 * - The iterator state MUST NOT be changed by user code during the iteration.
 *   Doing so causes the behavior if this function to be undefined.
 *
 * @returns @li 0 on success,
 *          @li AVS_COAP_OPTION_MISSING when there are no more options with
 *              given @p option_number to retrieve,
 *          @li a negative value if @p buffer is not big enough to hold the
 *              option value or terminating nullbyte.
 */
int avs_coap_msg_get_option_string_it(const avs_coap_msg_t *msg,
                                      uint16_t option_number,
                                      avs_coap_opt_iterator_t *it,
                                      size_t *out_bytes_read,
                                      char *buffer,
                                      size_t buffer_size);

/**
 * @param[in]  msg       CoAP message to retrieve Content-Format option from.
 * @param[out] out_value Retrieved value of the Content-Format CoAP option.
 *
 * @returns @li 0 if the Content-Format was successfully retrieved and written
 *              to <c>*out_value</c>, or the option was missing, in which case
 *              <c>*out_value</c> is set to @ref AVS_COAP_FORMAT_NONE ,
 *          @li A negative value if the option was malformed or multiple
 *              Content-Format options were found in @p msg .
 */
int avs_coap_msg_get_content_format(const avs_coap_msg_t *msg,
                                    uint16_t *out_value);

/**
 * A callback that determines whether given option number is appropriate for
 * a message with specific CoAP code.
 *
 * @param msg_code Code of the CoAP message.
 * @param optnum   Option number to check. This will always be a number
 *                 referring to a critical option (as defined in RFC7252).
 *
 * @returns Should return true if the option is acceptable, false otherwise.
 */
typedef bool avs_coap_critical_option_validator_t(uint8_t msg_code,
                                                  uint32_t optnum);

/**
 * Checks whether critical options from @p msg are valid. BLOCK1 and BLOCK2
 * options are handled internally, other options need to be checked
 * by @p validator.
 *
 * @param msg       CoAP Message to validation options in.
 * @param validator Callback that checks validity of a critical option.
 *                  Must not be NULL.
 *
 * @returns 0 if all critical options are considered valid, a negative value
 *          otherwise.
 */
int avs_coap_msg_validate_critical_options(
        const avs_coap_msg_t *msg,
        avs_coap_critical_option_validator_t validator);

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_MSG_OPT_H
