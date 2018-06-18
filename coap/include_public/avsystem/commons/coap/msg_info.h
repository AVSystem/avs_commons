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

#ifndef AVS_COMMONS_COAP_MSGINFO_H
#define AVS_COMMONS_COAP_MSGINFO_H

#include <stdlib.h>

#include <avsystem/commons/list.h>

#include <avsystem/commons/coap/block_utils.h>
#include <avsystem/commons/coap/msg.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Internal, opaque struct that holds a single CoAP option. */
typedef struct avs_coap_msg_info_opt avs_coap_msg_info_opt_t;

/** Unserialized form of CoAP message header + token + options. */
typedef struct avs_coap_msg_info {
    avs_coap_msg_type_t type;
    uint8_t code;
    avs_coap_msg_identity_t identity;

    /* Fields below are NOT meant to be modified directly. Use provided
     * accessor functions instead. */
    AVS_LIST(avs_coap_msg_info_opt_t) options_;
} avs_coap_msg_info_t;

/**
 * Initializes a @ref avs_coap_header_msg_info_t .
 */
static inline avs_coap_msg_info_t avs_coap_msg_info_init() {
    return (avs_coap_msg_info_t){
        .code = AVS_COAP_CODE_EMPTY,
        .identity = {
            .msg_id = 0,
            .token = { 0, "" },
        },
        .options_ = NULL
    };
}

/**
 * Frees any memory allocated for temporary storage required by the info object.
 * Resets all header fields to defaults.
 */
void avs_coap_msg_info_reset(avs_coap_msg_info_t *info);

/**
 * Calculates number of header bytes in the CoAP packet constructed from the
 * @p info struct.
 *
 * @returns total number of bytes of a message that will be actually transmitted
 *          over the wire.
 *
 * NOTE: Unlike @ref avs_coap_msg_info_get_storage_size , this DOES NOT
 * include the size of @ref avs_coap_msg_info_t#length field. Because of that
 * this function is NOT suitable for calculating size of the buffer for a
 * serialized message.
 */
size_t avs_coap_msg_info_get_headers_size(const avs_coap_msg_info_t *info);

/**
 * Calculates number of bytes required to serialize the message stored in a
 * @ref avs_coap_msg_info_t object.
 *
 * @returns total number of bytes required for serialized message, assuming
 *          no payload and a token of maximum possible size.
 *
 * NOTE: This includes the @ref avs_coap_msg_info_t length field size.
 */
size_t avs_coap_msg_info_get_storage_size(const avs_coap_msg_info_t *info);

/**
 * @returns total number of bytes required for serialized message, assuming
 *          @p payload_size bytes of payload and a token of maximum possible size.
 */
size_t
avs_coap_msg_info_get_packet_storage_size(const avs_coap_msg_info_t *info,
                                          size_t payload_size);

/**
 * Removes all options with given @p option_number added to @p info.
 */
void avs_coap_msg_info_opt_remove_by_number(avs_coap_msg_info_t *info,
                                            uint16_t option_number);


/**
 * A magic value used to indicate the absence of the Content-Format option.
 * Mainly used during CoAP message parsing, passing it to the info object does
 * nothing.
 * */
#define AVS_COAP_FORMAT_NONE UINT16_MAX

/**
 * Adds a Content-Format Option (@ref AVS_COAP_OPT_CONTENT_FORMAT = 12) to the
 * message being built.
 *
 * @param info    Info object to operate on.
 * @param format  Numeric value of the Content-Format option. May be one of the
 *                AVS_COAP_FORMAT_* contants. Calling this function with
 *                @ref AVS_COAP_FORMAT_NONE removes the Content-Format option.
 *
 * @return 0 on success, -1 in case of error.
 */
int avs_coap_msg_info_opt_content_format(avs_coap_msg_info_t *info,
                                         uint16_t format);

/**
 * Adds the Block1 or Block2 Option to the message being built.
 *
 * @param info  Info object to operate on.
 * @param block BLOCK option content to set.
 *
 * @return 0 on success, -1 in case of error.
 */
int avs_coap_msg_info_opt_block(avs_coap_msg_info_t *info,
                                const avs_coap_block_info_t *block);

/**
 * Adds an arbitrary CoAP option with custom value.
 *
 * Repeated calls to this function APPEND additional instances of a CoAP option.
 *
 * @param info          Info object to operate on.
 * @param opt_number    CoAP Option Number to set.
 * @param opt_data      Option value.
 * @param opt_data_size Number of bytes in the @p opt_data buffer.
 *
 * @return 0 on success, -1 in case of error:
 *         - the message code is set to @ref AVS_COAP_CODE_EMPTY, which must
 *           not contain any options.
 */
int avs_coap_msg_info_opt_opaque(avs_coap_msg_info_t *info,
                                 uint16_t opt_number,
                                 const void *opt_data,
                                 uint16_t opt_data_size);

/**
 * Equivalent to:
 *
 * @code
 * avs_coap_msg_info_opt_opaque(info, opt_number,
 *                              opt_data, strlen(opt_data))
 * @endcode
 */
int avs_coap_msg_info_opt_string(avs_coap_msg_info_t *info,
                                 uint16_t opt_number,
                                 const char *opt_data);

/**
 * Adds an arbitrary CoAP option with no value.
 * See @ref avs_coap_msg_info_opt_opaque for more info.
 */
int avs_coap_msg_info_opt_empty(avs_coap_msg_info_t *info, uint16_t opt_number);

/** @{
 * Functions below add an arbitrary CoAP option with an integer value. The value
 * is encoded in the most compact way available, so e.g. for @p value equal to 0
 * the option has no payload when added using any of them.
 *
 * See @ref avs_coap_msg_info_opt_opaque for more info.
 */
int avs_coap_msg_info_opt_uint(avs_coap_msg_info_t *info,
                               uint16_t opt_number,
                               const void *value,
                               size_t value_size);

static inline int avs_coap_msg_info_opt_u16(avs_coap_msg_info_t *info,
                                            uint16_t opt_number,
                                            uint16_t value) {
    return avs_coap_msg_info_opt_uint(info, opt_number, &value, sizeof(value));
}

static inline int avs_coap_msg_info_opt_u32(avs_coap_msg_info_t *info,
                                            uint16_t opt_number,
                                            uint32_t value) {
    return avs_coap_msg_info_opt_uint(info, opt_number, &value, sizeof(value));
}

/** @} */

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_MSGINFO_H
