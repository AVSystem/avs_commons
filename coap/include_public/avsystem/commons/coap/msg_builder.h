/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_COAP_MSGBUILDER_H
#define AVS_COMMONS_COAP_MSGBUILDER_H

#include <stdlib.h>
#include <assert.h>

#include <avsystem/commons/coap/msg_info.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Internal helper object used to store a buffer and its capacity. */
typedef struct avs_coap_msg_buffer {
    avs_coap_msg_t *msg;
    size_t capacity;
} avs_coap_msg_buffer_t;

/**
 * Builder object used to construct a single CoAP packet.
 *
 * Its fields should not be modified directly. Use <c>avs_coap_msg_builder_*</c>
 * functions instead.
 */
typedef struct avs_coap_msg_builder {
    bool has_payload_marker;
    avs_coap_msg_buffer_t msg_buffer;
} avs_coap_msg_builder_t;

/**
 * Internal use only.
 *
 * Initializes a dummy @ref avs_coap_msg_builder_t object with no buffer for
 * the constructed message.
 */
#define AVS_COAP_MSG_BUILDER_UNINITIALIZED \
    ((avs_coap_msg_builder_t){ \
        .has_payload_marker = false, \
        .msg_buffer = { .msg = NULL, .capacity = 0 } \
    })

/**
 * @returns true if the builder object is backed by some non-NULL buffer,
 *          false otherwise.
 */
static inline bool
avs_coap_msg_builder_is_initialized(avs_coap_msg_builder_t *builder) {
    return builder->msg_buffer.msg != NULL;
}

/**
 * @return true if any payload has already been fed to the @p builder ,
 *         false otherwise.
 */
static inline bool
avs_coap_msg_builder_has_payload(avs_coap_msg_builder_t *builder) {
    return builder->has_payload_marker;
}

/**
 * Internal helper function for ensuring correct alignment
 * of the message buffer.
 *
 * The struct itself is not defined, as the pointer is never defererenced.
 */
typedef struct avs_coap_aligned_msg_buffer avs_coap_aligned_msg_buffer_t;

/**
 * Ensures @p buffer is appropriately aligned for use with
 * @ref avs_coap_msg_builder_t .
 *
 * @returns @p buffer cast to @ref avs_coap_aligned_msg_buffer_t .
 */
static inline avs_coap_aligned_msg_buffer_t *
avs_coap_ensure_aligned_buffer(void *buffer) {
    AVS_ASSERT((uintptr_t)buffer % AVS_ALIGNOF(avs_coap_msg_t) == 0,
               "the buffer MUST have the same alignment as avs_coap_msg_t");

    return (avs_coap_aligned_msg_buffer_t *)buffer;
}

/**
 * Creates an @ref avs_coap_msg_builder_t backed by @p buffer . @p buffer MUST
 * live at least as long as @p builder.
 *
 * @param[out] builder     Builder to initialize.
 * @param[in]  buffer      Buffer to use as storage for constructed CoAP
 *                         message. WARNING: this buffer MUST have the same
 *                         alignment as @ref avs_coap_msg_t .
 * @param[in]  buffer_size Number of bytes available in @p buffer.
 * @param[in]  header      Set of headers to initialize @p builder with.
 *
 * @returns 0 on success, a negative value in case of error (including incorrect
 *          alignment of @p buffer).
 */
int avs_coap_msg_builder_init(avs_coap_msg_builder_t *builder,
                              avs_coap_aligned_msg_buffer_t *buffer,
                              size_t buffer_size_bytes,
                              const avs_coap_msg_info_t *info);

/**
 * Initializes a @p builder with message headers stored in @p header. Resets any
 * payload possibly written to @p builder.
 *
 * @param builder Builder object to reset.
 * @param header  Set of headers to initialize @p builder with.
 *
 * @return 0 on success, a negative value in case of error.
 */
int avs_coap_msg_builder_reset(avs_coap_msg_builder_t *builder,
                               const avs_coap_msg_info_t *info);

/**
 * Returns amount of bytes that can be written as a payload using this builder
 * instance.
 *
 * @param builder      Builder object to operate on.
 *
 * @return Number of bytes available for the payload.
 */
size_t
avs_coap_msg_builder_payload_remaining(const avs_coap_msg_builder_t *builder);

/**
 * Appends at most @p payload_size bytes of @p payload to the message
 * being built.
 *
 * @param builder      Builder object to operate on.
 * @param payload      Payload bytes to append.
 * @param payload_size Number of bytes in the @p payload buffer.
 *
 * @return Number of bytes written. NOTE: this may be less than @p payload_size.
 */
size_t avs_coap_msg_builder_payload(avs_coap_msg_builder_t *builder,
                                    const void *payload,
                                    size_t payload_size);

/**
 * Finalizes creation of the message. At least message header MUST be set in
 * order for this function to succeed.
 *
 * This function does not consume the builder. Repeated calls create identical
 * messages.
 *
 * @param builder Builder object to retrieve a message from.
 *
 * @return Pointer to a @ref avs_coap_msg_t object stored in the @p builder
 *         buffer. The message is guaranteed to be syntactically valid.
 *         This function always returns a non-NULL pointer to a serialized
 *         message build in @p buffer .
 */
const avs_coap_msg_t *
avs_coap_msg_builder_get_msg(const avs_coap_msg_builder_t *builder);

/**
 * Helper function for building messages with no payload.
 *
 * @param buffer      Buffer to store the message in.
 * @param buffer_size Number of bytes available in @p buffer.
 * @param header      Message headers.
 *
 * @return Constructed message object on success, NULL in case of error.
 */
static inline const avs_coap_msg_t *
avs_coap_msg_build_without_payload(avs_coap_aligned_msg_buffer_t *buffer,
                                   size_t buffer_size,
                                   const avs_coap_msg_info_t *info) {
    avs_coap_msg_builder_t builder;
    if (avs_coap_msg_builder_init(&builder, buffer, buffer_size, info)) {
        AVS_UNREACHABLE("could not initialize msg builder");
        return NULL;
    }

    return avs_coap_msg_builder_get_msg(&builder);
}

#ifdef __cplusplus
}
#endif

#endif // AVS_COMMONS_COAP_MSGBUILDER_H
