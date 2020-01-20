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

#include <avs_commons_config.h>

#include <avsystem/commons/coap/block_builder.h>
#include <avsystem/commons/utils.h>

#include "coap_log.h"

VISIBILITY_SOURCE_BEGIN

avs_coap_block_builder_t
avs_coap_block_builder_init(avs_coap_msg_builder_t *msg_builder) {
    assert(msg_builder->msg_buffer.msg != NULL);
    assert(msg_builder->msg_buffer.capacity > 0);

    const uint8_t *payload =
            (const uint8_t *) avs_coap_msg_payload(msg_builder->msg_buffer.msg);

    assert((const uint8_t *) msg_builder->msg_buffer.msg <= payload);
    size_t read_offset =
            (size_t) (payload - (const uint8_t *) msg_builder->msg_buffer.msg);

    size_t payload_size =
            avs_coap_msg_payload_length(msg_builder->msg_buffer.msg);

    avs_coap_block_builder_t block_builder = (avs_coap_block_builder_t) {
        .payload_buffer = msg_builder->msg_buffer.msg,
        .payload_capacity = msg_builder->msg_buffer.capacity,

        .read_offset = read_offset,
        .write_offset = read_offset + payload_size,
    };

    *msg_builder = AVS_COAP_MSG_BUILDER_UNINITIALIZED;
    return block_builder;
}

static void *payload_read_ptr(avs_coap_block_builder_t *builder) {
    return (uint8_t *) builder->payload_buffer + builder->read_offset;
}

static void *payload_write_ptr(avs_coap_block_builder_t *builder) {
    return (uint8_t *) builder->payload_buffer + builder->write_offset;
}

static void shift_payload(avs_coap_block_builder_t *builder) {
    if (builder->read_offset == 0) {
        return;
    }

    size_t unread_bytes = avs_coap_block_builder_payload_remaining(builder);
    if (unread_bytes > 0) {
        memmove(builder->payload_buffer, payload_read_ptr(builder),
                unread_bytes);
    }

    builder->read_offset = 0;
    builder->write_offset = unread_bytes;
}

size_t avs_coap_block_builder_append_payload(avs_coap_block_builder_t *builder,
                                             const void *payload,
                                             size_t payload_size) {
    shift_payload(builder);

    size_t bytes_available = builder->payload_capacity - builder->write_offset;
    size_t bytes_to_write = AVS_MIN(bytes_available, payload_size);

    memcpy(payload_write_ptr(builder), payload, bytes_to_write);
    builder->write_offset += bytes_to_write;

    return bytes_to_write;
}

size_t avs_coap_block_builder_payload_remaining(
        const avs_coap_block_builder_t *builder) {
    assert(builder->read_offset <= builder->write_offset);
    return builder->write_offset - builder->read_offset;
}

const avs_coap_msg_t *
avs_coap_block_builder_build(avs_coap_block_builder_t *builder,
                             const avs_coap_msg_info_t *info,
                             size_t block_size,
                             avs_coap_aligned_msg_buffer_t *buffer,
                             size_t buffer_size) {
    assert(buffer_size
           >= avs_coap_msg_info_get_packet_storage_size(info, block_size));
    AVS_ASSERT(block_size < builder->payload_capacity,
               "payload buffer MUST be able to hold more than a single block");

    if (builder->read_offset == builder->write_offset) {
        LOG(WARNING, _("no payload data to extract!"));
        return NULL;
    }

    avs_coap_msg_builder_t msg_builder;
    if (avs_coap_msg_builder_init(&msg_builder, buffer, buffer_size, info)) {
        AVS_UNREACHABLE("Failed to init msg_builder");
        return NULL;
    }

    size_t bytes_available = 0;
    {
        size_t block_builder_payload_remaining =
                avs_coap_block_builder_payload_remaining(builder);
        size_t msg_builder_payload_remaining =
                avs_coap_msg_builder_payload_remaining(&msg_builder);
        bytes_available = AVS_MIN(block_builder_payload_remaining,
                                  msg_builder_payload_remaining);
    }
    size_t bytes_to_write = AVS_MIN(bytes_available, block_size);
    assert(builder->read_offset + bytes_to_write <= builder->write_offset);

    size_t bytes_written = avs_coap_msg_builder_payload(
            &msg_builder, payload_read_ptr(builder), bytes_to_write);

    if (bytes_to_write != bytes_written) {
        AVS_UNREACHABLE("Could not flush the payload");
        return NULL;
    }

    return avs_coap_msg_builder_get_msg(&msg_builder);
}

void avs_coap_block_builder_next(avs_coap_block_builder_t *builder,
                                 size_t block_size) {
    builder->read_offset =
            AVS_MIN(builder->read_offset + block_size, builder->write_offset);
}
