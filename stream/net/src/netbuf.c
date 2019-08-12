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

#include <avs_commons_config.h>

#include <stdio.h>
#include <string.h>

#include <avsystem/commons/buffer.h>
#include <avsystem/commons/errno.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/net.h>
#include <avsystem/commons/stream/netbuf.h>
#include <avsystem/commons/stream_v_table.h>

#include <avsystem/commons/stream/stream_net.h>

#define MODULE_NAME avs_stream
#include <x_log_config.h>

VISIBILITY_SOURCE_BEGIN

typedef struct buffered_netstream_struct {
    const avs_stream_v_table_t * const vtable;
    avs_net_abstract_socket_t *socket;

    avs_buffer_t *out_buffer;
    avs_buffer_t *in_buffer;

    avs_errno_t errno_;
} buffered_netstream_t;

#define WRAP_ERRNO(Stream, Retval, ...) do { \
    Retval = (__VA_ARGS__); \
    if (Retval) { \
        if ((Stream)->errno_) { \
            LOG(TRACE, "error already set"); \
        } else { \
            (Stream)->errno_ = avs_net_socket_errno((Stream)->socket); \
        } \
    } \
} while (0)

static int out_buffer_flush(buffered_netstream_t *stream) {
    int result;
    WRAP_ERRNO(stream, result,
               avs_net_socket_send(stream->socket,
                                   avs_buffer_data(stream->out_buffer),
                                   avs_buffer_data_size(stream->out_buffer)));
    if (!result) {
        avs_buffer_reset(stream->out_buffer);
    }
    return result;
}

static int buffered_netstream_write_some(avs_stream_abstract_t *stream_,
                                         const void *data,
                                         size_t *inout_data_length) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;
    int result;
    if (*inout_data_length < avs_buffer_space_left(stream->out_buffer)) {
        return avs_buffer_append_bytes(stream->out_buffer, data,
                                       *inout_data_length);
    } else if ((result = out_buffer_flush(stream))) {
        return result;
    } else {
        WRAP_ERRNO(stream, result, avs_net_socket_send(stream->socket, data,
                                                       *inout_data_length));
        return result;
    }
}

static int
buffered_netstream_nonblock_write_ready(avs_stream_abstract_t *stream_,
                                        size_t *out_ready_capacity_bytes) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;
    *out_ready_capacity_bytes = avs_buffer_space_left(stream->out_buffer);
    return 0;
}

static int buffered_netstream_finish_message(avs_stream_abstract_t *stream_) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;
    return out_buffer_flush(stream);
}

static int return_data_from_buffer(avs_buffer_t *in_buffer,
                                   size_t *out_bytes_read,
                                   char *out_message_finished,
                                   void *buffer,
                                   size_t buffer_length) {
    *out_bytes_read = avs_buffer_data_size(in_buffer);
    if (buffer_length < *out_bytes_read) {
        *out_bytes_read = buffer_length;
    }

    memcpy(buffer, avs_buffer_data(in_buffer), *out_bytes_read);
    avs_buffer_consume_bytes(in_buffer, *out_bytes_read);

    *out_message_finished = 0;

    return 0;
}

static int read_data_to_user_buffer(buffered_netstream_t *stream,
                                    size_t *out_bytes_read,
                                    char *out_message_finished,
                                    void *buffer,
                                    size_t buffer_length) {
    int result;
    WRAP_ERRNO(stream, result, avs_net_socket_receive(stream->socket,
                                                      out_bytes_read,
                                                      buffer,
                                                      buffer_length));
    *out_message_finished = (result || *out_bytes_read == 0);
    return result;
}

static int in_buffer_read_some(buffered_netstream_t *stream,
                               size_t *out_bytes_read) {
    int result;
    avs_buffer_t *in_buffer = stream->in_buffer;
    size_t space_left = avs_buffer_space_left(in_buffer);

    if (!space_left) {
        LOG(ERROR, "cannot read more data - buffer is full");
        return -1;
    }

    WRAP_ERRNO(stream, result,
               avs_net_socket_receive(stream->socket,
                                      out_bytes_read,
                                      avs_buffer_raw_insert_ptr(in_buffer),
                                      space_left));

    if (!result) {
        avs_buffer_advance_ptr(in_buffer, *out_bytes_read);
    }
    return result;
}

static int read_data_through_internal_buffer(buffered_netstream_t *stream,
                                             size_t *out_bytes_read,
                                             char *out_message_finished,
                                             void *buffer,
                                             size_t buffer_length) {
    if (in_buffer_read_some(stream, out_bytes_read)) {
        *out_message_finished = 0;
        return -1;
    } else {
        if (avs_buffer_data_size(stream->in_buffer) > 0) {
            return return_data_from_buffer(stream->in_buffer,
                                           out_bytes_read,
                                           out_message_finished,
                                           buffer,
                                           buffer_length);
        } else {
            *out_bytes_read = 0;
            *out_message_finished = 1;
            return 0;
        }
    }
}

static int read_new_data(buffered_netstream_t *stream,
                         size_t *out_bytes_read,
                         char *out_message_finished,
                         void *buffer,
                         size_t buffer_length) {
    if (buffer_length >= avs_buffer_capacity(stream->in_buffer)) {
        return read_data_to_user_buffer(stream,
                                        out_bytes_read,
                                        out_message_finished,
                                        buffer,
                                        buffer_length);
    } else {
        return read_data_through_internal_buffer(stream,
                                                 out_bytes_read,
                                                 out_message_finished,
                                                 buffer,
                                                 buffer_length);
    }
}

static int buffered_netstream_read(avs_stream_abstract_t *stream_,
                                   size_t *out_bytes_read,
                                   char *out_message_finished,
                                   void *buffer,
                                   size_t buffer_length) {
    size_t bytes_read;
    char message_finished;
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;
    if (!out_bytes_read) {
        out_bytes_read = &bytes_read;
    }
    if (!out_message_finished) {
        out_message_finished = &message_finished;
    }

    if (avs_buffer_data_size(stream->in_buffer) > 0) {
        return return_data_from_buffer(stream->in_buffer,
                                       out_bytes_read,
                                       out_message_finished,
                                       buffer,
                                       buffer_length);
    } else {
        return read_new_data(stream,
                             out_bytes_read,
                             out_message_finished,
                             buffer,
                             buffer_length);

    }
}

static int try_recv_nonblock(buffered_netstream_t *stream) {
    avs_net_socket_opt_value_t old_recv_timeout;
    const avs_net_socket_opt_value_t zero_timeout = {
        .recv_timeout = AVS_TIME_DURATION_ZERO
    };

    if (avs_net_socket_get_opt(stream->socket, AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                               &old_recv_timeout)
            || avs_net_socket_set_opt(stream->socket,
                                      AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                                      zero_timeout)) {
        LOG(ERROR, "cannot set socket timeout");
        return -1;
    }

    size_t bytes_read;
    int result = in_buffer_read_some(stream, &bytes_read);
    if (result) {
        avs_errno_t socket_errno = avs_net_socket_errno(stream->socket);
        if (socket_errno == AVS_ETIMEDOUT) {
            // nothing to read - this is expected, ignore
            result = 0;
        }
    }

    if (avs_net_socket_set_opt(stream->socket, AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                               old_recv_timeout)) {
        LOG(ERROR, "cannot restore socket timeout");
    }

    return result;
}

static int
buffered_netstream_nonblock_read_ready(avs_stream_abstract_t *stream_) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;

    if (avs_buffer_data_size(stream->in_buffer) > 0) {
        return true;
    }

    /*
     * NOTE: if the underlying socket is a TLS socket, there may be some
     * data in TLS backend internal buffers that will never be reported by
     * select/poll on these sockets.
     *
     * To make sure we don't keep ignoring that data, attempt to read
     * something from the socket with timeout set to 0 before telling the
     * caller nonblock read is not possible.
     */
    return try_recv_nonblock(stream) == 0
        && avs_buffer_data_size(stream->in_buffer) > 0;
}

static int buffered_netstream_peek(avs_stream_abstract_t *stream_,
                                   size_t offset) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;

    if (offset < avs_buffer_capacity(stream->in_buffer)) {
        while (offset >= avs_buffer_data_size(stream->in_buffer)) {
            size_t bytes_read;
            if (in_buffer_read_some(stream, &bytes_read)) {
                LOG(ERROR, "cannot peek - read error");
                return EOF;
            } else if (bytes_read == 0) {
                LOG(ERROR, "cannot peek - 0 bytes read");
                return EOF;
            }
        }
        return (unsigned char)avs_buffer_data(stream->in_buffer)[offset];
    } else {
        LOG(ERROR, "cannot peek - buffer is too small");
        if (stream->errno_) {
            LOG(TRACE, "error already set");
        } else {
            stream->errno_ = AVS_EINVAL;
        }
        return EOF;
    }
}

static int buffered_netstream_reset(avs_stream_abstract_t *stream_) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;
    avs_buffer_reset(stream->in_buffer);
    avs_buffer_reset(stream->out_buffer);
    return 0;
}

static int buffered_netstream_close(avs_stream_abstract_t *stream_) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;
    if (stream->socket) {
        avs_net_socket_shutdown(stream->socket);
    }
    avs_net_socket_cleanup(&stream->socket);
    avs_free(stream->in_buffer);
    avs_buffer_free(&stream->out_buffer);
    return 0;
}

static int buffered_netstream_getsock(avs_stream_abstract_t *stream_,
                                      avs_net_abstract_socket_t **out_socket) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;
    *out_socket = stream->socket;
    return 0;
}

static int buffered_netstream_setsock(avs_stream_abstract_t *stream_,
                                      avs_net_abstract_socket_t *socket) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->errno_ = AVS_NO_ERROR;
    stream->socket = socket;
    return 0;
}

static avs_errno_t buffered_netstream_errno(avs_stream_abstract_t *stream) {
    return ((buffered_netstream_t *) stream)->errno_;
}

static const avs_stream_v_table_extension_net_t
buffered_netstream_net_vtable = {
    buffered_netstream_getsock,
    buffered_netstream_setsock,
};

static const avs_stream_v_table_extension_nonblock_t
buffered_netstream_nonblock_vtable = {
    buffered_netstream_nonblock_read_ready,
    buffered_netstream_nonblock_write_ready
};

static const avs_stream_v_table_extension_t
buffered_netstream_vtable_extensions[] = {
    { AVS_STREAM_V_TABLE_EXTENSION_NET, &buffered_netstream_net_vtable },
    { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
      &buffered_netstream_nonblock_vtable },
    AVS_STREAM_V_TABLE_EXTENSION_NULL
};

static const avs_stream_v_table_t buffered_netstream_vtable = {
    buffered_netstream_write_some,
    buffered_netstream_finish_message,
    buffered_netstream_read,
    buffered_netstream_peek,
    buffered_netstream_reset,
    buffered_netstream_close,
    buffered_netstream_errno,
    buffered_netstream_vtable_extensions
};

int avs_stream_netbuf_create(avs_stream_abstract_t **stream_,
                             avs_net_abstract_socket_t *socket,
                             size_t in_buffer_size,
                             size_t out_buffer_size) {
    buffered_netstream_t *stream = (buffered_netstream_t*)
            avs_calloc(1, sizeof(buffered_netstream_t));
    *stream_ = (avs_stream_abstract_t*) stream;

    if (!*stream_) {
        LOG(ERROR, "cannot allocate memory");
        return -1;
    }

    *(const avs_stream_v_table_t **) (intptr_t) &stream->vtable =
            &buffered_netstream_vtable;

    stream->socket = socket;
    if (avs_buffer_create(&stream->in_buffer, in_buffer_size)) {
        LOG(ERROR, "cannot create input buffer");
        goto buffered_netstream_create_error;
    }
    if (avs_buffer_create(&stream->out_buffer, out_buffer_size)) {
        LOG(ERROR, "cannot create output buffer");
        goto buffered_netstream_create_error;
    }
    return 0;

buffered_netstream_create_error:
    avs_buffer_free(&stream->in_buffer);
    avs_buffer_free(&stream->out_buffer);
    avs_free(*stream_);
    *stream_ = NULL;
    return -1;
}

int avs_stream_netbuf_transfer(avs_stream_abstract_t *destination_,
                               avs_stream_abstract_t *source_) {
    buffered_netstream_t *destination = (buffered_netstream_t *) destination_;
    buffered_netstream_t *source = (buffered_netstream_t *) source_;

    if (source->vtable != &buffered_netstream_vtable
            || destination->vtable != &buffered_netstream_vtable) {
        LOG(ERROR, "buffers can be transferred only between netbuf streams");
        return -1;
    }

    if (avs_buffer_space_left(destination->out_buffer)
            < avs_buffer_data_size(source->out_buffer)
            || avs_buffer_space_left(destination->in_buffer)
            < avs_buffer_data_size(source->in_buffer)) {
        LOG(ERROR, "no space left in destination buffer");
        return -1;
    }

    avs_buffer_append_bytes(destination->out_buffer,
                            avs_buffer_data(source->out_buffer),
                            avs_buffer_data_size(source->out_buffer));
    avs_buffer_reset(source->out_buffer);

    avs_buffer_append_bytes(destination->in_buffer,
                            avs_buffer_data(source->in_buffer),
                            avs_buffer_data_size(source->in_buffer));

    avs_buffer_reset(source->in_buffer);

    return 0;
}

int avs_stream_netbuf_out_buffer_left(avs_stream_abstract_t *str) {
    buffered_netstream_t *stream = (buffered_netstream_t *) str;
    if (stream->vtable != &buffered_netstream_vtable) {
        LOG(ERROR, "not a buffered_netstream");
        return -1;
    }
    return (int) avs_buffer_space_left(stream->out_buffer);
}

void avs_stream_netbuf_set_recv_timeout(avs_stream_abstract_t *str,
                                        avs_time_duration_t timeout) {
    buffered_netstream_t *stream = (buffered_netstream_t *) str;
    avs_net_socket_opt_value_t timeout_opt;

    timeout_opt.recv_timeout = timeout;
    avs_net_socket_set_opt(stream->socket,
                           AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                           timeout_opt);
    stream->errno_ = AVS_NO_ERROR;
}
