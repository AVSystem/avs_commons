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

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_STREAM)        \
        && defined(AVS_COMMONS_WITH_AVS_BUFFER) \
        && defined(AVS_COMMONS_WITH_AVS_NET)

#    include <stdio.h>
#    include <string.h>

#    include <avsystem/commons/avs_buffer.h>
#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_net.h>
#    include <avsystem/commons/avs_stream_netbuf.h>
#    include <avsystem/commons/avs_stream_v_table.h>

#    include <avsystem/commons/avs_stream_net.h>

#    define MODULE_NAME avs_stream
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

typedef struct buffered_netstream_struct {
    const avs_stream_v_table_t *const vtable;
    avs_net_socket_t *socket;

    avs_buffer_t *out_buffer;
    avs_buffer_t *in_buffer;
} buffered_netstream_t;

static avs_error_t out_buffer_flush(buffered_netstream_t *stream) {
    avs_error_t err =
            avs_net_socket_send(stream->socket,
                                avs_buffer_data(stream->out_buffer),
                                avs_buffer_data_size(stream->out_buffer));
    if (avs_is_ok(err)) {
        avs_buffer_reset(stream->out_buffer);
    }
    return err;
}

static avs_error_t buffered_netstream_write_some(avs_stream_t *stream_,
                                                 const void *data,
                                                 size_t *inout_data_length) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    avs_error_t err;
    if (*inout_data_length < avs_buffer_space_left(stream->out_buffer)) {
        return avs_errno(avs_buffer_append_bytes(stream->out_buffer, data,
                                                 *inout_data_length)
                                 ? AVS_ENOBUFS
                                 : AVS_NO_ERROR);
    } else if (avs_is_err((err = out_buffer_flush(stream)))) {
        return err;
    } else {
        return avs_net_socket_send(stream->socket, data, *inout_data_length);
    }
}

static size_t buffered_netstream_nonblock_write_ready(avs_stream_t *stream) {
    return avs_buffer_space_left(((buffered_netstream_t *) stream)->out_buffer);
}

static avs_error_t buffered_netstream_finish_message(avs_stream_t *stream) {
    return out_buffer_flush((buffered_netstream_t *) stream);
}

static void return_data_from_buffer(avs_buffer_t *in_buffer,
                                    size_t *out_bytes_read,
                                    void *buffer,
                                    size_t buffer_length) {
    *out_bytes_read = avs_buffer_data_size(in_buffer);
    if (buffer_length < *out_bytes_read) {
        *out_bytes_read = buffer_length;
    }

    memcpy(buffer, avs_buffer_data(in_buffer), *out_bytes_read);
    if (avs_buffer_consume_bytes(in_buffer, *out_bytes_read)) {
        AVS_UNREACHABLE();
    }
}

static avs_error_t read_data_to_user_buffer(buffered_netstream_t *stream,
                                            size_t *out_bytes_read,
                                            bool *out_message_finished,
                                            void *buffer,
                                            size_t buffer_length) {
    avs_error_t err = avs_net_socket_receive(stream->socket, out_bytes_read,
                                             buffer, buffer_length);
    *out_message_finished = (avs_is_err(err) || *out_bytes_read == 0);
    return err;
}

static avs_error_t in_buffer_read_some(buffered_netstream_t *stream,
                                       size_t *out_bytes_read) {
    avs_buffer_t *in_buffer = stream->in_buffer;
    size_t space_left = avs_buffer_space_left(in_buffer);

    if (!space_left) {
        LOG(ERROR, _("cannot read more data - buffer is full"));
        return avs_errno(AVS_ENOBUFS);
    }

    avs_error_t err =
            avs_net_socket_receive(stream->socket, out_bytes_read,
                                   avs_buffer_raw_insert_ptr(in_buffer),
                                   space_left);
    if (avs_is_ok(err)) {
        avs_buffer_advance_ptr(in_buffer, *out_bytes_read);
    }
    return err;
}

static avs_error_t
read_data_through_internal_buffer(buffered_netstream_t *stream,
                                  size_t *out_bytes_read,
                                  bool *out_message_finished,
                                  void *buffer,
                                  size_t buffer_length) {
    avs_error_t err = in_buffer_read_some(stream, out_bytes_read);
    if (avs_is_err(err)) {
        *out_message_finished = false;
        return err;
    }
    if (avs_buffer_data_size(stream->in_buffer) > 0) {
        return_data_from_buffer(stream->in_buffer, out_bytes_read, buffer,
                                buffer_length);
        *out_message_finished = false;
    } else {
        *out_bytes_read = 0;
        *out_message_finished = true;
    }
    return AVS_OK;
}

static avs_error_t read_new_data(buffered_netstream_t *stream,
                                 size_t *out_bytes_read,
                                 bool *out_message_finished,
                                 void *buffer,
                                 size_t buffer_length) {
    if (buffer_length >= avs_buffer_capacity(stream->in_buffer)) {
        return read_data_to_user_buffer(stream, out_bytes_read,
                                        out_message_finished, buffer,
                                        buffer_length);
    } else {
        return read_data_through_internal_buffer(stream, out_bytes_read,
                                                 out_message_finished, buffer,
                                                 buffer_length);
    }
}

static avs_error_t buffered_netstream_read(avs_stream_t *stream_,
                                           size_t *out_bytes_read,
                                           bool *out_message_finished,
                                           void *buffer,
                                           size_t buffer_length) {
    size_t bytes_read;
    bool message_finished;
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    if (!out_bytes_read) {
        out_bytes_read = &bytes_read;
    }
    if (!out_message_finished) {
        out_message_finished = &message_finished;
    }

    if (avs_buffer_data_size(stream->in_buffer) <= 0) {
        return read_new_data(stream, out_bytes_read, out_message_finished,
                             buffer, buffer_length);
    }

    return_data_from_buffer(stream->in_buffer, out_bytes_read, buffer,
                            buffer_length);
    *out_message_finished = false;
    return AVS_OK;
}

static avs_error_t try_recv_nonblock(buffered_netstream_t *stream) {
    avs_net_socket_opt_value_t old_recv_timeout;
    const avs_net_socket_opt_value_t zero_timeout = {
        .recv_timeout = AVS_TIME_DURATION_ZERO
    };

    avs_error_t err;
    if (avs_is_err(
                (err = avs_net_socket_get_opt(stream->socket,
                                              AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                                              &old_recv_timeout)))
            || avs_is_err((err = avs_net_socket_set_opt(
                                   stream->socket,
                                   AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                                   zero_timeout)))) {
        LOG(ERROR, _("cannot set socket timeout"));
        return err;
    }

    size_t bytes_read;
    err = in_buffer_read_some(stream, &bytes_read);
    if (err.category == AVS_ERRNO_CATEGORY && err.code == AVS_ETIMEDOUT) {
        // nothing to read - this is expected, ignore
        err = AVS_OK;
    }

    avs_error_t restore_err = avs_net_socket_set_opt(
            stream->socket, AVS_NET_SOCKET_OPT_RECV_TIMEOUT, old_recv_timeout);
    if (avs_is_err(restore_err)) {
        LOG(ERROR, _("cannot restore socket timeout"));
        if (avs_is_ok(err)) {
            err = restore_err;
        }
    }

    return err;
}

static bool buffered_netstream_nonblock_read_ready(avs_stream_t *stream_) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
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
    return avs_is_ok(try_recv_nonblock(stream))
           && avs_buffer_data_size(stream->in_buffer) > 0;
}

static avs_error_t
buffered_netstream_peek(avs_stream_t *stream_, size_t offset, char *out_value) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    if (offset < avs_buffer_capacity(stream->in_buffer)) {
        while (offset >= avs_buffer_data_size(stream->in_buffer)) {
            size_t bytes_read;
            avs_error_t err = in_buffer_read_some(stream, &bytes_read);
            if (avs_is_err(err)) {
                LOG(ERROR, _("cannot peek - read error"));
                return err;
            } else if (bytes_read == 0) {
                LOG(ERROR, _("cannot peek - 0 bytes read"));
                return AVS_EOF;
            }
        }
        *out_value = avs_buffer_data(stream->in_buffer)[offset];
        return AVS_OK;
    } else {
        LOG(ERROR, _("cannot peek - buffer is too small"));
        return avs_errno(AVS_EINVAL);
    }
}

static avs_error_t buffered_netstream_reset(avs_stream_t *stream_) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    avs_buffer_reset(stream->in_buffer);
    avs_buffer_reset(stream->out_buffer);
    return AVS_OK;
}

static avs_error_t buffered_netstream_close(avs_stream_t *stream_) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    avs_error_t err = AVS_OK;
    if (stream->socket) {
        err = avs_net_socket_shutdown(stream->socket);
    }
    avs_net_socket_cleanup(&stream->socket);
    avs_free(stream->in_buffer);
    avs_buffer_free(&stream->out_buffer);
    return err;
}

static avs_net_socket_t *buffered_netstream_getsock(avs_stream_t *stream) {
    return ((buffered_netstream_t *) stream)->socket;
}

static avs_error_t buffered_netstream_setsock(avs_stream_t *stream_,
                                              avs_net_socket_t *socket) {
    buffered_netstream_t *stream = (buffered_netstream_t *) stream_;
    stream->socket = socket;
    return AVS_OK;
}

static const avs_stream_v_table_t buffered_netstream_vtable = {
    .write_some = buffered_netstream_write_some,
    .finish_message = buffered_netstream_finish_message,
    .read = buffered_netstream_read,
    .peek = buffered_netstream_peek,
    .reset = buffered_netstream_reset,
    .close = buffered_netstream_close,
    .extension_list =
            (const avs_stream_v_table_extension_t[]) {
                    { AVS_STREAM_V_TABLE_EXTENSION_NET,
                      &(const avs_stream_v_table_extension_net_t) {
                              buffered_netstream_getsock,
                              buffered_netstream_setsock,
                      } },
                    { AVS_STREAM_V_TABLE_EXTENSION_NONBLOCK,
                      &(const avs_stream_v_table_extension_nonblock_t) {
                              buffered_netstream_nonblock_read_ready,
                              buffered_netstream_nonblock_write_ready } },
                    AVS_STREAM_V_TABLE_EXTENSION_NULL }
};

int avs_stream_netbuf_create(avs_stream_t **stream_,
                             avs_net_socket_t *socket,
                             size_t in_buffer_size,
                             size_t out_buffer_size) {
    buffered_netstream_t *stream =
            (buffered_netstream_t *) avs_calloc(1,
                                                sizeof(buffered_netstream_t));
    *stream_ = (avs_stream_t *) stream;

    if (!*stream_) {
        LOG(ERROR, _("cannot allocate memory"));
        return -1;
    }

    *(const avs_stream_v_table_t **) (intptr_t) &stream->vtable =
            &buffered_netstream_vtable;

    stream->socket = socket;
    if (avs_buffer_create(&stream->in_buffer, in_buffer_size)) {
        LOG(ERROR, _("cannot create input buffer"));
        goto buffered_netstream_create_error;
    }
    if (avs_buffer_create(&stream->out_buffer, out_buffer_size)) {
        LOG(ERROR, _("cannot create output buffer"));
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

int avs_stream_netbuf_transfer(avs_stream_t *destination_,
                               avs_stream_t *source_) {
    buffered_netstream_t *destination = (buffered_netstream_t *) destination_;
    buffered_netstream_t *source = (buffered_netstream_t *) source_;

    if (source->vtable != &buffered_netstream_vtable
            || destination->vtable != &buffered_netstream_vtable) {
        LOG(ERROR, _("buffers can be transferred only between netbuf streams"));
        return -1;
    }

    if (avs_buffer_space_left(destination->out_buffer)
                    < avs_buffer_data_size(source->out_buffer)
            || avs_buffer_space_left(destination->in_buffer)
                           < avs_buffer_data_size(source->in_buffer)) {
        LOG(ERROR, _("no space left in destination buffer"));
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

int avs_stream_netbuf_out_buffer_left(avs_stream_t *str) {
    buffered_netstream_t *stream = (buffered_netstream_t *) str;
    if (stream->vtable != &buffered_netstream_vtable) {
        LOG(ERROR, _("not a buffered_netstream"));
        return -1;
    }
    return (int) avs_buffer_space_left(stream->out_buffer);
}

void avs_stream_netbuf_set_recv_timeout(avs_stream_t *str,
                                        avs_time_duration_t timeout) {
    buffered_netstream_t *stream = (buffered_netstream_t *) str;
    avs_net_socket_opt_value_t timeout_opt;

    timeout_opt.recv_timeout = timeout;
    avs_net_socket_set_opt(stream->socket, AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
                           timeout_opt);
}

#endif // defined(AVS_COMMONS_WITH_AVS_STREAM) &&
       // defined(AVS_COMMONS_WITH_AVS_BUFFER) &&
       // defined(AVS_COMMONS_WITH_AVS_NET)
