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

#define MODULE_NAME mocksock
#include <x_log_config.h>

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>

#include <avsystem/commons/list.h>
#include <avsystem/commons/log.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/net.h>
#include <avsystem/commons/socket_v_table.h>
#include <avsystem/commons/unit/mocksock.h>
#include <avsystem/commons/unit/test.h>

#include "test.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    const char *host;
    const char *port;
} mocksock_expected_connect_t;

typedef struct {
    const char *localaddr;
    const char *port;
} mocksock_expected_bind_t;

typedef struct {
    avs_net_socket_opt_key_t key;
    avs_net_socket_opt_value_t value;
} mocksock_expected_get_opt_t;

typedef struct {
    avs_net_socket_opt_key_t key;
} mocksock_expected_set_opt_t;

typedef enum {
    MOCKSOCK_COMMAND_CONNECT,
    MOCKSOCK_COMMAND_BIND,
    MOCKSOCK_COMMAND_ACCEPT,
    MOCKSOCK_COMMAND_SHUTDOWN,
    MOCKSOCK_COMMAND_SYSTEM_SOCKET,
    MOCKSOCK_COMMAND_INTERFACE_NAME,
    MOCKSOCK_COMMAND_REMOTE_HOST,
    MOCKSOCK_COMMAND_REMOTE_HOSTNAME,
    MOCKSOCK_COMMAND_REMOTE_PORT,
    MOCKSOCK_COMMAND_LOCAL_HOST,
    MOCKSOCK_COMMAND_LOCAL_PORT,
    MOCKSOCK_COMMAND_MID_CLOSE,
    MOCKSOCK_COMMAND_GET_OPT,
    MOCKSOCK_COMMAND_SET_OPT,
    MOCKSOCK_COMMAND_ERRNO
} mocksock_expected_command_type_t;

typedef struct mocksock_expected_command_struct {
    const char *source_file;
    int source_line;

    mocksock_expected_command_type_t command;
    union {
        mocksock_expected_connect_t connect;
        mocksock_expected_bind_t bind;
        const char *host;
        const char *port;
        mocksock_expected_get_opt_t get_opt;
        mocksock_expected_set_opt_t set_opt;
        const void *system_socket;
        avs_net_socket_interface_name_t if_name;
    } data;
    int retval;
} mocksock_expected_command_t;

static int mock_connect(avs_net_abstract_socket_t *socket,
                        const char *host,
                        const char *port);
static int mock_send(avs_net_abstract_socket_t *socket,
                     const void *buffer,
                     size_t buffer_length);
static int mock_send_to(avs_net_abstract_socket_t *socket,
                        const void *buffer,
                        size_t buffer_length,
                        const char *host,
                        const char *port);
static int mock_receive(avs_net_abstract_socket_t *socket,
                        size_t *out,
                        void *buffer,
                        size_t buffer_length);
static int mock_receive_from(avs_net_abstract_socket_t *socket,
                             size_t *out,
                             void *buffer,
                             size_t buffer_length,
                             char *out_host, size_t out_host_size,
                             char *out_port, size_t out_port_size);
static int mock_bind(avs_net_abstract_socket_t *socket,
                     const char *localaddr,
                     const char *port);
static int mock_accept(avs_net_abstract_socket_t *server_socket,
                       avs_net_abstract_socket_t *new_socket);
static int mock_close(avs_net_abstract_socket_t *socket);
static int mock_shutdown(avs_net_abstract_socket_t *socket);
static int mock_cleanup(avs_net_abstract_socket_t **socket);
static int mock_system_socket(avs_net_abstract_socket_t *socket,
                              const void **out);
static int mock_interface_name(avs_net_abstract_socket_t *socket,
                               avs_net_socket_interface_name_t *if_name);
static int mock_remote_host(avs_net_abstract_socket_t *socket,
                            char *hostname, size_t hostname_size);
static int mock_remote_hostname(avs_net_abstract_socket_t *socket,
                                char *hostname, size_t hostname_size);
static int mock_remote_port(avs_net_abstract_socket_t *socket,
                            char *port, size_t port_size);
static int mock_local_host(avs_net_abstract_socket_t *socket,
                           char *hostname, size_t hostname_size);
static int mock_local_port(avs_net_abstract_socket_t *socket,
                           char *port, size_t port_size);
static int mock_get_opt(avs_net_abstract_socket_t *socket,
                        avs_net_socket_opt_key_t option_key,
                        avs_net_socket_opt_value_t *out_option_value);
static int mock_set_opt(avs_net_abstract_socket_t *socket,
                        avs_net_socket_opt_key_t option_key,
                        avs_net_socket_opt_value_t option_value);
static int mock_errno(avs_net_abstract_socket_t *socket);

static int unimplemented() {
    return -1;
}

static const avs_net_socket_v_table_t mock_vtable = {
    mock_connect,
    (avs_net_socket_decorate_t) unimplemented,
    mock_send,
    mock_send_to,
    mock_receive,
    mock_receive_from,
    mock_bind,
    mock_accept,
    mock_close,
    mock_shutdown,
    mock_cleanup,
    mock_system_socket,
    mock_interface_name,
    mock_remote_host,
    mock_remote_hostname,
    mock_remote_port,
    mock_local_host,
    mock_local_port,
    mock_get_opt,
    mock_set_opt,
    mock_errno
};

static const char *cmd_type_to_string(mocksock_expected_command_type_t type) {
    switch (type) {
    case MOCKSOCK_COMMAND_CONNECT:
        return "connect";
    case MOCKSOCK_COMMAND_BIND:
        return "bind";
    case MOCKSOCK_COMMAND_ACCEPT:
        return "accept";
    case MOCKSOCK_COMMAND_SHUTDOWN:
        return "shutdown";
    case MOCKSOCK_COMMAND_SYSTEM_SOCKET:
        return "system_socket";
    case MOCKSOCK_COMMAND_INTERFACE_NAME:
        return "interface_name";
    case MOCKSOCK_COMMAND_REMOTE_HOST:
        return "remote_host";
    case MOCKSOCK_COMMAND_REMOTE_HOSTNAME:
        return "remote_hostname";
    case MOCKSOCK_COMMAND_REMOTE_PORT:
        return "remote_port";
    case MOCKSOCK_COMMAND_LOCAL_HOST:
        return "local_host";
    case MOCKSOCK_COMMAND_LOCAL_PORT:
        return "local_port";
    case MOCKSOCK_COMMAND_MID_CLOSE:
        return "mid_close";
    case MOCKSOCK_COMMAND_GET_OPT:
        return "get_opt";
    case MOCKSOCK_COMMAND_SET_OPT:
        return "set_opt";
    case MOCKSOCK_COMMAND_ERRNO:
        return "errno";
    }

    return "<invalid>";
}

static const char *cmd_to_string(const mocksock_expected_command_t *cmd) {
    return cmd ? cmd_type_to_string(cmd->command) : "<none>";
}

typedef enum {
    MOCKSOCK_DATA_TYPE_INPUT,
    MOCKSOCK_DATA_TYPE_OUTPUT,
    MOCKSOCK_DATA_TYPE_INPUT_FAIL,
    MOCKSOCK_DATA_TYPE_OUTPUT_FAIL
} mocksock_expected_data_type_t;

typedef struct {
    mocksock_expected_data_type_t type;
    const char *source_file;
    int source_line;
    union {
        struct {
            const char *remote_host;
            const char *remote_port;
            const void *data;
            size_t ptr;
            size_t size;
        } valid;
        int retval;
    } args;
} mocksock_expected_data_t;

static int data_has_size(const mocksock_expected_data_t *data) {
    switch (data->type) {
    case MOCKSOCK_DATA_TYPE_INPUT:
    case MOCKSOCK_DATA_TYPE_OUTPUT:
        return 1;
    default:
        return 0;
    }
}

static const char *data_type_to_string(mocksock_expected_data_type_t type) {
    switch (type) {
    case MOCKSOCK_DATA_TYPE_INPUT:
        return "input";
    case MOCKSOCK_DATA_TYPE_OUTPUT:
        return "output";
    case MOCKSOCK_DATA_TYPE_INPUT_FAIL:
        return "input fail";
    case MOCKSOCK_DATA_TYPE_OUTPUT_FAIL:
        return "output fail";
    }

    return "<invalid>";
}

typedef struct {
    const avs_net_socket_v_table_t *const vtable;
    mocksock_type_t type;

    AVS_LIST(mocksock_expected_command_t) expected_commands;
    AVS_LIST(mocksock_expected_data_t) expected_data;
    size_t last_data_read;

    bool recv_timeout_enabled;
    avs_time_duration_t recv_timeout;

    bool inner_mtu_enabled;
    int inner_mtu;

    bool mtu_enabled;
    int mtu;

    bool state_enabled;
    avs_net_socket_state_t state;

    bool remote_host_enabled;
    const char *remote_host;

    bool remote_port_enabled;
    const char *remote_port;
} mocksock_t;

static void assert_command_expected(const mocksock_expected_command_t *expected,
                                    mocksock_expected_command_type_t actual) {
    if (!expected) {
        _avs_unit_assert(0, __FILE__, __LINE__,
                         "unexpected call: %s\n", cmd_type_to_string(actual));
    } else {
        _avs_unit_assert(expected->command == actual, __FILE__, __LINE__,
                         "%s called instead of %s (expect call at %s:%d)\n",
                         cmd_type_to_string(actual), cmd_to_string(expected),
                         expected->source_file, expected->source_line);
    }
}

static int mock_connect(avs_net_abstract_socket_t *socket_,
                        const char *host,
                        const char *port) {
    LOG(TRACE, "mock_connect: host <%s>, port <%s>", host, port);

    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
                            MOCKSOCK_COMMAND_CONNECT);

    AVS_UNIT_ASSERT_TRUE(socket->state == AVS_NET_SOCKET_STATE_CLOSED
            || socket->state == AVS_NET_SOCKET_STATE_BOUND);
    AVS_UNIT_ASSERT_EQUAL_STRING(host,
                                 socket->expected_commands->data.connect.host);
    AVS_UNIT_ASSERT_EQUAL_STRING(port,
                                 socket->expected_commands->data.connect.port);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    if (!retval) {
        socket->state = AVS_NET_SOCKET_STATE_CONNECTED;
    }
    return retval;
}

static void hexdumpify(char *out_buf,
                       size_t buf_size,
                       const uint8_t *data,
                       size_t data_size,
                       size_t bytes_per_segment,
                       size_t segments_per_row) {
    const size_t bytes_per_row = bytes_per_segment * segments_per_row;

    // bytes_per_row * 3 chars for hex segments (00 00)
    // + (segments_per_row - 1) extra spaces between hex segments (00 00  00 00)
    // + 1 extra space between hex segments and char segments
    // + bytes_per_row chars for char segments (xx)
    // + (segments_per_row - 1) extra spaces between char segments (xx xx)
    // + nullbyte at the end
    assert(buf_size >= bytes_per_row * 4 + segments_per_row * 2);

    char *at = out_buf;

    // hex segments: 00 00 00 00  00 00 00 00
    for (size_t seg = 0; seg < segments_per_row; ++seg) {
        for (size_t i = 0; i < bytes_per_segment; ++i) {
            size_t idx = seg * bytes_per_segment + i;
            size_t bytes_rem = (size_t)(buf_size - (size_t)(at - out_buf));

            if (idx < data_size) {
                snprintf(at, bytes_rem, "%02x ", data[idx]);
            } else {
                snprintf(at, bytes_rem, "   ");
            }

            at += 3;
        }
        *at++ = ' ';
    }

    // char segment: xxxx xxxx
    for (size_t seg = 0; seg < segments_per_row; ++seg) {
        for (size_t i = 0; i < bytes_per_segment; ++i) {
            size_t idx = seg * bytes_per_segment + i;
            size_t bytes_rem = (size_t)(buf_size - (size_t)(at - out_buf));

            if (idx < data_size) {
                snprintf(at, bytes_rem, isprint(data[idx]) ? "%c" : ".",
                         data[idx]);
            } else {
                snprintf(at, bytes_rem, " ");
            }

            at += 1;
        }
        *at++ = ' ';
    }

    // trailing space is useless
    *--at = '\0';
}


static void hexdump_data(const void *raw_data,
                         size_t data_size) {
    const uint8_t *data = (const uint8_t *) raw_data;
    const size_t bytes_per_segment = 8;
    const size_t segments_per_row = 2;
    const size_t bytes_per_row = bytes_per_segment * segments_per_row;

    size_t buffer_size = bytes_per_row * 4 + segments_per_row * 2;
    char *buffer = (char *) avs_malloc(buffer_size);
    AVS_UNIT_ASSERT_NOT_NULL(buffer);
    for (size_t offset = 0; offset < data_size; offset += bytes_per_row) {
        hexdumpify(buffer, buffer_size,
                   data + offset, data_size - offset,
                   bytes_per_segment, segments_per_row);
        LOG(TRACE, "%s", buffer);
    }

    avs_free(buffer);
}

static int mock_send_to(avs_net_abstract_socket_t *socket_,
                        const void *buffer,
                        size_t buffer_length,
                        const char *host,
                        const char *port) {
    LOG(TRACE, "mock_send_to: host <%s>, port <%s>, %zu bytes",
        host, port, buffer_length);
    hexdump_data(buffer, buffer_length);

    mocksock_t *socket = (mocksock_t *) socket_;
    AVS_UNIT_ASSERT_TRUE(socket->state == AVS_NET_SOCKET_STATE_BOUND
            || socket->state == AVS_NET_SOCKET_STATE_ACCEPTED
            || socket->state == AVS_NET_SOCKET_STATE_CONNECTED);
    while (buffer_length > 0) {
        AVS_UNIT_ASSERT_NOT_NULL(socket->expected_data);
        if (socket->expected_data->type == MOCKSOCK_DATA_TYPE_OUTPUT) {
            size_t to_send = socket->expected_data->args.valid.size
                             - socket->expected_data->args.valid.ptr;
            if (buffer_length < to_send) {
                to_send = buffer_length;
            }

            AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer,
                                              (const char*)socket->expected_data->args.valid.data
                                              + socket->expected_data->args.valid.ptr,
                                              to_send);
            AVS_UNIT_ASSERT_EQUAL_STRING(
                    host, socket->expected_data->args.valid.remote_host);
            AVS_UNIT_ASSERT_EQUAL_STRING(
                    port, socket->expected_data->args.valid.remote_port);
            socket->expected_data->args.valid.ptr += to_send;
            if (socket->expected_data->args.valid.ptr
                    == socket->expected_data->args.valid.size) {
                LOG(TRACE, "mock_send_to: item fully sent");
                avs_free((void*)(intptr_t)socket->expected_data->args.valid.data);
                AVS_LIST_DELETE(&socket->expected_data);
            } else {
                LOG(TRACE, "mock_send_to: partial send, %u/%u",
                    (unsigned) to_send,
                    (unsigned) socket->expected_data->args.valid.size);
            }
            buffer_length -= to_send;
            buffer = ((const char *) buffer) + to_send;
        } else if (socket->expected_data->type
                   == MOCKSOCK_DATA_TYPE_OUTPUT_FAIL) {
            int retval = socket->expected_data->args.retval;
            AVS_LIST_DELETE(&socket->expected_data);

            LOG(TRACE, "mock_send_to: failure, result == %d", retval);
            return retval;
        } else {
            AVS_UNIT_ASSERT_TRUE(!"mock_send_to: unexpected send");
        }
    }

    LOG(TRACE, "mock_send_to: sent %zu B", buffer_length);
    return 0;
}

static int mock_send(avs_net_abstract_socket_t *socket,
                     const void *buffer,
                     size_t buffer_length) {
    return mock_send_to(socket, buffer, buffer_length, NULL, NULL);
}

static void fill_remote_addr(char *out, size_t size, const char *in) {
    if (out) {
        AVS_UNIT_ASSERT_NOT_NULL(in);
        AVS_UNIT_ASSERT_TRUE(strlen(in) < size);
        strcpy(out, in);
    } else {
        AVS_UNIT_ASSERT_NULL(in);
    }
}

static int mock_receive_from(avs_net_abstract_socket_t *socket_,
                             size_t *out,
                             void *buffer,
                             size_t buffer_length,
                             char *out_host, size_t out_host_size,
                             char *out_port, size_t out_port_size) {
    LOG(TRACE, "mock_receive_from: buffer_length %zu", buffer_length);

    mocksock_t *socket = (mocksock_t *) socket_;
    int retval = 0;
    AVS_UNIT_ASSERT_TRUE(socket->state == AVS_NET_SOCKET_STATE_BOUND
            || socket->state == AVS_NET_SOCKET_STATE_ACCEPTED
            || socket->state == AVS_NET_SOCKET_STATE_CONNECTED);
    *out = 0;
    if (!socket->expected_data) {
        return 0;
    }
    if (socket->expected_data->type == MOCKSOCK_DATA_TYPE_INPUT) {
        *out = socket->expected_data->args.valid.size
               - socket->expected_data->args.valid.ptr;
        if (buffer_length < *out) {
            *out = buffer_length;
        }
        memcpy(buffer, (const char*)socket->expected_data->args.valid.data
               + socket->expected_data->args.valid.ptr, *out);
        socket->expected_data->args.valid.ptr += *out;
        fill_remote_addr(out_host, out_host_size,
                         socket->expected_data->args.valid.remote_host);
        fill_remote_addr(out_port, out_port_size,
                         socket->expected_data->args.valid.remote_port);
        if (socket->expected_data->args.valid.ptr
                == socket->expected_data->args.valid.size) {
            LOG(TRACE, "mock_receive_from: item fully received");
            socket->last_data_read = socket->expected_data->args.valid.ptr;
            avs_free((void*)(intptr_t)socket->expected_data->args.valid.data);
            AVS_LIST_DELETE(&socket->expected_data);
        } else {
            LOG(TRACE, "mock_receive_from: partial receive, %u/%u",
                (unsigned) *out,
                (unsigned) socket->expected_data->args.valid.size);

            if (socket->type == AVS_UNIT_MOCKSOCK_TYPE_DATAGRAM) {
                avs_free((void*)(intptr_t)socket->expected_data->args.valid.data);
                AVS_LIST_DELETE(&socket->expected_data);
                retval = -1;
            }
        }
    } else if (socket->expected_data->type
               == MOCKSOCK_DATA_TYPE_INPUT_FAIL) {
        retval = socket->expected_data->args.retval;
        AVS_LIST_DELETE(&socket->expected_data);

        LOG(TRACE, "mock_receive_from: failure, result = %d", retval);
        return retval;
    }

    LOG(TRACE, "mock_receive_from: recv %zu/%zu B, host <%s>, port <%s>",
        *out, buffer_length, out_host, out_port);
    hexdump_data(buffer, *out);
    return retval;
}

static int mock_receive(avs_net_abstract_socket_t *socket,
                        size_t *out,
                        void *buffer,
                        size_t buffer_length) {
    return mock_receive_from(socket, out, buffer, buffer_length,
                             NULL, 0, NULL, 0);
}

static int mock_bind(avs_net_abstract_socket_t *socket_,
                     const char *localaddr,
                     const char *port) {
    LOG(TRACE, "mock_bind: localaddr <%s>, port <%s>", localaddr, port);

    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands, MOCKSOCK_COMMAND_BIND);

    AVS_UNIT_ASSERT_TRUE(socket->state == AVS_NET_SOCKET_STATE_CLOSED);
    AVS_UNIT_ASSERT_EQUAL_STRING(localaddr,
                                 socket->expected_commands->data.bind.localaddr);
    AVS_UNIT_ASSERT_EQUAL_STRING(port,
                                 socket->expected_commands->data.bind.port);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    if (!retval) {
        socket->state = AVS_NET_SOCKET_STATE_BOUND;
    }
    return retval;
}

static int mock_accept(avs_net_abstract_socket_t *server_socket_,
                       avs_net_abstract_socket_t *new_socket_) {
    int retval = 0;
    mocksock_t *server_socket = (mocksock_t *) server_socket_;
    mocksock_t *new_socket = (mocksock_t *) new_socket_;

    assert_command_expected(server_socket->expected_commands,
            MOCKSOCK_COMMAND_ACCEPT);

    assert(server_socket->vtable == &mock_vtable);
    AVS_UNIT_ASSERT_TRUE(new_socket->vtable == &mock_vtable);

    AVS_UNIT_ASSERT_TRUE(
            server_socket->state == AVS_NET_SOCKET_STATE_BOUND);
    AVS_UNIT_ASSERT_TRUE(new_socket->state == AVS_NET_SOCKET_STATE_CLOSED);
    AVS_LIST_DELETE(&server_socket->expected_commands);
    retval = server_socket->expected_commands->retval;
    AVS_LIST_DELETE(&server_socket->expected_commands);
    if (!retval) {
        new_socket->state = AVS_NET_SOCKET_STATE_ACCEPTED;
    }
    return retval;
}

static int mock_close(avs_net_abstract_socket_t *socket_) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    if (socket->expected_commands) {
        assert_command_expected(socket->expected_commands,
                MOCKSOCK_COMMAND_MID_CLOSE);

        AVS_UNIT_ASSERT_TRUE(!socket->expected_data
                             || socket->expected_data->args.valid.ptr == 0);
        retval = socket->expected_commands->retval;
        AVS_LIST_DELETE(&socket->expected_commands);
    } else {
        AVS_UNIT_ASSERT_NULL(socket->expected_data);
    }
    socket->state = AVS_NET_SOCKET_STATE_CLOSED;
    return retval;
}

static int mock_cleanup(avs_net_abstract_socket_t **socket) {
    int retval = mock_close(*socket);
    avs_free(*socket);
    *socket = NULL;
    return retval;
}

static int mock_shutdown(avs_net_abstract_socket_t *socket_) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_SHUTDOWN);

    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    AVS_LIST_CLEAR(&socket->expected_data);
    socket->state = AVS_NET_SOCKET_STATE_SHUTDOWN;
    return retval;
}

static int mock_system_socket(avs_net_abstract_socket_t *socket_,
                              const void **out) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_SYSTEM_SOCKET);

    *out = socket->expected_commands->data.system_socket;
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_interface_name(avs_net_abstract_socket_t *socket_,
                               avs_net_socket_interface_name_t *if_name) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_INTERFACE_NAME);

    memcpy(*if_name, socket->expected_commands->data.if_name,
           sizeof(avs_net_socket_interface_name_t));
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_remote_host(avs_net_abstract_socket_t *socket_,
                            char *hostname, size_t hostname_size) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    if (socket->remote_host_enabled) {
        strncpy(hostname, socket->remote_host, hostname_size);
        return 0;
    }

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_REMOTE_HOST);

    strncpy(hostname,
            socket->expected_commands->data.host, hostname_size);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_remote_hostname(avs_net_abstract_socket_t *socket_,
                                char *hostname, size_t hostname_size) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_REMOTE_HOSTNAME);

    strncpy(hostname, socket->expected_commands->data.host, hostname_size);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_remote_port(avs_net_abstract_socket_t *socket_,
                            char *port, size_t port_size) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    if (socket->remote_port_enabled) {
        strncpy(port, socket->remote_port, port_size);
        return 0;
    }

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_REMOTE_PORT);

    strncpy(port, socket->expected_commands->data.port, port_size);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_local_host(avs_net_abstract_socket_t *socket_,
                           char *hostname, size_t hostname_size) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_LOCAL_HOST);

    strncpy(hostname, socket->expected_commands->data.host, hostname_size);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_local_port(avs_net_abstract_socket_t *socket_,
                           char *port, size_t port_size) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_LOCAL_PORT);

    strncpy(port, socket->expected_commands->data.port, port_size);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_get_opt(avs_net_abstract_socket_t *socket_,
                        avs_net_socket_opt_key_t option_key,
                        avs_net_socket_opt_value_t *out_option_value) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    if (socket->recv_timeout_enabled
            && option_key == AVS_NET_SOCKET_OPT_RECV_TIMEOUT) {
        out_option_value->recv_timeout = socket->recv_timeout;
        return 0;
    }

    if (socket->inner_mtu_enabled
            && option_key == AVS_NET_SOCKET_OPT_INNER_MTU) {
        out_option_value->mtu = socket->inner_mtu;
        return 0;
    }

    if (socket->mtu_enabled && option_key == AVS_NET_SOCKET_OPT_MTU) {
        out_option_value->mtu = socket->mtu;
        return 0;
    }

    if (socket->state_enabled
            && option_key == AVS_NET_SOCKET_OPT_STATE) {
        out_option_value->state = socket->state;
        return 0;
    }

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_GET_OPT);

    AVS_UNIT_ASSERT_EQUAL(socket->expected_commands->data.get_opt.key,
                          option_key);

    *out_option_value = socket->expected_commands->data.get_opt.value;
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_set_opt(avs_net_abstract_socket_t *socket_,
                        avs_net_socket_opt_key_t option_key,
                        avs_net_socket_opt_value_t option_value) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    if (socket->recv_timeout_enabled
            && option_key == AVS_NET_SOCKET_OPT_RECV_TIMEOUT) {
        socket->recv_timeout = option_value.recv_timeout;
        return 0;
    }

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_SET_OPT);

    AVS_UNIT_ASSERT_EQUAL(socket->expected_commands->data.set_opt.key, option_key);
    (void) option_value;

    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_errno(avs_net_abstract_socket_t *socket_) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;
    assert_command_expected(socket->expected_commands, MOCKSOCK_COMMAND_ERRNO);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

void avs_unit_mocksock_create__(avs_net_abstract_socket_t **socket_,
                                mocksock_type_t type,
                                const char *file,
                                int line) {
    static const avs_net_socket_v_table_t *const vtable_ptr = &mock_vtable;
    mocksock_t **socket = (mocksock_t **) socket_;
    *socket = (mocksock_t *) avs_calloc(1, sizeof(**socket));
    _avs_unit_assert(!!*socket, file, line, "out of memory\n");
    memcpy(*socket, &vtable_ptr, sizeof(vtable_ptr));
    (*socket)->type = type;
}

static mocksock_expected_data_t *new_expected_data(mocksock_t *socket,
                                                   const char *source_file,
                                                   int source_line) {
    mocksock_expected_data_t *new_data =
        AVS_LIST_NEW_ELEMENT(mocksock_expected_data_t);
    _avs_unit_assert(!!new_data, source_file, source_line, "out of memory\n");

    new_data->source_file = source_file;
    new_data->source_line = source_line;
    AVS_LIST_APPEND(&socket->expected_data, new_data);
    return new_data;
}

void avs_unit_mocksock_input_from__(avs_net_abstract_socket_t *socket_,
                                    const void *data,
                                    size_t length,
                                    const char *host,
                                    const char *port,
                                    const char *file,
                                    int line) {
    mocksock_t *socket = (mocksock_t *) socket_;
    mocksock_expected_data_t *new_data = new_expected_data(socket, file, line);
    new_data->type = MOCKSOCK_DATA_TYPE_INPUT;
    new_data->args.valid.remote_host = host;
    new_data->args.valid.remote_port = port;
    new_data->args.valid.data = avs_malloc(length);
    AVS_UNIT_ASSERT_NOT_NULL(new_data->args.valid.data);
    memcpy((void*)(intptr_t)new_data->args.valid.data, data, length);
    new_data->args.valid.ptr = 0;
    new_data->args.valid.size = length;
}

void avs_unit_mocksock_input__(avs_net_abstract_socket_t *socket,
                               const void *data,
                               size_t length,
                               const char *file,
                               int line) {
    avs_unit_mocksock_input_from__(socket, data, length, NULL, NULL,
                                   file, line);
}

void avs_unit_mocksock_input_fail__(avs_net_abstract_socket_t *socket_,
                                    int retval,
                                    const char *file,
                                    int line) {
    mocksock_t *socket = (mocksock_t *) socket_;
    mocksock_expected_data_t *new_data = new_expected_data(socket, file, line);
    new_data->type = MOCKSOCK_DATA_TYPE_INPUT_FAIL;
    new_data->args.retval = retval;
}

size_t avs_unit_mocksock_data_read(avs_net_abstract_socket_t *socket_) {
    mocksock_t *socket = (mocksock_t *) socket_;
    if (socket->expected_data
            && socket->expected_data->type == MOCKSOCK_DATA_TYPE_INPUT) {
        return socket->expected_data->args.valid.ptr;
    } else {
        return socket->last_data_read;
    }
}

void avs_unit_mocksock_expect_output_to__(avs_net_abstract_socket_t *socket_,
                                          const void *expect, size_t length,
                                          const char *host, const char *port,
                                          const char *file, int line) {
    LOG(TRACE, "expect_output: %zuB", length);
    hexdump_data(expect, length);

    mocksock_t *socket = (mocksock_t *) socket_;
    mocksock_expected_data_t *new_data = new_expected_data(socket, file, line);
    new_data->type = MOCKSOCK_DATA_TYPE_OUTPUT;
    new_data->args.valid.remote_host = host;
    new_data->args.valid.remote_port = port;
    new_data->args.valid.data = avs_malloc(length);
    AVS_UNIT_ASSERT_NOT_NULL(new_data->args.valid.data);
    memcpy((void*)(intptr_t)new_data->args.valid.data, expect, length);
    new_data->args.valid.ptr = 0;
    new_data->args.valid.size = length;
}

void avs_unit_mocksock_expect_output__(avs_net_abstract_socket_t *socket,
                                       const void *expect, size_t length,
                                       const char *file, int line) {
    avs_unit_mocksock_expect_output_to__(socket, expect, length, NULL, NULL,
                                         file, line);
}

void avs_unit_mocksock_output_fail__(avs_net_abstract_socket_t *socket_,
                                     int retval,
                                     const char *file,
                                     int line) {
    mocksock_t *socket = (mocksock_t *) socket_;
    mocksock_expected_data_t *new_data = new_expected_data(socket, file, line);
    new_data->type = MOCKSOCK_DATA_TYPE_OUTPUT_FAIL;
    new_data->args.retval = retval;
}

void avs_unit_mocksock_assert_io_clean__(avs_net_abstract_socket_t *socket_,
                                         const char *file,
                                         int line) {
    mocksock_t *socket = (mocksock_t *) socket_;

    if (socket->expected_data) {
        AVS_LIST(mocksock_expected_data_t) expected;
        _avs_unit_test_fail_printf(file, line,
                                   "expected more I/O operations:\n");

        AVS_LIST_FOREACH(expected, socket->expected_data) {
            if (data_has_size(expected)) {
                _avs_unit_test_fail_printf(file, line,
                                           "- %s (%u bytes) from %s:%d\n",
                                           data_type_to_string(expected->type),
                                           (unsigned)expected->args.valid.size,
                                           expected->source_file,
                                           expected->source_line);
            } else {
                _avs_unit_test_fail_printf(file, line, "- %s from %s:%d\n",
                                           data_type_to_string(expected->type),
                                           expected->source_file,
                                           expected->source_line);
            }
        }

        _avs_unit_assert(0, file, line, "\n");
    }
}

static mocksock_expected_command_t
*new_expected_command(avs_net_abstract_socket_t *socket,
                      const char *source_file,
                      int source_line) {
    mocksock_expected_command_t *new_command =
        AVS_LIST_NEW_ELEMENT(mocksock_expected_command_t);
    _avs_unit_assert(!!new_command, source_file, source_line,
                     "out of memory\n");
    AVS_LIST_APPEND(&((mocksock_t *) socket)->expected_commands,
                    new_command);
    new_command->source_file = source_file;
    new_command->source_line = source_line;
    return new_command;
}

void avs_unit_mocksock_expect_connect__(avs_net_abstract_socket_t *socket,
                                        const char *host, const char *port,
                                        const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_CONNECT;
    command->data.connect.host = host;
    command->data.connect.port = port;
}

void avs_unit_mocksock_expect_bind__(avs_net_abstract_socket_t *socket,
                                     const char *localaddr, const char *port,
                                     const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_BIND;
    command->data.bind.localaddr = localaddr;
    command->data.bind.port = port;
}

void avs_unit_mocksock_expect_accept__(avs_net_abstract_socket_t *socket,
                                       const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_ACCEPT;
}

void avs_unit_mocksock_expect_mid_close__(avs_net_abstract_socket_t *socket,
                                          const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_MID_CLOSE;
}

void avs_unit_mocksock_expect_shutdown__(avs_net_abstract_socket_t *socket,
                                         const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_SHUTDOWN;
}

void avs_unit_mocksock_expect_system_socket__(avs_net_abstract_socket_t *socket,
                                              const void *to_return,
                                              const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_SYSTEM_SOCKET;
    command->data.system_socket = to_return;
}

void avs_unit_mocksock_expect_interface_name__(
        avs_net_abstract_socket_t *socket,
        const avs_net_socket_interface_name_t *to_return,
        const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_INTERFACE_NAME;
    memcpy(command->data.if_name, *to_return,
           sizeof(avs_net_socket_interface_name_t));
}

void avs_unit_mocksock_expect_remote_host__(avs_net_abstract_socket_t *socket,
                                            const char *to_return,
                                            const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_REMOTE_HOST;
    command->data.host = to_return;
}

void
avs_unit_mocksock_expect_remote_hostname__(avs_net_abstract_socket_t *socket,
                                           const char *to_return,
                                           const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_REMOTE_HOSTNAME;
    command->data.host = to_return;
}

void avs_unit_mocksock_expect_remote_port__(avs_net_abstract_socket_t *socket,
                                            const char *to_return,
                                            const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_REMOTE_PORT;
    command->data.port = to_return;
}

void avs_unit_mocksock_expect_local_host__(avs_net_abstract_socket_t *socket,
                                           const char *to_return,
                                           const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_LOCAL_HOST;
    command->data.host = to_return;
}

void avs_unit_mocksock_expect_local_port__(avs_net_abstract_socket_t *socket,
                                           const char *to_return,
                                           const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_LOCAL_PORT;
    command->data.port = to_return;
}

void avs_unit_mocksock_expect_get_opt__(avs_net_abstract_socket_t *socket,
                                        avs_net_socket_opt_key_t key,
                                        avs_net_socket_opt_value_t resp_value,
                                        const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_GET_OPT;
    command->data.get_opt.key = key;
    command->data.get_opt.value = resp_value;
}

void avs_unit_mocksock_expect_set_opt__(avs_net_abstract_socket_t *socket,
                                        avs_net_socket_opt_key_t key,
                                        const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_SET_OPT;
    command->data.set_opt.key = key;
}

void avs_unit_mocksock_expect_errno__(avs_net_abstract_socket_t *socket,
                                      int to_return,
                                      const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_ERRNO;
    command->retval = to_return;
}

void avs_unit_mocksock_fail_command__(avs_net_abstract_socket_t *socket,
                                      const char *file,
                                      int line) {
    mocksock_expected_command_t *command = (mocksock_expected_command_t *)
        AVS_LIST_TAIL(((mocksock_t *) socket)->expected_commands);
    _avs_unit_assert(command != NULL, file, line, "no command to fail\n");
    command->retval = -1;
}

void avs_unit_mocksock_assert_expects_met__(avs_net_abstract_socket_t *socket_,
                                            const char *file, int line) {
    mocksock_t *socket = (mocksock_t *) socket_;

    if (socket->expected_commands) {
        AVS_LIST(mocksock_expected_command_t) expected;
        _avs_unit_test_fail_printf(file, line, "expects not met\n");

        AVS_LIST_FOREACH(expected, socket->expected_commands) {
            _avs_unit_test_fail_printf(file, line, "- %s from %s:%d\n",
                                       cmd_to_string(expected),
                                       expected->source_file,
                                       expected->source_line);
        }

        _avs_unit_assert(0, file, line, "\n");
    }
}

/* -------------------------------------------------------------------------- */

void avs_unit_mocksock_enable_recv_timeout_getsetopt(
        avs_net_abstract_socket_t *socket_,
        avs_time_duration_t default_timeout) {
    mocksock_t *socket = (mocksock_t *) socket_;
    socket->recv_timeout_enabled = true;
    socket->recv_timeout = default_timeout;
}

void avs_unit_mocksock_enable_inner_mtu_getopt(
        avs_net_abstract_socket_t *socket_,
        int inner_mtu) {
    mocksock_t *socket = (mocksock_t *) socket_;
    socket->inner_mtu_enabled = true;
    socket->inner_mtu = inner_mtu;
}

void avs_unit_mocksock_enable_mtu_getopt(
        avs_net_abstract_socket_t *socket_,
        int mtu) {
    mocksock_t *socket = (mocksock_t *) socket_;
    socket->mtu_enabled = true;
    socket->mtu = mtu;
}

void avs_unit_mocksock_enable_state_getopt(avs_net_abstract_socket_t *socket) {
    ((mocksock_t *) socket)->state_enabled = true;
}

void avs_unit_mocksock_enable_remote_host(avs_net_abstract_socket_t *socket_,
                                          const char *remote_host) {
    mocksock_t *socket = (mocksock_t *) socket_;
    socket->remote_host_enabled = true;
    socket->remote_host = remote_host;
}

void avs_unit_mocksock_enable_remote_port(avs_net_abstract_socket_t *socket_,
                                          const char *remote_port) {
    mocksock_t *socket = (mocksock_t *) socket_;
    socket->remote_port_enabled = true;
    socket->remote_port = remote_port;
}
