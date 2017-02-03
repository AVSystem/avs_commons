/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <string.h>

#include <avsystem/commons/list.h>
#include <avsystem/commons/net.h>
#include <avsystem/commons/socket_v_table.h>
#include <avsystem/commons/unit/mocksock.h>
#include <avsystem/commons/unit/test.h>

#include "test.h"

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
    MOCKSOCK_COMMAND_REMOTE_HOST,
    MOCKSOCK_COMMAND_REMOTE_PORT,
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
        const char *remote_host;
        const char *remote_port;
        mocksock_expected_get_opt_t get_opt;
        mocksock_expected_set_opt_t set_opt;
    } data;
    int retval;
} mocksock_expected_command_t;

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
    case MOCKSOCK_COMMAND_REMOTE_HOST:
        return "remote_host";
    case MOCKSOCK_COMMAND_REMOTE_PORT:
        return "remote_port";
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
            const char *data;
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
    int connected;
    AVS_LIST(mocksock_expected_command_t) expected_commands;
    AVS_LIST(mocksock_expected_data_t) expected_data;
    size_t last_data_read;

    char recv_timeout_enabled;
    int recv_timeout_ms;

    char inner_mtu_enabled;
    int inner_mtu;
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
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
                            MOCKSOCK_COMMAND_CONNECT);

    AVS_UNIT_ASSERT_FALSE(socket->connected);
    AVS_UNIT_ASSERT_EQUAL_STRING(host,
                                 socket->expected_commands->data.connect.host);
    AVS_UNIT_ASSERT_EQUAL_STRING(port,
                                 socket->expected_commands->data.connect.port);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    if (!retval) {
        socket->connected = 1;
    }
    return retval;
}

static int mock_send_to(avs_net_abstract_socket_t *socket_,
                        size_t *out_bytes_sent,
                        const void *buffer,
                        size_t buffer_length,
                        const char *host,
                        const char *port) {
    mocksock_t *socket = (mocksock_t *) socket_;
    AVS_UNIT_ASSERT_TRUE(socket->connected);
    *out_bytes_sent = 0;
    while (buffer_length > 0) {
        AVS_UNIT_ASSERT_NOT_NULL(socket->expected_data);
        if (socket->expected_data->type == MOCKSOCK_DATA_TYPE_OUTPUT) {
            size_t to_send = socket->expected_data->args.valid.size
                             - socket->expected_data->args.valid.ptr;
            if (buffer_length < to_send) {
                to_send = buffer_length;
            }
            AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buffer,
                                              socket->expected_data->args.valid.data
                                              + socket->expected_data->args.valid.ptr,
                                              to_send);
            AVS_UNIT_ASSERT_EQUAL_STRING(
                    host, socket->expected_data->args.valid.remote_host);
            AVS_UNIT_ASSERT_EQUAL_STRING(
                    port, socket->expected_data->args.valid.remote_port);
            socket->expected_data->args.valid.ptr += to_send;
            if (socket->expected_data->args.valid.ptr
                    == socket->expected_data->args.valid.size) {
                AVS_LIST_DELETE(&socket->expected_data);
            }
            buffer_length -= to_send;
            buffer = ((const char *) buffer) + to_send;
            *out_bytes_sent += to_send;
        } else if (socket->expected_data->type
                   == MOCKSOCK_DATA_TYPE_OUTPUT_FAIL) {
            int retval = socket->expected_data->args.retval;
            AVS_LIST_DELETE(&socket->expected_data);
            return retval;
        }
    }
    return 0;
}

static int mock_send(avs_net_abstract_socket_t *socket,
                     const void *buffer,
                     size_t buffer_length) {
    size_t tmp_bytes_sent;
    return mock_send_to(socket, &tmp_bytes_sent, buffer, buffer_length,
                        NULL, NULL);
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
    mocksock_t *socket = (mocksock_t *) socket_;
    AVS_UNIT_ASSERT_TRUE(socket->connected);
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
        memcpy(buffer, socket->expected_data->args.valid.data
               + socket->expected_data->args.valid.ptr, *out);
        socket->expected_data->args.valid.ptr += *out;
        fill_remote_addr(out_host, out_host_size,
                         socket->expected_data->args.valid.remote_host);
        fill_remote_addr(out_port, out_port_size,
                         socket->expected_data->args.valid.remote_port);
        if (socket->expected_data->args.valid.ptr
                == socket->expected_data->args.valid.size) {
            socket->last_data_read = socket->expected_data->args.valid.ptr;
            AVS_LIST_DELETE(&socket->expected_data);
        }
    } else if (socket->expected_data->type
               == MOCKSOCK_DATA_TYPE_INPUT_FAIL) {
        int retval = socket->expected_data->args.retval;
        AVS_LIST_DELETE(&socket->expected_data);
        return retval;
    }
    return 0;
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
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands, MOCKSOCK_COMMAND_BIND);

    AVS_UNIT_ASSERT_FALSE(socket->connected);
    AVS_UNIT_ASSERT_EQUAL_STRING(localaddr,
                                 socket->expected_commands->data.bind.localaddr);
    AVS_UNIT_ASSERT_EQUAL_STRING(port,
                                 socket->expected_commands->data.bind.port);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    if (!retval) {
        socket->connected = 1;
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

    AVS_UNIT_ASSERT_TRUE(server_socket->connected);
    AVS_UNIT_ASSERT_FALSE(new_socket->connected);
    AVS_LIST_DELETE(&server_socket->expected_commands);
    retval = server_socket->expected_commands->retval;
    AVS_LIST_DELETE(&server_socket->expected_commands);
    if (!retval) {
        new_socket->connected = 1;
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
    socket->connected = 0;
    return retval;
}

static int mock_cleanup(avs_net_abstract_socket_t **socket) {
    int retval = mock_close(*socket);
    free(*socket);
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
    socket->connected = 0;
    return retval;
}

static int mock_remote_host(avs_net_abstract_socket_t *socket_,
                            char *hostname, size_t hostname_size) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_REMOTE_HOST);

    strncpy(hostname,
            socket->expected_commands->data.remote_host, hostname_size);
    retval = socket->expected_commands->retval;
    AVS_LIST_DELETE(&socket->expected_commands);
    return retval;
}

static int mock_remote_port(avs_net_abstract_socket_t *socket_,
                            char *port, size_t port_size) {
    int retval = 0;
    mocksock_t *socket = (mocksock_t *) socket_;

    assert_command_expected(socket->expected_commands,
            MOCKSOCK_COMMAND_REMOTE_PORT);

    strncpy(port, socket->expected_commands->data.remote_port, port_size);
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
        out_option_value->recv_timeout = socket->recv_timeout_ms;
        return 0;
    }

    if (socket->inner_mtu_enabled
            && option_key == AVS_NET_SOCKET_OPT_INNER_MTU) {
        out_option_value->mtu = socket->inner_mtu;
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
        socket->recv_timeout_ms = option_value.recv_timeout;
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
    (avs_net_socket_get_system_t) unimplemented,
    (avs_net_socket_get_interface_t) unimplemented,
    mock_remote_host,
    mock_remote_port,
    (avs_net_socket_get_local_port_t) unimplemented,
    mock_get_opt,
    mock_set_opt,
    mock_errno
};

void avs_unit_mocksock_create__(avs_net_abstract_socket_t **socket_,
                                const char *file,
                                int line) {
    static const avs_net_socket_v_table_t *const vtable_ptr = &mock_vtable;
    mocksock_t **socket = (mocksock_t **) socket_;
    *socket = (mocksock_t *) calloc(1, sizeof(**socket));
    _avs_unit_assert(!!*socket, file, line, "out of memory\n");
    memcpy(*socket, &vtable_ptr, sizeof(vtable_ptr));
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
                                    const char *data,
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
    new_data->args.valid.data = data;
    new_data->args.valid.ptr = 0;
    new_data->args.valid.size = length;
}

void avs_unit_mocksock_input__(avs_net_abstract_socket_t *socket,
                               const char *data,
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
                                          const char *expect, size_t length,
                                          const char *host, const char *port,
                                          const char *file, int line) {
    mocksock_t *socket = (mocksock_t *) socket_;
    mocksock_expected_data_t *new_data = new_expected_data(socket, file, line);
    new_data->type = MOCKSOCK_DATA_TYPE_OUTPUT;
    new_data->args.valid.remote_host = host;
    new_data->args.valid.remote_port = port;
    new_data->args.valid.data = expect;
    new_data->args.valid.ptr = 0;
    new_data->args.valid.size = length;
}

void avs_unit_mocksock_expect_output__(avs_net_abstract_socket_t *socket,
                                       const char *expect, size_t length,
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

void avs_unit_mocksock_expect_remote_host__(avs_net_abstract_socket_t *socket,
                                            const char *to_return,
                                            const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_REMOTE_HOST;
    command->data.remote_host = to_return;
}

void avs_unit_mocksock_expect_remote_port__(avs_net_abstract_socket_t *socket,
                                            const char *to_return,
                                            const char *file, int line) {
    mocksock_expected_command_t *command = new_expected_command(socket,
                                                                file, line);
    command->command = MOCKSOCK_COMMAND_REMOTE_PORT;
    command->data.remote_port = to_return;
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
    mocksock_expected_command_t *command =
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
        int default_timeout_ms) {
    mocksock_t *socket = (mocksock_t *) socket_;
    socket->recv_timeout_enabled = 1;
    socket->recv_timeout_ms = default_timeout_ms;
}

void avs_unit_mocksock_enable_inner_mtu_getopt(
        avs_net_abstract_socket_t *socket_,
        int inner_mtu) {
    mocksock_t *socket = (mocksock_t *) socket_;
    socket->inner_mtu_enabled = 1;
    socket->inner_mtu = inner_mtu;
}
