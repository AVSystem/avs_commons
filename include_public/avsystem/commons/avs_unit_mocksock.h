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

#ifndef AVS_COMMONS_UNIT_MOCKSOCK_H
#define AVS_COMMONS_UNIT_MOCKSOCK_H

#include <avsystem/commons/avs_net.h>
#include <avsystem/commons/avs_time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AVS_UNIT_MOCKSOCK_TYPE_STREAMING,
    AVS_UNIT_MOCKSOCK_TYPE_DATAGRAM
} mocksock_type_t;

typedef void mocksock_and_then_callback_t(avs_net_socket_t *socket, void *arg);

typedef struct {
    const char *file;
    int line;
    mocksock_and_then_callback_t *and_then;
    void *and_then_arg;
} mocksock_additional_args_t;

size_t avs_unit_mocksock_data_read(avs_net_socket_t *socket);

void avs_unit_mocksock_create__(avs_net_socket_t **socket,
                                mocksock_type_t type,
                                const char *file,
                                int line);
#define avs_unit_mocksock_create(Socket) \
    avs_unit_mocksock_create__(          \
            (Socket), AVS_UNIT_MOCKSOCK_TYPE_STREAMING, __FILE__, __LINE__)

#define avs_unit_mocksock_create_datagram(Socket) \
    avs_unit_mocksock_create__(                   \
            (Socket), AVS_UNIT_MOCKSOCK_TYPE_DATAGRAM, __FILE__, __LINE__)

void avs_unit_mocksock_input__(avs_net_socket_t *socket,
                               const void *data,
                               size_t length,
                               const mocksock_additional_args_t *args);
#define avs_unit_mocksock_input(Socket, Data, /* Length, */...) \
    avs_unit_mocksock_input__(                                  \
            (Socket),                                           \
            (Data),                                             \
            (AVS_VARARG0(__VA_ARGS__)),                         \
            &(const mocksock_additional_args_t) {               \
                .file = __FILE__,                               \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)   \
            })

void avs_unit_mocksock_input_from__(avs_net_socket_t *socket_,
                                    const void *data,
                                    size_t length,
                                    const char *host,
                                    const char *port,
                                    const mocksock_additional_args_t *args);
#define avs_unit_mocksock_input_from(                         \
        Socket, Data, Length, Host, /* Port, */...)           \
    avs_unit_mocksock_input_from__(                           \
            (Socket),                                         \
            (Data),                                           \
            (Length),                                         \
            (Host),                                           \
            (AVS_VARARG0(__VA_ARGS__)),                       \
            &(const mocksock_additional_args_t) {             \
                .file = __FILE__,                             \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__) \
            })

void avs_unit_mocksock_input_fail__(avs_net_socket_t *socket_,
                                    avs_error_t retval,
                                    const mocksock_additional_args_t *args);
#define avs_unit_mocksock_input_fail(Socket, /* Retval, */...) \
    avs_unit_mocksock_input_fail__(                            \
            (Socket),                                          \
            (AVS_VARARG0(__VA_ARGS__)),                        \
            &(const mocksock_additional_args_t) {              \
                .file = __FILE__,                              \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)  \
            })

void avs_unit_mocksock_output_fail__(avs_net_socket_t *socket_,
                                     avs_error_t retval,
                                     const mocksock_additional_args_t *args);
#define avs_unit_mocksock_output_fail(Socket, /* Retval, */...) \
    avs_unit_mocksock_output_fail__(                            \
            (Socket),                                           \
            (AVS_VARARG0(__VA_ARGS__)),                         \
            &(const mocksock_additional_args_t) {               \
                .file = __FILE__,                               \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)   \
            })

void avs_unit_mocksock_fail_command__(avs_net_socket_t *socket,
                                      avs_error_t retval,
                                      const char *file,
                                      int line);
#define avs_unit_mocksock_fail_command(Socket, Retval) \
    avs_unit_mocksock_fail_command__((Socket), (Retval), __FILE__, __LINE__)

void avs_unit_mocksock_expect_output__(avs_net_socket_t *socket,
                                       const void *expect,
                                       size_t length,
                                       const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_output(Socket, Expect, /* Length, */...) \
    avs_unit_mocksock_expect_output__(                                    \
            (Socket),                                                     \
            (Expect),                                                     \
            (AVS_VARARG0(__VA_ARGS__)),                                   \
            &(const mocksock_additional_args_t) {                         \
                .file = __FILE__,                                         \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)             \
            })

void avs_unit_mocksock_expect_output_to__(
        avs_net_socket_t *socket_,
        const void *expect,
        size_t length,
        const char *host,
        const char *port,
        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_output_to(                   \
        Socket, Expect, Length, Host, /* Port, */...)         \
    avs_unit_mocksock_expect_output_to__(                     \
            (Socket),                                         \
            (Expect),                                         \
            (Length),                                         \
            (Host),                                           \
            (AVS_VARARG0(__VA_ARGS__)),                       \
            &(const mocksock_additional_args_t) {             \
                .file = __FILE__,                             \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__) \
            })

void avs_unit_mocksock_assert_io_clean__(avs_net_socket_t *socket,
                                         const char *file,
                                         int line);
#define avs_unit_mocksock_assert_io_clean(Socket) \
    avs_unit_mocksock_assert_io_clean__((Socket), __FILE__, __LINE__)

void avs_unit_mocksock_expect_connect__(avs_net_socket_t *socket,
                                        const char *host,
                                        const char *port,
                                        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_connect(Socket, Host, /* Port, */...) \
    avs_unit_mocksock_expect_connect__(                                \
            (Socket),                                                  \
            (Host),                                                    \
            (AVS_VARARG0(__VA_ARGS__)),                                \
            &(const mocksock_additional_args_t) {                      \
                .file = __FILE__,                                      \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)          \
            })

void avs_unit_mocksock_expect_bind__(avs_net_socket_t *socket,
                                     const char *localaddr,
                                     const char *port,
                                     const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_bind(Socket, LocalAddr, /* Port, */...) \
    avs_unit_mocksock_expect_bind__(                                     \
            (Socket),                                                    \
            (LocalAddr),                                                 \
            (AVS_VARARG0(__VA_ARGS__)),                                  \
            &(const mocksock_additional_args_t) {                        \
                .file = __FILE__,                                        \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)            \
            })

void avs_unit_mocksock_expect_accept__(avs_net_socket_t *socket,
                                       const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_accept(/* Socket, */...)     \
    avs_unit_mocksock_expect_accept__(                        \
            (AVS_VARARG0(__VA_ARGS__)),                       \
            &(const mocksock_additional_args_t) {             \
                .file = __FILE__,                             \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__) \
            })

void avs_unit_mocksock_expect_mid_close__(
        avs_net_socket_t *socket, const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_mid_close(/* Socket, */...)  \
    avs_unit_mocksock_expect_mid_close__(                     \
            (AVS_VARARG0(__VA_ARGS__)),                       \
            &(const mocksock_additional_args_t) {             \
                .file = __FILE__,                             \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__) \
            })

void avs_unit_mocksock_expect_shutdown__(
        avs_net_socket_t *socket, const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_shutdown(/* Socket, */...)   \
    avs_unit_mocksock_expect_shutdown__(                      \
            (AVS_VARARG0(__VA_ARGS__)),                       \
            &(const mocksock_additional_args_t) {             \
                .file = __FILE__,                             \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__) \
            })

void avs_unit_mocksock_expect_system_socket__(
        avs_net_socket_t *socket,
        const void *to_return,
        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_system_socket(Socket, /* ToReturn, */...) \
    avs_unit_mocksock_expect_system_socket__(                              \
            (Socket),                                                      \
            (AVS_VARARG0(__VA_ARGS__)),                                    \
            &(const mocksock_additional_args_t) {                          \
                .file = __FILE__,                                          \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)              \
            })

void avs_unit_mocksock_expect_interface_name__(
        avs_net_socket_t *socket,
        const avs_net_socket_interface_name_t *to_return,
        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_interface_name(Socket, /* ToReturn, */...) \
    avs_unit_mocksock_expect_interface_name__(                              \
            (Socket),                                                       \
            (AVS_VARARG0(__VA_ARGS__)),                                     \
            &(const mocksock_additional_args_t) {                           \
                .file = __FILE__,                                           \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)               \
            })

void avs_unit_mocksock_expect_remote_host__(
        avs_net_socket_t *socket,
        const char *to_return,
        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_remote_host(Socket, /* ToReturn, */...) \
    avs_unit_mocksock_expect_remote_host__(                              \
            (Socket),                                                    \
            (AVS_VARARG0(__VA_ARGS__)),                                  \
            &(const mocksock_additional_args_t) {                        \
                .file = __FILE__,                                        \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)            \
            })

void avs_unit_mocksock_expect_remote_hostname__(
        avs_net_socket_t *socket,
        const char *to_return,
        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_remote_hostname(Socket, /* ToReturn, */...) \
    avs_unit_mocksock_expect_remote_hostname__(                              \
            (Socket),                                                        \
            (AVS_VARARG0(__VA_ARGS__)),                                      \
            &(const mocksock_additional_args_t) {                            \
                .file = __FILE__,                                            \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)                \
            })

void avs_unit_mocksock_expect_remote_port__(
        avs_net_socket_t *socket,
        const char *to_return,
        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_remote_port(Socket, /* ToReturn, */...) \
    avs_unit_mocksock_expect_remote_port__(                              \
            (Socket),                                                    \
            (AVS_VARARG0(__VA_ARGS__)),                                  \
            &(const mocksock_additional_args_t) {                        \
                .file = __FILE__,                                        \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)            \
            })

void avs_unit_mocksock_expect_local_host__(
        avs_net_socket_t *socket,
        const char *to_return,
        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_local_host(Socket, /* ToReturn, */...) \
    avs_unit_mocksock_expect_local_host__(                              \
            (Socket),                                                   \
            (AVS_VARARG0(__VA_ARGS__)),                                 \
            &(const mocksock_additional_args_t) {                       \
                .file = __FILE__,                                       \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)           \
            })

void avs_unit_mocksock_expect_local_port__(
        avs_net_socket_t *socket,
        const char *to_return,
        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_local_port(Socket, /* ToReturn, */...) \
    avs_unit_mocksock_expect_local_port__(                              \
            (Socket),                                                   \
            (AVS_VARARG0(__VA_ARGS__)),                                 \
            &(const mocksock_additional_args_t) {                       \
                .file = __FILE__,                                       \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)           \
            })

void avs_unit_mocksock_expect_get_opt__(avs_net_socket_t *socket,
                                        avs_net_socket_opt_key_t key,
                                        avs_net_socket_opt_value_t resp_value,
                                        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_get_opt(Socket, Key, /* RespValue, */...) \
    avs_unit_mocksock_expect_get_opt__(                                    \
            (Socket),                                                      \
            (Key),                                                         \
            (AVS_VARARG0(__VA_ARGS__)),                                    \
            &(const mocksock_additional_args_t) {                          \
                .file = __FILE__,                                          \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)              \
            })

void avs_unit_mocksock_expect_set_opt__(avs_net_socket_t *socket,
                                        avs_net_socket_opt_key_t key,
                                        const mocksock_additional_args_t *args);
#define avs_unit_mocksock_expect_set_opt(Socket, /* Key, */...) \
    avs_unit_mocksock_expect_set_opt__(                         \
            (Socket),                                           \
            (AVS_VARARG0(__VA_ARGS__)),                         \
            &(const mocksock_additional_args_t) {               \
                .file = __FILE__,                               \
                .line = __LINE__ AVS_VARARG_REST(__VA_ARGS__)   \
            })

void avs_unit_mocksock_assert_expects_met__(avs_net_socket_t *socket_,
                                            const char *file,
                                            int line);
#define avs_unit_mocksock_assert_expects_met(Socket) \
    avs_unit_mocksock_assert_expects_met__((Socket), __FILE__, __LINE__);

void avs_unit_mocksock_enable_recv_timeout_getsetopt(
        avs_net_socket_t *socket_, avs_time_duration_t default_timeout);

void avs_unit_mocksock_enable_inner_mtu_getopt(avs_net_socket_t *socket_,
                                               int inner_mtu);

void avs_unit_mocksock_enable_mtu_getopt(avs_net_socket_t *socket_, int mtu);

void avs_unit_mocksock_enable_state_getopt(avs_net_socket_t *socket);

void avs_unit_mocksock_enable_remote_host(avs_net_socket_t *socket_,
                                          const char *remote_host);

void avs_unit_mocksock_enable_remote_port(avs_net_socket_t *socket_,
                                          const char *remote_port);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_UNIT_MOCKSOCK_H */
