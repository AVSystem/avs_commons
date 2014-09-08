/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef V_TABLE_H
#define V_TABLE_H

#include <avsystem/commons/net.h>

typedef int (*avs_net_socket_connect_t)(avs_net_abstract_socket_t *socket,
                                        const char *host,
                                        const char *port);
typedef int (*avs_net_socket_decorate_t)(avs_net_abstract_socket_t *socket,
                                         avs_net_abstract_socket_t *backend_socket);
typedef int (*avs_net_socket_send_t)(avs_net_abstract_socket_t *socket,
                                     const void *buffer,
                                     size_t buffer_length);
typedef int (*avs_net_socket_send_to_t)(avs_net_abstract_socket_t *socket,
                                        size_t *out_bytes_sent,
                                        const void *buffer,
                                        size_t buffer_length,
                                        const char *host,
                                        const char *port);
typedef int (*avs_net_socket_receive_t)(avs_net_abstract_socket_t *socket,
                                        size_t *out_bytes_received,
                                        void *buffer,
                                        size_t buffer_length);
typedef int (*avs_net_socket_receive_from_t)(avs_net_abstract_socket_t *socket,
                                             size_t *out_bytes_received,
                                             void *buffer,
                                             size_t buffer_length,
                                             char *host, size_t host_size,
                                             char *port, size_t port_size);
typedef int (*avs_net_socket_bind_t)(avs_net_abstract_socket_t *socket,
                                     const char *address,
                                     const char *port);
typedef int (*avs_net_socket_accept_t)(avs_net_abstract_socket_t *server_socket,
                                       avs_net_abstract_socket_t *new_socket);
typedef int (*avs_net_socket_close_t)(avs_net_abstract_socket_t *socket);
typedef int (*avs_net_socket_shutdown_t)(avs_net_abstract_socket_t *socket);
typedef int (*avs_net_socket_connected_t)(avs_net_abstract_socket_t *socket);
typedef int (*avs_net_socket_cleanup_t)(avs_net_abstract_socket_t **socket);

typedef int (*avs_net_socket_get_system_t)(avs_net_abstract_socket_t *socket,
                                           const void **out);

typedef
int (*avs_net_socket_get_interface_t)(avs_net_abstract_socket_t *socket,
                                      avs_net_socket_interface_name_t *if_name);

typedef
int (*avs_net_socket_get_remote_host_t)(avs_net_abstract_socket_t *socket,
                                        char *out_buffer, size_t out_buffer_size);

typedef
int (*avs_net_socket_get_remote_port_t)(avs_net_abstract_socket_t *socket,
                                        char *out_buffer, size_t out_buffer_size);

typedef
int (*avs_net_socket_get_local_port_t)(avs_net_abstract_socket_t *socket,
                                       char *out_buffer, size_t out_buffer_size);

typedef int (*avs_net_socket_get_opt_t)(avs_net_abstract_socket_t *socket,
                                        avs_net_socket_opt_key_t option_key,
                                        avs_net_socket_opt_value_t *out_option_value);

typedef int (*avs_net_socket_set_opt_t)(avs_net_abstract_socket_t *socket,
                                        avs_net_socket_opt_key_t option_key,
                                        avs_net_socket_opt_value_t option_value);

typedef struct {
    avs_net_socket_connect_t connect;
    avs_net_socket_decorate_t decorate;
    avs_net_socket_send_t send;
    avs_net_socket_send_to_t send_to;
    avs_net_socket_receive_t receive;
    avs_net_socket_receive_from_t receive_from;
    avs_net_socket_bind_t bind;
    avs_net_socket_accept_t accept;
    avs_net_socket_close_t close;
    avs_net_socket_shutdown_t shutdown;
    avs_net_socket_cleanup_t cleanup;
    avs_net_socket_get_system_t get_system_socket;
    avs_net_socket_get_interface_t get_interface_name;
    avs_net_socket_get_remote_host_t get_remote_host;
    avs_net_socket_get_remote_port_t get_remote_port;
    avs_net_socket_get_local_port_t get_local_port;
    avs_net_socket_get_opt_t get_opt;
    avs_net_socket_set_opt_t set_opt;
} avs_net_socket_v_table_t;

#endif /* V_TABLE_H */
