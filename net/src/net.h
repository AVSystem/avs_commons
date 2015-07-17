/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef NET_H
#define NET_H

#include <stdint.h>

#include <avsystem/commons/socket_v_table.h>

#ifdef WITH_AVS_LOG
#include <avsystem/commons/log.h>
#define LOG(...) avs_log(avs_net, __VA_ARGS__)
#else
#define LOG(...) ((void) 0)
#endif

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

#define NET_MAX_HOSTNAME_SIZE    64
#define NET_PORT_SIZE            6

int _avs_net_create_tcp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration);
int _avs_net_create_udp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration);

#ifdef WITH_SSL
int _avs_net_create_ssl_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration);
int _avs_net_create_dtls_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration);
#endif

#ifdef HAVE_VISIBILITY
#pragma GCC visibility pop
#endif

#endif /* LIBCWMP_INCLUDE_COMPAT_NET_H */

