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

#include "v_table.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

int _avs_net_create_tcp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration);
int _avs_net_create_udp_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration);

#ifdef HAVE_VISIBILITY
#pragma GCC visibility pop
#endif

#endif /* LIBCWMP_INCLUDE_COMPAT_NET_H */

