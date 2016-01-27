/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014-2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

int _avs_net_create_ssl_socket(avs_net_abstract_socket_t **socket,
                               const void *socket_configuration) {
}

int _avs_net_create_dtls_socket(avs_net_abstract_socket_t **socket,
                                const void *socket_configuration) {
}
