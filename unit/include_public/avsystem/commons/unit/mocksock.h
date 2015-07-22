/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_UNIT_MOCKSOCK_H
#define	AVS_COMMONS_UNIT_MOCKSOCK_H

#include <avsystem/commons/net.h>

#ifdef	__cplusplus
extern "C" {
#endif

void avs_unit_mocksock_create(avs_net_abstract_socket_t **socket);
void avs_unit_mocksock_input(avs_net_abstract_socket_t *socket,
                             const char *data, size_t length);
void avs_unit_mocksock_input_fail(avs_net_abstract_socket_t *socket_, int retval);
size_t avs_unit_mocksock_data_read(avs_net_abstract_socket_t *socket);
void avs_unit_mocksock_expect_output(avs_net_abstract_socket_t *socket,
                                     const char *expect, size_t length);
void avs_unit_mocksock_output_fail(avs_net_abstract_socket_t *socket_, int retval);
void avs_unit_mocksock_assert_io_clean(avs_net_abstract_socket_t *socket);
void avs_unit_mocksock_expect_connect(avs_net_abstract_socket_t *socket,
                                      const char *host, const char *port);
void avs_unit_mocksock_expect_bind(avs_net_abstract_socket_t *socket,
                                   const char *localaddr, const char *port);
void avs_unit_mocksock_expect_accept(avs_net_abstract_socket_t *socket);
void avs_unit_mocksock_expect_mid_close(avs_net_abstract_socket_t *socket);
void avs_unit_mocksock_expect_shutdown(avs_net_abstract_socket_t *socket);
void avs_unit_mocksock_expect_remote_host(avs_net_abstract_socket_t *socket,
                                          const char *to_return);
void avs_unit_mocksock_expect_remote_port(avs_net_abstract_socket_t *socket,
                                          const char *to_return);
void avs_unit_mocksock_expect_get_opt(avs_net_abstract_socket_t *socket,
                                      avs_net_socket_opt_key_t key,
                                      avs_net_socket_opt_value_t resp_value);
void avs_unit_mocksock_expect_set_opt(avs_net_abstract_socket_t *socket,
                                      avs_net_socket_opt_key_t key);
void avs_unit_mocksock_fail_command(avs_net_abstract_socket_t *socket);

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_UNIT_MOCKSOCK_H */

