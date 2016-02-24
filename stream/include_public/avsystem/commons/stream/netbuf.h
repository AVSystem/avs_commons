/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_NETBUF_H
#define	AVS_COMMONS_STREAM_NETBUF_H

#include <avsystem/commons/net.h>
#include <avsystem/commons/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

int avs_stream_netbuf_create(avs_stream_abstract_t **stream_,
                             avs_net_abstract_socket_t *socket,
                             size_t in_buffer_size,
                             size_t out_buffer_size);

int avs_stream_netbuf_transfer(avs_stream_abstract_t *destination,
                               avs_stream_abstract_t *source);

int avs_stream_netbuf_out_buffer_left(avs_stream_abstract_t *str);

void avs_stream_netbuf_set_recv_timeout(avs_stream_abstract_t *str,
                                        avs_net_timeout_t timeout);

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_STREAM_NETBUF_H */

