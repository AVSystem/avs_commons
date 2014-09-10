/* 
 * File:   net.h
 * Author: kfyatek
 *
 * Created on 10 września 2014, 12:48
 */

#ifndef NET_H
#define	NET_H

#include <stdint.h>

#include <avsystem/commons/net.h>
#include <avsystem/commons/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define AVS_STREAM_V_TABLE_EXTENSION_NET 0x4E455453UL /* "NETS" */

typedef int (*avs_stream_net_getsock_t)(avs_stream_abstract_t *stream,
                                        avs_net_abstract_socket_t **out_socket);

typedef int (*avs_stream_net_setsock_t)(avs_stream_abstract_t *stream,
                                        avs_net_abstract_socket_t *socket);

typedef struct {
    avs_stream_net_getsock_t getsock;
    avs_stream_net_setsock_t setsock;
} avs_stream_v_table_extension_net_t;

avs_net_abstract_socket_t *
avs_stream_net_getsock(avs_stream_abstract_t *stream);

int avs_stream_net_setsock(avs_stream_abstract_t *stream,
                           avs_net_abstract_socket_t *socket);

#ifdef	__cplusplus
}
#endif

#endif	/* NET_H */

