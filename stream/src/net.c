/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <avsystem/commons/stream_v_table.h>
#include <avsystem/commons/stream/net.h>

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

avs_net_abstract_socket_t *
avs_stream_net_getsock(avs_stream_abstract_t *stream) {
    avs_net_abstract_socket_t *out = NULL;
    const avs_stream_v_table_extension_net_t *net =
            (const avs_stream_v_table_extension_net_t *)
            avs_stream_v_table_find_extension(stream,
                                              AVS_STREAM_V_TABLE_EXTENSION_NET);
    if (net) {
        if (net->getsock(stream, &out) < 0) {
            out = NULL;
        }
    }
    return out;
}

int avs_stream_net_setsock(avs_stream_abstract_t *stream,
                           avs_net_abstract_socket_t *socket) {
    const avs_stream_v_table_extension_net_t *net =
            (const avs_stream_v_table_extension_net_t *)
            avs_stream_v_table_find_extension(stream,
                                              AVS_STREAM_V_TABLE_EXTENSION_NET);
    if (net) {
        return net->setsock(stream, socket);
    } else {
        return -1;
    }
}
