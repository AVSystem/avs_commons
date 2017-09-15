/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#include <avs-config.h>

#include <avsystem/commons/stream_v_table.h>
#include <avsystem/commons/stream/stream_net.h>

VISIBILITY_SOURCE_BEGIN

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
