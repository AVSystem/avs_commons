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

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_STREAM)        \
        && defined(AVS_COMMONS_WITH_AVS_BUFFER) \
        && defined(AVS_COMMONS_WITH_AVS_NET)

#    include <avsystem/commons/avs_stream_net.h>
#    include <avsystem/commons/avs_stream_v_table.h>

VISIBILITY_SOURCE_BEGIN

avs_net_socket_t *avs_stream_net_getsock(avs_stream_t *stream) {
    avs_net_socket_t *out = NULL;
    const avs_stream_v_table_extension_net_t *net =
            (const avs_stream_v_table_extension_net_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_NET);
    if (net) {
        out = net->getsock(stream);
    }
    return out;
}

avs_error_t avs_stream_net_setsock(avs_stream_t *stream,
                                   avs_net_socket_t *socket) {
    const avs_stream_v_table_extension_net_t *net =
            (const avs_stream_v_table_extension_net_t *)
                    avs_stream_v_table_find_extension(
                            stream, AVS_STREAM_V_TABLE_EXTENSION_NET);
    if (net) {
        return net->setsock(stream, socket);
    } else {
        return avs_errno(AVS_ENOTSUP);
    }
}

#endif // defined(AVS_COMMONS_WITH_AVS_STREAM) &&
       // defined(AVS_COMMONS_WITH_AVS_BUFFER) &&
       // defined(AVS_COMMONS_WITH_AVS_NET)
