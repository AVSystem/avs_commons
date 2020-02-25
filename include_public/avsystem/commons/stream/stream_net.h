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

#ifndef AVS_COMMONS_STREAM_STREAM_NET_H
#define AVS_COMMONS_STREAM_STREAM_NET_H

#include <stdint.h>

#include <avsystem/commons/avs_net.h>
#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVS_STREAM_V_TABLE_EXTENSION_NET 0x4E455453UL /* "NETS" */

typedef avs_net_socket_t *(*avs_stream_net_getsock_t)(avs_stream_t *stream);

typedef avs_error_t (*avs_stream_net_setsock_t)(avs_stream_t *stream,
                                                avs_net_socket_t *socket);

typedef struct {
    avs_stream_net_getsock_t getsock;
    avs_stream_net_setsock_t setsock;
} avs_stream_v_table_extension_net_t;

avs_net_socket_t *avs_stream_net_getsock(avs_stream_t *stream);

avs_error_t avs_stream_net_setsock(avs_stream_t *stream,
                                   avs_net_socket_t *socket);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_STREAM_NET_H */
