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

#ifndef AVS_COMMONS_STREAM_NETBUF_H
#define AVS_COMMONS_STREAM_NETBUF_H

#include <avsystem/commons/avs_net.h>
#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

int avs_stream_netbuf_create(avs_stream_t **stream_,
                             avs_net_socket_t *socket,
                             size_t in_buffer_size,
                             size_t out_buffer_size);

int avs_stream_netbuf_transfer(avs_stream_t *destination, avs_stream_t *source);

int avs_stream_netbuf_out_buffer_left(avs_stream_t *str);

void avs_stream_netbuf_set_recv_timeout(avs_stream_t *str,
                                        avs_time_duration_t timeout);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_NETBUF_H */
