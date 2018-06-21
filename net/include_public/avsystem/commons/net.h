/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_NET_H
#define AVS_COMMONS_NET_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <avsystem/commons/defs.h>

#include <avsystem/commons/socket.h>
#include <avsystem/commons/addrinfo.h>

#ifdef	__cplusplus
extern "C" {
#endif

int avs_net_local_address_for_target_host(const char *target_host,
                                          avs_net_af_t addr_family,
                                          char *address_buffer,
                                          size_t buffer_size);

int avs_net_validate_ip_address(avs_net_af_t family, const char *ip_address);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_NET_H */
