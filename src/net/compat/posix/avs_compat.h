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

#ifndef AVS_COMMONS_NET_COMPAT_H
#define AVS_COMMONS_NET_COMPAT_H

#include "../../avs_net_global.h"

#include "../../avs_net_impl.h"

VISIBILITY_PRIVATE_HEADER_BEGIN

/* Following values are not defined e.g. in LwIP 1.4.1 */
#ifndef AI_ADDRCONFIG
#    define AI_ADDRCONFIG 0
#endif
#ifndef AI_PASSIVE
#    define AI_PASSIVE 0
#endif

/* Hopefully high enum values will not collide with any existing ones */
#ifndef SO_BINDTODEVICE
#    define SO_BINDTODEVICE 0xFFFF
#endif
#ifndef SO_PRIORITY
#    define SO_PRIORITY 0xFFFE
#endif

/* This one is a bit-flag, so it needs to be set to 0 */
#ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#endif

int _avs_net_get_socket_type(avs_net_socket_type_t socket_type);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_NET_COMPAT_H */
