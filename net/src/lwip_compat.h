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

#ifndef AVS_COMMONS_NET_LWIP_COMPAT_H
#define AVS_COMMONS_NET_LWIP_COMPAT_H

#undef LWIP_COMPAT_SOCKETS
#define LWIP_COMPAT_SOCKETS 1
#include "lwipopts.h"
#include "lwip/arch.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#endif /* AVS_COMMONS_NET_LWIP_COMPAT_H */
