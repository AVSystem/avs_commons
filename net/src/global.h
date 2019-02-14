/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#ifndef NET_GLOBAL_H
#define NET_GLOBAL_H

VISIBILITY_PRIVATE_HEADER_BEGIN

int _avs_net_initialize_global_compat_state(void);

void _avs_net_cleanup_global_compat_state(void);

#ifdef WITH_SSL
int _avs_net_initialize_global_ssl_state(void);

void _avs_net_cleanup_global_ssl_state(void);
#else // WITH_SSL
#define _avs_net_initialize_global_ssl_state(...) 0
#define _avs_net_cleanup_global_ssl_state(...) ((void) 0)
#endif // WITH_SSL

int _avs_net_ensure_global_state(void);
void _avs_net_cleanup_global_state(void);

VISIBILITY_PRIVATE_HEADER_END

#endif // NET_GLOBAL_H
