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

#ifdef AVS_COMMONS_WITH_AVS_NET

#    include <assert.h>
#    include <string.h>

#    include <avsystem/commons/avs_net.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_net_impl.h"

VISIBILITY_SOURCE_BEGIN

avs_net_addrinfo_t *avs_net_addrinfo_resolve(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        const avs_net_resolved_endpoint_t *preferred_endpoint) {
    return avs_net_addrinfo_resolve_ex(socket_type, family, host, port, 0,
                                       preferred_endpoint);
}

avs_error_t avs_net_resolve_host_simple(avs_net_socket_type_t socket_type,
                                        avs_net_af_t family,
                                        const char *host,
                                        char *resolved_buf,
                                        size_t resolved_buf_size) {
    avs_error_t err = avs_errno(AVS_EADDRNOTAVAIL);
    avs_net_resolved_endpoint_t address;
    avs_net_addrinfo_t *info =
            avs_net_addrinfo_resolve(socket_type, family, host,
                                     AVS_NET_RESOLVE_DUMMY_PORT, NULL);
    if (info && !avs_net_addrinfo_next(info, &address)) {
        err = avs_net_resolved_endpoint_get_host(&address, resolved_buf,
                                                 resolved_buf_size);
    }
    avs_net_addrinfo_delete(&info);
    return err;
}

#endif // AVS_COMMONS_WITH_AVS_NET
