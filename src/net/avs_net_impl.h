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

#ifndef NET_H
#define NET_H

#include <stdint.h>

#include <avsystem/commons/avs_socket_v_table.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

#if !defined(AVS_COMMONS_NET_WITH_IPV4) && !defined(AVS_COMMONS_NET_WITH_IPV6)
#    error "At least one IP protocol version must be enabled"
#endif

#if defined(AVS_COMMONS_NET_WITH_IPV4) && defined(AVS_COMMONS_NET_WITH_IPV6)
#    define WITH_AVS_V4MAPPED
#endif

#define MODULE_NAME avs_net
#include <avs_x_log_config.h>

/**
 * An owned PSK/identity pair. avs_commons will avs_free()
 * @ref avs_net_owned_psk_t#psk and @ref avs_net_owned_psk_t#identity pointers
 * when they are no longer needed.
 */
typedef struct {
    void *psk;
    size_t psk_size;
    void *identity;
    size_t identity_size;
} avs_net_owned_psk_t;

/**
 * Note: the _actual_ maximum hostname length is not precisely defined.
 * NI_MAXHOST on Linux is actually a very generous 1025 (incl. nullbyte). DNS
 * frame format allows for up to 253 (excl. nullbyte), and also each segment
 * (substring between the dots) may be at most 64 characters long. Maximum
 * length of a TLS certificate's CN is 64 (excl. nullbyte), but it may contain
 * wildcards (even though we don't support them here in Commons).
 *
 * So... let's use 256 ;)
 */
#define NET_MAX_HOSTNAME_SIZE 256

#define NET_PORT_SIZE 6

#define AVS_NET_RESOLVE_DUMMY_PORT "1337"

avs_error_t _avs_net_create_tcp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration);
avs_error_t _avs_net_create_udp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration);

#ifndef WITHOUT_SSL
avs_error_t _avs_net_create_ssl_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration);
avs_error_t _avs_net_create_dtls_socket(avs_net_socket_t **socket,
                                        const void *socket_configuration);
#endif // WITHOUT_SSL

VISIBILITY_PRIVATE_HEADER_END

#endif /* NET_H */
