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

#ifndef AVS_COMMONS_ADDRINFO_H
#define AVS_COMMONS_ADDRINFO_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_socket.h>

#ifdef __cplusplus
extern "C" {
#endif

struct avs_net_addrinfo_struct;

/**
 * Type for address resolution abstraction context.
 */
typedef struct avs_net_addrinfo_struct avs_net_addrinfo_t;

#define AVS_NET_ADDRINFO_END 1

/**
 * When calling @ref avs_net_addrinfo_resolve_ex with this bit set in the
 * <c>flags</c> parameter, a DNS query is not performed. Binary endpoint will
 * only be available for successful retrieval if the <c>host</c> passed is a
 * valid, unambiguous textual representation of an already resolved IP address.
 *
 * This is equivalent to <c>AI_PASSIVE</c> flag to <c>getaddrinfo()</c>.
 */
#define AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE (1 << 0)

/**
 * When calling @ref avs_net_addrinfo_resolve_ex with this bit set in the
 * <c>flags</c> parameter, all resolved addresses are converted to IPv6
 * addresses in output. In particular, IPv4 addresses are converted to
 * IPv4-mapped IPv6 addresses. Addresses that cannot be converted to IPv6 are
 * discarded.
 *
 * As a special compatibility case, if <c>family</c> is set to
 * <c>AVS_NET_AF_INET6</c>, address resolution will happen as if it was actually
 * set to <c>AVS_NET_AF_UNSPEC</c>.
 *
 * This is roughly equivalent to <c>AI_V4MAPPED | AI_ALL</c> flags to
 * <c>getaddrinfo()</c>, but implemented independently of them.
 *
 * This flag is meaningful only if the plaform supports both IPv4 and IPv6.
 * Otherwise it is ignored.
 */
#define AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED (1 << 1)

/**
 * When calling @ref avs_net_addrinfo_resolve_ex with this bit set in the
 * <c>flags</c> parameter, addresses of all families (i.e. both IPv4 and IPv6)
 * will be allowed to be returned, even if the host has no connectivity over the
 * given family.
 *
 * This is equivalent to an inverse of <c>AI_ADDRCONFIG</c> flag to
 * <c>getaddrinfo()</c>. For historical compatibility reasons,
 * <c>AI_ADDRCONFIG</c> is used by default; this flag can be used to disable it.
 */
#define AVS_NET_ADDRINFO_RESOLVE_F_NOADDRCONFIG (1 << 2)

/**
 * Resolves a text-represented host and port address to its binary
 * representation, possibly executing a DNS query as necessary.
 *
 * If there are multiple addresses that correspond to the specified names, they
 * are returned in randomized order.
 *
 * @param socket_type        Type of the socket for which the resolving is
 *                           performed. Valid values are
 *                           <c>AVS_NET_TCP_SOCKET</c> and
 *                           <c>AVS_NET_UDP_SOCKET</c>.
 *
 * @param family             Family of the address to resolve.
 *                           <c>AVS_NET_AF_UNSPEC</c> means that an address of
 *                           any supported type may be returned.
 *
 * @param host               Host name.
 *
 * @param port               Port number represented as a string.
 *
 * @param flags              Either 0 or a bit mask of one or more
 *                           <c>AVS_NET_ADDRINFO_RESOLVE_F_*</c> constants.
 *                           Please see their documentation for details.
 *
 * @param preferred_endpoint Preferred resolved address. If it is found among
 *                           the resolved addresses, it is returned on the first
 *                           position.
 *
 * @return A new instance of @ref avs_net_addrinfo_t that may be queried using
 *         @ref avs_net_addrinfo_next and has to be freed using
 *         @ref avs_net_addrinfo_delete. If an error occured, <c>NULL</c> is
 *         returned.
 */
avs_net_addrinfo_t *avs_net_addrinfo_resolve_ex(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        int flags,
        const avs_net_resolved_endpoint_t *preferred_endpoint);

/**
 * Equivalent to @ref avs_net_addrinfo_resolve_ex with <c>flags</c> set to 0.
 */
avs_net_addrinfo_t *
avs_net_addrinfo_resolve(avs_net_socket_type_t socket_type,
                         avs_net_af_t family,
                         const char *host,
                         const char *port,
                         const avs_net_resolved_endpoint_t *preferred_endpoint);

/**
 * Frees an object allocated by @ref avs_net_addrinfo_resolve or
 * @ref avs_net_addrinfo_resolve_ex.
 *
 * @param ctx Pointer to a variable holding an instance of
 *            @ref avs_net_addrinfo_t. It will be freed and zeroed.
 */
void avs_net_addrinfo_delete(avs_net_addrinfo_t **ctx);

/**
 * Returns a binary representation of the address previously queried for
 * resolution using @ref avs_net_addrinfo_resolve or
 * @ref avs_net_addrinfo_resolve_ex.
 *
 * Calling this function more than once will return subsequent alternative
 * addresses, if any.
 *
 * @param ctx A context object returned from @ref avs_net_addrinfo_resolve or
 *            @ref avs_net_addrinfo_resolve_ex.
 * @param out Pointer to variable in which to store the result.
 *
 * @return @li 0 for success
 *         @li negative value in case of error
 *         @li <c>AVS_NET_ADDRINFO_END</c> if there are no more addresses to
 *             return
 */
int avs_net_addrinfo_next(avs_net_addrinfo_t *ctx,
                          avs_net_resolved_endpoint_t *out);

/**
 * "Rewinds" a list of resolved addresses, so that a following call to
 * @ref avs_net_addrinfo_next will return the same value as the first call for
 * given context.
 *
 * @param ctx A context object returned from @ref avs_net_addrinfo_resolve or
 *            @ref avs_net_addrinfo_resolve_ex.
 */
void avs_net_addrinfo_rewind(avs_net_addrinfo_t *ctx);

/**
 * Translates a binary representation of a socket address to textual
 * representation.
 *
 * @param endp    The socket address to convert.
 *
 * @param host    Buffer in which to store the textual representation of the
 *                numerical host address.
 *
 * @param hostlen Size in bytes of the buffer pointed to by <c>host</c>.
 *
 * @param serv    Buffer in which to store the textual representation of the
 *                port number.
 *
 * @param servlen Size in bytes of the buffer pointed to by <c>serv</c>.
 *
 * Either <c>host</c> or <c>serv</c> arguments may be <c>NULL</c> in which case
 * only the non-<c>NULL</c> argument is filled in.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t
avs_net_resolved_endpoint_get_host_port(const avs_net_resolved_endpoint_t *endp,
                                        char *host,
                                        size_t hostlen,
                                        char *serv,
                                        size_t servlen);

/**
 * Equivalent to @ref avs_net_resolved_endpoint_get_host_port with the
 * <c>serv</c> argument set to <c>NULL</c>.
 *
 * @param endp    The socket address to convert.
 *
 * @param host    Buffer in which to store the textual representation of the
 *                numerical host address.
 *
 * @param hostlen Size in bytes of the buffer pointed to by <c>host</c>.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
static inline avs_error_t avs_net_resolved_endpoint_get_host(
        const avs_net_resolved_endpoint_t *endp, char *host, size_t hostlen) {
    return avs_net_resolved_endpoint_get_host_port(endp, host, hostlen, NULL,
                                                   0);
}

/**
 * A convenience function that handles the most common use case of host address
 * resolution. It resolves a host name (possibly by doing a DNS query in the
 * common case of it being a symbolic name) and returns a string representation
 * of one of its numerical addresses. If multiple addresses are available, one
 * of them is chosen at random.
 *
 * This call is essentially equivalent to calling @ref avs_net_addrinfo_resolve
 * (with a dummy port number), getting the first result (if available) using
 * @ref avs_net_addrinfo_next and stringifying it using
 * @ref avs_net_resolved_endpoint_get_host.
 *
 * @param socket_type       Type of the socket for which the resolving is
 *                          performed. Valid values are
 *                          <c>AVS_NET_TCP_SOCKET</c> and
 *                          <c>AVS_NET_UDP_SOCKET</c>.
 *
 * @param family            Family of the address to resolve.
 *                          <c>AVS_NET_AF_UNSPEC</c> means that an address of
 *                          any supported type may be returned.
 *
 * @param host              Host name to resolve.
 *
 * @param resolved_buf      Buffer in which to store the textual representation
 *                          of the numerical host address.
 *
 * @param resolved_buf_size Size in bytes of the buffer pointed to by
 *                          <c>resolved_buf</c>.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_net_resolve_host_simple(avs_net_socket_type_t socket_type,
                                        avs_net_af_t family,
                                        const char *host,
                                        char *resolved_buf,
                                        size_t resolved_buf_size);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_ADDRINFO_H */
