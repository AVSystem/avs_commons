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

#include <avsystem/commons/avs_commons_config.h>

#if defined(AVS_COMMONS_WITH_AVS_NET) \
        && defined(AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET)

#    include <avs_commons_posix_init.h>

#    include <assert.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_net.h>
#    include <avsystem/commons/avs_time.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_compat.h"

VISIBILITY_SOURCE_BEGIN

struct avs_net_addrinfo_struct {
    struct addrinfo *results;
    const struct addrinfo *to_send;
#    ifdef WITH_AVS_V4MAPPED
    bool v4mapped;
#    endif
};

static int port_from_string(uint16_t *out, const char *port_str) {
    if (!port_str || !*port_str) {
        *out = 0;
        return 0;
    }
    char *endptr = NULL;
    long result = strtol(port_str, &endptr, 10);
    if (result < 0 || result > UINT16_MAX || !endptr || *endptr) {
        return -1;
    }
    *out = (uint16_t) result;
    return 0;
}

static void update_ports(struct addrinfo *head, uint16_t port) {
    port = htons(port);
    for (; head; head = head->ai_next) {
        switch (head->ai_family) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
        case AF_INET:
            memcpy((char *) head->ai_addr
                           + offsetof(struct sockaddr_in, sin_port),
                   &port, sizeof(uint16_t));
            break;
#    endif // AVS_COMMONS_NET_WITH_IPV4
#    ifdef AVS_COMMONS_NET_WITH_IPV6
        case AF_INET6:
            memcpy((char *) head->ai_addr
                           + offsetof(struct sockaddr_in6, sin6_port),
                   &port, sizeof(uint16_t));
            break;
#    endif        // AVS_COMMONS_NET_WITH_IPV6
        default:; // do nothing
        }
    }
}

static struct addrinfo *detach_preferred(struct addrinfo **list_ptr,
                                         const void *preferred_addr,
                                         socklen_t preferred_addr_len) {
    for (; *list_ptr; list_ptr = &(*list_ptr)->ai_next) {
        if ((socklen_t) (*list_ptr)->ai_addrlen == preferred_addr_len
                && memcmp((*list_ptr)->ai_addr, preferred_addr,
                          (size_t) preferred_addr_len)
                               == 0) {
            struct addrinfo *retval = *list_ptr;
            *list_ptr = retval->ai_next;
            retval->ai_next = NULL;
            return retval;
        }
    }
    return NULL;
}

static void half_addrinfo(struct addrinfo *list, struct addrinfo **part2_ptr) {
    size_t length = 0;
    struct addrinfo *ptr = list;
    assert(list);
    assert(list->ai_next);
    while (ptr) {
        ++length;
        ptr = ptr->ai_next;
    }
    length /= 2;
    while (--length) {
        list = list->ai_next;
    }
    *part2_ptr = list->ai_next;
    list->ai_next = NULL;
}

static void randomize_addrinfo_list(struct addrinfo **list_ptr,
                                    unsigned *random_seed) {
    struct addrinfo *part1 = NULL;
    struct addrinfo *part2 = NULL;
    struct addrinfo **list_end_ptr = NULL;
    if (!list_ptr || !*list_ptr || !(*list_ptr)->ai_next) {
        /* zero or one element */
        return;
    }
    part1 = *list_ptr;
    half_addrinfo(part1, &part2);
    *list_ptr = NULL;
    list_end_ptr = list_ptr;
    randomize_addrinfo_list(&part1, random_seed);
    randomize_addrinfo_list(&part2, random_seed);
    while (part1 && part2) {
        if (avs_rand_r(random_seed) % 2) {
            *list_end_ptr = part1;
            part1 = part1->ai_next;
        } else {
            *list_end_ptr = part2;
            part2 = part2->ai_next;
        }
        (*list_end_ptr)->ai_next = NULL;
        list_end_ptr = &(*list_end_ptr)->ai_next;
    }
    if (part1) {
        *list_end_ptr = part1;
    } else {
        *list_end_ptr = part2;
    }
}

void avs_net_addrinfo_delete(avs_net_addrinfo_t **ctx) {
    if (*ctx) {
        if ((*ctx)->results) {
            freeaddrinfo((*ctx)->results);
        }
        avs_free(*ctx);
        *ctx = NULL;
    }
}

static int get_native_af(avs_net_af_t addr_family) {
    switch (addr_family) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
    case AVS_NET_AF_INET4:
        return AF_INET;
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */

#    ifdef AVS_COMMONS_NET_WITH_IPV6
    case AVS_NET_AF_INET6:
        return AF_INET6;
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

    case AVS_NET_AF_UNSPEC:
    default:
        return AF_UNSPEC;
    }
}

avs_net_addrinfo_t *avs_net_addrinfo_resolve_ex(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port_str,
        int flags,
        const avs_net_resolved_endpoint_t *preferred_endpoint) {
    if (avs_is_err(_avs_net_ensure_global_state())) {
        LOG(ERROR, _("avs_net global state initialization error"));
        return NULL;
    }

    struct addrinfo hint;
    memset((void *) &hint, 0, sizeof(hint));
    hint.ai_family = get_native_af(family);
    if (family != AVS_NET_AF_UNSPEC && hint.ai_family == AF_UNSPEC) {
        LOG(DEBUG, _("Unsupported avs_net_af_t: ") "%d", (int) family);
        return NULL;
    }
    if (!(flags & AVS_NET_ADDRINFO_RESOLVE_F_NOADDRCONFIG)) {
        hint.ai_flags |= AI_ADDRCONFIG;
    }
    if (flags & AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE) {
        hint.ai_flags |= AI_PASSIVE;
    }

    // some getaddrinfo() implementations interpret port 0 as invalid,
    // so we use our own port parsing
    uint16_t port;
    if (port_from_string(&port, port_str)) {
        LOG(ERROR, _("Invalid port: ") "%s", port_str);
        return NULL;
    }

    avs_net_addrinfo_t *ctx =
            (avs_net_addrinfo_t *) avs_calloc(1, sizeof(avs_net_addrinfo_t));
    if (!ctx) {
        LOG(ERROR, _("Out of memory"));
        return NULL;
    }

#    ifdef WITH_AVS_V4MAPPED
    if (flags & AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED) {
        ctx->v4mapped = true;
        if (family == AVS_NET_AF_INET6) {
            hint.ai_family = AF_UNSPEC;
        }
    }
#    endif
    hint.ai_socktype = _avs_net_get_socket_type(socket_type);

    if (!host || !*host) {
        switch (family) {
        case AVS_NET_AF_INET4:
            host = "0.0.0.0";
            break;
        case AVS_NET_AF_INET6:
            host = "::";
            break;
        default:
            host = "";
        }
    }
    int error = getaddrinfo(host, NULL, &hint, &ctx->results);
    if (error) {
#    ifdef AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GAI_STRERROR
        LOG(DEBUG,
            _("getaddrinfo() error: ") "%s" _(
                    "; family == (avs_net_af_t) ") "%d",
            gai_strerror(error), (int) family);
#    else
        LOG(DEBUG,
            _("getaddrinfo() error: ") "%d" _(
                    "; family == (avs_net_af_t) ") "%d",
            error, (int) family);
#    endif
        avs_net_addrinfo_delete(&ctx);
        return NULL;
    } else {
        update_ports(ctx->results, port);
        unsigned seed = (unsigned) avs_time_real_now().since_real_epoch.seconds;
        struct addrinfo *preferred = NULL;
        if (preferred_endpoint) {
            preferred = detach_preferred(&ctx->results,
                                         preferred_endpoint->data.buf,
                                         preferred_endpoint->size);
        }
        randomize_addrinfo_list(&ctx->results, &seed);
        if (preferred) {
            preferred->ai_next = ctx->results;
            ctx->results = preferred;
        }
        ctx->to_send = ctx->results;
        return ctx;
    }
}

#    ifdef WITH_AVS_V4MAPPED
static int create_v4mapped(struct sockaddr_in6 *out,
                           const struct addrinfo *in) {
    struct sockaddr_in v4_address;
    if (in->ai_addr->sa_family != AF_INET
            || in->ai_addrlen > (socklen_t) sizeof(v4_address)) {
        return -1;
    }
    memset(&v4_address, 0, sizeof(v4_address));
    memcpy(&v4_address, in->ai_addr, in->ai_addrlen);
    memset(out, 0, sizeof(struct sockaddr_in6));
    out->sin6_family = AF_INET6;
    out->sin6_port = v4_address.sin_port;
    out->sin6_addr.s6_addr[10] = 0xFF;
    out->sin6_addr.s6_addr[11] = 0xFF;
    memcpy(&out->sin6_addr.s6_addr[12], &v4_address.sin_addr, 4);
    return 0;
}
#    endif // WITH_AVS_V4MAPPED

static int return_resolved_endpoint(avs_net_resolved_endpoint_t *out,
                                    void *addr,
                                    socklen_t addrlen) {
    AVS_STATIC_ASSERT(sizeof(out->data) <= UINT8_MAX, resolved_enpoint_size);
    if (addrlen > (socklen_t) sizeof(out->data)) {
        return -1;
    }
    out->size = (uint8_t) addrlen;
    memcpy(out->data.buf, addr, out->size);
    return 0;
}

int avs_net_addrinfo_next(avs_net_addrinfo_t *ctx,
                          avs_net_resolved_endpoint_t *out) {
#    ifdef WITH_AVS_V4MAPPED
    if (ctx->v4mapped) {
        while (ctx->to_send && ctx->to_send->ai_family != AF_INET
               && ctx->to_send->ai_family != AF_INET6) {
            ctx->to_send = ctx->to_send->ai_next;
        }
    }
#    endif
    if (!ctx->to_send) {
        return AVS_NET_ADDRINFO_END;
    }
    int result;
#    ifdef WITH_AVS_V4MAPPED
    if (ctx->v4mapped && ctx->to_send->ai_family == AF_INET) {
        struct sockaddr_in6 v6_address;
        (void) ((result = create_v4mapped(&v6_address, ctx->to_send))
                || (result = return_resolved_endpoint(
                            out, &v6_address, (socklen_t) sizeof(v6_address))));
    } else
#    endif
    {
        result = return_resolved_endpoint(out, ctx->to_send->ai_addr,
                                          (socklen_t) ctx->to_send->ai_addrlen);
    }
    if (!result) {
        ctx->to_send = ctx->to_send->ai_next;
    }
    return result;
}

void avs_net_addrinfo_rewind(avs_net_addrinfo_t *ctx) {
    ctx->to_send = ctx->results;
}

#endif // defined(AVS_COMMONS_WITH_AVS_NET) &&
       // defined(AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET)
