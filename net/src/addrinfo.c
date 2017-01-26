/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for addrinfo */
#endif

#include <config.h>

#ifdef WITH_LWIP
#   include "lwip_compat.h"
#else /* WITH_LWIP */
#   include <netdb.h>
#   include <sys/socket.h>
#   include <sys/types.h>
#endif

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <avsystem/commons/net.h>

#include "net.h"

#ifdef __GLIBC__
#if !__GLIBC_PREREQ(2,4)
/* This guy is available since glibc 2.3.4 */
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif
#endif
#endif /* __GLIBC__ */

#ifdef __UCLIBC__
#define __UCLIBC_PREREQ(maj, min, patch) \
    (__UCLIBC_MAJOR__ > (maj) || \
     (__UCLIBC_MAJOR__ == (maj) && \
      (__UCLIBC_MINOR > (min) || \
       (__UCLIBC_MINOR__ == (min) && __UCLIBC_SUBLEVEL__ >= (patch)))))

#if !__UCLIBC_PREREQ(0,9,30)
/* These guys are available since uClibc 0.9.30 */
#ifdef AI_NUMERICSERV
#undef AI_NUMERICSERV
#endif /* AI_NUMERICSERV */
#define AI_NUMERICSERV 0

#ifdef AI_ADDRCONFIG
#undef AI_ADDRCONFIG
#endif /* AI_ADDRCONFIG */
#define AI_ADDRCONFIG 0
#endif

#endif /* __UCLIBC__ */

#ifdef HAVE_RAND_R
#define _avs_rand_r rand_r
#else
#warning "rand_r not available, please provide int _avs_rand_r(unsigned int *)"
int _avs_rand_r(unsigned int *seedp);
#endif

#if defined(WITH_IPV4) && defined(WITH_IPV6)
#define WITH_AVS_V4MAPPED
#endif

struct avs_net_addrinfo_struct {
    struct addrinfo *results;
    const struct addrinfo *to_send;
#ifdef WITH_AVS_V4MAPPED
    bool v4mapped;
#endif
};

static struct addrinfo *detach_preferred(struct addrinfo **list_ptr,
                                         const void *preferred_addr,
                                         socklen_t preferred_addr_len) {
    for (; *list_ptr; list_ptr = &(*list_ptr)->ai_next) {
        if ((*list_ptr)->ai_addrlen == preferred_addr_len
                && memcmp((*list_ptr)->ai_addr, preferred_addr,
                          preferred_addr_len) == 0) {
            struct addrinfo *retval = *list_ptr;
            *list_ptr = retval->ai_next;
            retval->ai_next = NULL;
            return retval;
        }
    }
    return NULL;
}

static void half_addrinfo(struct addrinfo *list,
                          struct addrinfo **part2_ptr) {
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
        if (_avs_rand_r(random_seed) % 2) {
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
        free(*ctx);
        *ctx = NULL;
    }
}

avs_net_addrinfo_t *avs_net_addrinfo_resolve_ex(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        int flags,
        const avs_net_resolved_endpoint_t *preferred_endpoint) {

    avs_net_addrinfo_t *ctx =
            (avs_net_addrinfo_t *) calloc(1, sizeof(avs_net_addrinfo_t));
    if (!ctx) {
        return NULL;
    }

    struct addrinfo hint;
    memset((void *) &hint, 0, sizeof (hint));
    hint.ai_family = _avs_net_get_af(family);
    hint.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
    if (flags & AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE) {
        hint.ai_flags |= AI_PASSIVE;
    }

#ifdef WITH_AVS_V4MAPPED
    if (family == AVS_NET_AF_INET6
            && (flags & AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED)) {
        ctx->v4mapped = true;
        hint.ai_family = AF_UNSPEC;
    }
#endif
    hint.ai_socktype = _avs_net_get_socket_type(socket_type);

    int error = getaddrinfo(host, port, &hint, &ctx->results);
    if (error) {
#ifdef HAVE_GAI_STRERROR
        LOG(ERROR, "%s", gai_strerror(error));
#else
        LOG(ERROR, "getaddrinfo() error %d", error);
#endif
        avs_net_addrinfo_delete(&ctx);
        return NULL;
    } else {
        unsigned seed = (unsigned) time(NULL);
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

avs_net_addrinfo_t *avs_net_addrinfo_resolve(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        const avs_net_resolved_endpoint_t *preferred_endpoint) {
    return avs_net_addrinfo_resolve_ex(socket_type, family, host, port, 0,
                                       preferred_endpoint);
}

#ifdef WITH_AVS_V4MAPPED
static int create_v4mapped(struct sockaddr_in6 *out,
                           const struct addrinfo *in) {
    struct sockaddr_in v4_address;
    if (in->ai_addr->sa_family != AF_INET
            || in->ai_addrlen > sizeof(v4_address)) {
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
#endif // WITH_AVS_V4MAPPED

static int return_resolved_endpoint(avs_net_resolved_endpoint_t *out,
                                    void *addr,
                                    socklen_t addrlen) {
    AVS_STATIC_ASSERT(sizeof(out->data) <= UINT8_MAX, resolved_enpoint_size);
    if (addrlen > sizeof(out->data)) {
        return -1;
    }
    out->size = (uint8_t) addrlen;
    memcpy(out->data.buf, addr, addrlen);
    return 0;
}

int avs_net_addrinfo_next(avs_net_addrinfo_t *ctx,
                          avs_net_resolved_endpoint_t *out) {
    if (!ctx->to_send) {
        return AVS_NET_ADDRINFO_END;
    }
    int result;
#ifdef WITH_AVS_V4MAPPED
    if (ctx->v4mapped && ctx->to_send->ai_family == AF_INET) {
        struct sockaddr_in6 v6_address;
        (void) ((result = create_v4mapped(&v6_address, ctx->to_send))
                || (result = return_resolved_endpoint(
                        out, &v6_address, (socklen_t) sizeof(v6_address))));
    } else
#endif
    {
        result = return_resolved_endpoint(out, ctx->to_send->ai_addr,
                                          ctx->to_send->ai_addrlen);
    }
    if (!result) {
        ctx->to_send = ctx->to_send->ai_next;
    }
    return result;
}

void avs_net_addrinfo_rewind(avs_net_addrinfo_t *ctx) {
    ctx->to_send = ctx->results;
}

int avs_net_resolve_host_simple(avs_net_socket_type_t socket_type,
                                avs_net_af_t family,
                                const char *host,
                                char *resolved_buf, size_t resolved_buf_size) {
    int result = -1;
    avs_net_resolved_endpoint_t address;
    avs_net_addrinfo_t *info =
            avs_net_addrinfo_resolve(socket_type, family,
                                     host, AVS_NET_RESOLVE_DUMMY_PORT, NULL);
    if (info) {
        (void) ((result = avs_net_addrinfo_next(info, &address))
                || (result = avs_net_resolved_endpoint_get_host(
                        &address, resolved_buf, resolved_buf_size)));
    }
    avs_net_addrinfo_delete(&info);
    return result;
}
