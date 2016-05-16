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
#   undef LWIP_COMPAT_SOCKETS
#   define LWIP_COMPAT_SOCKETS 1
#   include "lwipopts.h"
#   include "lwip/netdb.h"
#   include "lwip/socket.h"
#else
#   include <netdb.h>
#   include <sys/socket.h>
#   include <sys/types.h>
#endif

#include <assert.h>
#include <string.h>
#include <time.h>

#include <avsystem/commons/net.h>

#include "net.h"
#include "addrinfo.h"

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

void _avs_net_addrinfo_ctx_init(avs_net_addrinfo_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void _avs_net_addrinfo_ctx_cleanup(avs_net_addrinfo_ctx_t *ctx) {
    if (ctx && ctx->results) {
        freeaddrinfo(ctx->results);
    }
}

int avs_net_addrinfo_ctx_create(avs_net_addrinfo_ctx_t **ctx) {
    avs_net_addrinfo_ctx_delete(ctx);
    *ctx = (avs_net_addrinfo_ctx_t *) malloc(sizeof(avs_net_addrinfo_ctx_t));
    if (!*ctx) {
        return -1;
    }
    _avs_net_addrinfo_ctx_init(*ctx);
    return 0;
}

void avs_net_addrinfo_ctx_delete(avs_net_addrinfo_ctx_t **ctx) {
    if (*ctx) {
        _avs_net_addrinfo_ctx_cleanup(*ctx);
        free(*ctx);
        *ctx = NULL;
    }
}

int avs_net_addrinfo_ctx_resolve(
        avs_net_addrinfo_ctx_t *ctx,
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        int passive,
        const avs_net_resolved_endpoint_t *preferred_endpoint) {
    int error;
    struct addrinfo hint;

    memset((void *) &hint, 0, sizeof (hint));
    hint.ai_family = _avs_net_get_af(family);
    hint.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
    if (passive) {
        hint.ai_flags |= AI_PASSIVE;
    }
    hint.ai_socktype = _avs_net_get_socket_type(socket_type);

    if (ctx->results) {
        freeaddrinfo(ctx->results);
        ctx->results = NULL;
    }
    ctx->to_send = NULL;

    if ((error = getaddrinfo(host, port, &hint, &ctx->results))) {
#ifdef HAVE_GAI_STRERROR
        LOG(ERROR, "%s", gai_strerror(error));
#else
        LOG(ERROR, "getaddrinfo() error %d", error);
#endif
        return error;
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
        return 0;
    }
}

int avs_net_addrinfo_ctx_get_next(avs_net_addrinfo_ctx_t *ctx,
                                  avs_net_resolved_endpoint_t *out) {
    if (!ctx->to_send) {
        return AVS_NET_ADDRINFO_CTX_END;
    }
    if (ctx->to_send->ai_addrlen > sizeof(out->data)) {
        return -1;
    }
    out->size = (uint8_t) ctx->to_send->ai_addrlen;
    memcpy(out->data.buf, ctx->to_send->ai_addr, ctx->to_send->ai_addrlen);

    ctx->to_send = ctx->to_send->ai_next;
    return 0;
}

void avs_net_addrinfo_ctx_rewind(avs_net_addrinfo_ctx_t *ctx) {
    ctx->to_send = ctx->results;
}
