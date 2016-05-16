/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_ADDRINFO_H
#define AVS_COMMONS_ADDRINFO_H

#include <avsystem/commons/net.h>

struct avs_net_addrinfo_ctx_struct {
    struct addrinfo *results;
    struct addrinfo *to_send;
};

void _avs_net_addrinfo_ctx_init(avs_net_addrinfo_ctx_t *ctx);

void _avs_net_addrinfo_ctx_cleanup(avs_net_addrinfo_ctx_t *ctx);

#endif /* AVS_COMMONS_ADDRINFO_H */

