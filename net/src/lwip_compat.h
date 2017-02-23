#ifndef AVS_COMMONS_NET_LWIP_COMPAT_H
#define AVS_COMMONS_NET_LWIP_COMPAT_H

#undef LWIP_COMPAT_SOCKETS
#define LWIP_COMPAT_SOCKETS 1
#include "lwipopts.h"
#include "lwip/arch.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"


#endif /* AVS_COMMONS_NET_LWIP_COMPAT_H */
