#ifndef AVS_COMMONS_NET_COMPAT_H
#define AVS_COMMONS_NET_COMPAT_H

/* Following values are not defined e.g. in LwIP 1.4.1 */
#ifndef AI_NUMERICSERV
#   define AI_NUMERICSERV 0
#endif
#ifndef AI_ADDRCONFIG
#   define AI_ADDRCONFIG 0
#endif
#ifndef AI_PASSIVE
#   define AI_PASSIVE 0
#endif

/* Hopefully high enum values will not collide with any existing ones */
#ifndef SO_BINDTODEVICE
#   define SO_BINDTODEVICE 0xFFFF
#endif
#ifndef SO_PRIORITY
#   define SO_PRIORITY     0xFFFE
#endif

/* This one is a bit-flag, so it needs to be set to 0 */
#ifndef MSG_NOSIGNAL
#   define MSG_NOSIGNAL 0
#endif

#endif /* AVS_COMMONS_NET_COMPAT_H */
