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

/* This is from the BIND 4.9.4 release, modified to compile by itself */
/* Modified with some AVSystem specific code */

/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <avsystem/commons/avs_commons_config.h>

#if defined(AVS_COMMONS_WITH_AVS_NET)                     \
        && defined(AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET) \
        && !defined(AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_INET_NTOP)

#    include <avs_commons_posix_init.h>

#    include <stdint.h>
#    include <stdio.h>
#    include <string.h>

#    include <avsystem/commons/avs_errno.h>

VISIBILITY_SOURCE_BEGIN

#    if defined(LIBC_SCCS) && !defined(lint)
static char rcsid[] = "$Id: inet_ntop.c,v 8.5 1996/05/22 04:56:30 vixie Exp $";
#    endif /* LIBC_SCCS and not lint */

#    ifndef __u_char_defined

/* Type definitions for BSD code. */
typedef unsigned long u_long;
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;

#    endif

#    ifdef AVS_COMMONS_NET_WITH_IPV6
#        define IN6ADDRSZ 16
#        define INT16SZ 2

#        ifndef AF_INET6
#            define AF_INET6 (AF_MAX + 1) /* just to let this compile */
#        endif
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

VISIBILITY_SOURCE_BEGIN

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

const char *_avs_inet_ntop(int af, const void *src, char *dst, size_t size);
static const char *inet_ntop4(const u_char *src, char *dst, size_t size);
#    ifdef AVS_COMMONS_NET_WITH_IPV6
static const char *inet_ntop6(const u_char *src, char *dst, size_t size);
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char *_avs_inet_ntop(int af, const void *src, char *dst, size_t size) {
    switch (af) {
#    ifdef AVS_COMMONS_NET_WITH_IPV4
    case AF_INET:
        return (inet_ntop4((const u_char *) src, dst, size));
#    endif /* AVS_COMMONS_NET_WITH_IPV4 */
#    ifdef AVS_COMMONS_NET_WITH_IPV6
    case AF_INET6:
        return (inet_ntop6((const u_char *) src, dst, size));
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */
    default:
        errno = EAFNOSUPPORT;
        return (NULL);
    }
    /* NOTREACHED */
}

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address, more or less like inet_ntoa()
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char *inet_ntop4(const u_char *src, char *dst, size_t size) {
    static const char fmt[] = "%u.%u.%u.%u";
    char tmp[sizeof "255.255.255.255"];

    sprintf(tmp, fmt, src[0], src[1], src[2], src[3]);
    if (strlen(tmp) > size) {
        errno = ENOSPC;
        return (NULL);
    }
    strcpy(dst, tmp);
    return (dst);
}

#    ifdef AVS_COMMONS_NET_WITH_IPV6
/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
static const char *inet_ntop6(const u_char *src, char *dst, size_t size) {
    /*
     * Note that int32_t and int16_t need only be "at least" large enough
     * to contain a value of the specified size.  On some systems, like
     * Crays, there is no such thing as an integer variable with 16 bits.
     * Keep this in mind if you think this function should have been coded
     * to use pointer overlays.  All the world's not a VAX.
     */
    char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
    struct {
        int base, len;
    } best = { -1, -1 }, cur = { -1, -1 };
    u_int words[IN6ADDRSZ / INT16SZ];
    int i;

    /*
     * Preprocess:
     *	Copy the input (bytewise) array into a wordwise array.
     *	Find the longest run of 0x00's in src[] for :: shorthanding.
     */
    memset(words, 0, sizeof words);
    for (i = 0; i < IN6ADDRSZ; i++)
        words[i / 2] |= (u_int) (src[i] << ((1 - (i % 2)) << 3));
    for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
        if (words[i] == 0) {
            if (cur.base == -1)
                cur.base = i, cur.len = 1;
            else
                cur.len++;
        } else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                    best = cur;
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
            best = cur;
    }
    if (best.base != -1 && best.len < 2)
        best.base = -1;

    /*
     * Format the result.
     */
    tp = tmp;
    for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
        /* Are we inside the best run of 0x00's? */
        if (best.base != -1 && i >= best.base && i < (best.base + best.len)) {
            if (i == best.base)
                *tp++ = ':';
            continue;
        }
        /* Are we following an initial run of 0x00s or any real hex? */
        if (i != 0)
            *tp++ = ':';
        /* Is this address an encapsulated IPv4? */
        if (i == 6 && best.base == 0
                && (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
            if (!inet_ntop4(src + 12, tp, sizeof tmp - (size_t) (tp - tmp)))
                return (NULL);
            tp += strlen(tp);
            break;
        }
        sprintf(tp, "%x", words[i]);
        tp += strlen(tp);
    }
    /* Was it a trailing run of 0x00's? */
    if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
        *tp++ = ':';
    *tp++ = '\0';

    /*
     * Check for overflow, copy, and we're done.
     */
    if ((size_t) (tp - tmp) > size) {
        errno = ENOSPC;
        return (NULL);
    }
    strcpy(dst, tmp);
    return (dst);
}
#    endif /* AVS_COMMONS_NET_WITH_IPV6 */

#else

typedef int translation_unit_not_empty;

#endif // defined(AVS_COMMONS_WITH_AVS_NET) &&
       // defined(AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET) &&
       // !defined(AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_INET_NTOP)
