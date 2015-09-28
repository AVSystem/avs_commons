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
    ((__UCLIBC_MAJOR__ << 16) + (__UCLIBC_MINOR__ << 8) + __UCLIBC_SUBLEVEL__ \
    >= ((maj) << 16) + ((min) << 8) + (patch))

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

#endif /* AVS_COMMONS_ADDRINFO_H */

