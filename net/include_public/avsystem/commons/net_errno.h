/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_NET_ERRNO_H
#define AVS_COMMONS_NET_ERRNO_H

#include <errno.h>

#include <avsystem/commons/errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file net_errno.h
 *
 * Network-related error constant definitions.
 *
 * If networking is not implemented in the operating system, but rather uses
 * some additional library (e.g. lwIP), the network-related errno constants may
 * not be defined. This file exports them into public API.
 */

#ifndef EADDRINUSE
extern int AVS_NET_EADDRINUSE;
#define EADDRINUSE AVS_NET_EADDRINUSE /**< Address in use */
#endif

#ifndef EADDRNOTAVAIL
extern int AVS_NET_EADDRNOTAVAIL;
#define EADDRNOTAVAIL AVS_NET_EADDRNOTAVAIL /**< Address not available */
#endif

#ifndef EAFNOSUPPORT
extern int AVS_NET_EAFNOSUPPORT;
#define EAFNOSUPPORT AVS_NET_EAFNOSUPPORT /**< Address family not supported */
#endif

#ifndef EAGAIN
extern int AVS_NET_EAGAIN;
#define EAGAIN AVS_NET_EAGAIN /**< Resource unavailable, try again */
#endif

#ifndef EALREADY
extern int AVS_NET_EALREADY;
#define EALREADY AVS_NET_EALREADY /**< Connection already in progress */
#endif

#ifndef EBADMSG
extern int AVS_NET_EBADMSG;
#define EBADMSG AVS_NET_EBADMSG /**< Bad message */
#endif

#ifndef ECANCELED
extern int AVS_NET_ECANCELED;
#define ECANCELED AVS_NET_ECANCELED /**< Operation canceled */
#endif

#ifndef ECONNABORTED
extern int AVS_NET_ECONNABORTED;
#define ECONNABORTED AVS_NET_ECONNABORTED /**< Connection aborted */
#endif

#ifndef ECONNREFUSED
extern int AVS_NET_ECONNREFUSED;
#define ECONNREFUSED AVS_NET_ECONNREFUSED /**< Connection refused */
#endif

#ifndef ECONNRESET
extern int AVS_NET_ECONNRESET;
#define ECONNRESET AVS_NET_ECONNRESET /**< Connection reset */
#endif

#ifndef EDESTADDRREQ
extern int AVS_NET_EDESTADDRREQ;
#define EDESTADDRREQ AVS_NET_EDESTADDRREQ /**< Destination address required */
#endif

#ifndef EHOSTUNREACH
extern int AVS_NET_EHOSTUNREACH;
#define EHOSTUNREACH AVS_NET_EHOSTUNREACH /**< Host is unreachable */
#endif

#ifndef EINPROGRESS
extern int AVS_NET_EINPROGRESS;
#define EINPROGRESS AVS_NET_EINPROGRESS /**< Operation in progress */
#endif

#ifndef EISCONN
extern int AVS_NET_EISCONN;
#define EISCONN AVS_NET_EISCONN /**< Socket is connected */
#endif

#ifndef EMSGSIZE
extern int AVS_NET_EMSGSIZE;
#define EMSGSIZE AVS_NET_EMSGSIZE /**< Message too large */
#endif

#ifndef ENAMETOOLONG
extern int AVS_NET_ENAMETOOLONG;
#define ENAMETOOLONG AVS_NET_ENAMETOOLONG /**< Filename too long */
#endif

#ifndef ENETDOWN
extern int AVS_NET_ENETDOWN;
#define ENETDOWN AVS_NET_ENETDOWN /**< Network is down */
#endif

#ifndef ENETRESET
extern int AVS_NET_ENETRESET;
#define ENETRESET AVS_NET_ENETRESET /**< Connection aborted by network */
#endif

#ifndef ENETUNREACH
extern int AVS_NET_ENETUNREACH;
#define ENETUNREACH AVS_NET_ENETUNREACH /**< Network unreachable */
#endif

#ifndef ENOBUFS
extern int AVS_NET_ENOBUFS;
#define ENOBUFS AVS_NET_ENOBUFS /**< No buffer space available */
#endif

#ifndef ENODATA
extern int AVS_NET_ENODATA;
/** No message is available on the STREAM head read queue */
#define ENODATA AVS_NET_ENODATA
#endif

#ifndef ENOLINK
extern int AVS_NET_ENOLINK;
#define ENOLINK AVS_NET_ENOLINK /**< Link has been severed */
#endif

#ifndef ENOMSG
extern int AVS_NET_ENOMSG;
#define ENOMSG AVS_NET_ENOMSG /**< No message of the desired type */
#endif

#ifndef ENOPROTOOPT
extern int AVS_NET_ENOPROTOOPT;
#define ENOPROTOOPT AVS_NET_ENOPROTOOPT /**< Protocol not available */
#endif

#ifndef ENOSR
extern int AVS_NET_ENOSR;
#define ENOSR AVS_NET_ENOSR /**< No STREAM resources */
#endif

#ifndef ENOSYS
extern int AVS_NET_ENOSYS;
#define ENOSYS AVS_NET_ENOSYS /**< Function not supported */
#endif

#ifndef ENOTCONN
extern int AVS_NET_ENOTCONN;
#define ENOTCONN AVS_NET_ENOTCONN /**< The socket is not connected */
#endif

#ifndef ENOTSOCK
extern int AVS_NET_ENOTSOCK;
#define ENOTSOCK AVS_NET_ENOTSOCK /**< Not a socket */
#endif

#ifndef ENOTSUP
extern int AVS_NET_ENOTSUP;
#define ENOTSUP AVS_NET_ENOTSUP /**< Not supported */
#endif

#ifndef EOPNOTSUPP
extern int AVS_NET_EOPNOTSUPP;
#define EOPNOTSUPP AVS_NET_EOPNOTSUPP /**< Operation not supported on socket */
#endif

#ifndef EOVERFLOW
extern int AVS_NET_EOVERFLOW;
/*** Value too large to be stored in data type */
#define EOVERFLOW AVS_NET_EOVERFLOW
#endif

#ifndef EPROTO
extern int AVS_NET_EPROTO;
#define EPROTO AVS_NET_EPROTO /**< Protocol error */
#endif

#ifndef EPROTONOSUPPORT
extern int AVS_NET_EPROTONOSUPPORT;
#define EPROTONOSUPPORT AVS_NET_EPROTONOSUPPORT /**< Protocol not supported */
#endif

#ifndef EPROTOTYPE
extern int AVS_NET_EPROTOTYPE;
#define EPROTOTYPE AVS_NET_EPROTOTYPE /**< Protocol wrong type for socket */
#endif

#ifndef ETIME
extern int AVS_NET_ETIME;
#define ETIME AVS_NET_ETIME /**< Stream ioctl() timeout */
#endif

#ifndef ETIMEDOUT
extern int AVS_NET_ETIMEDOUT;
#define ETIMEDOUT AVS_NET_ETIMEDOUT /**<  Connection timed out */
#endif

#ifndef EWOULDBLOCK
extern int AVS_NET_EWOULDBLOCK;
#define EWOULDBLOCK AVS_NET_EWOULDBLOCK /**< Operation would block */
#endif

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_NET_ERRNO_H */
