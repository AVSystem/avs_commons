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

#ifndef AVS_COMMONS_ERRNO_H
#define AVS_COMMONS_ERRNO_H

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file errno.h
 *
 * Error constant definitions.
 *
 * Errno constants are sometimes used in the Commons library, most notably in
 * the <c>avs_net</c> and <c>avs_stream</c> modules as error codes that may be
 * reported through @ref avs_net_socket_errno and @ref avs_stream_errno.
 * Unfortunately, the C standard only specifies <c>EDOM</c>, <c>EILSEQ</c> and
 * <c>ERANGE</c> as standard, which is very limiting.
 *
 * Many more useful constants has been defined in standards related to Unix-like
 * operating systems (POSIX, SUSv2, IEEE 1003) - those have also been adopted
 * by C++11 and later. However, none of these standards define numerical values
 * of the required constants.
 *
 * This file is composed of two parts:
 * - A subset of errno constants that is common to all sane operating
 *   environments, i.e. the portable "de facto" standard values. This set is
 *   very limited compared to Unix or C++ standards, but it's much better than
 *   plain ISO C.
 * - A subset of errno constants that is relevant for network communication. It
 *   is defined as external symbols compiled in the <c>avs_net</c> component. If
 *   <c>avs_net</c> is not enabled and the constants are not natively available,
 *   using them may lead to link-time errors.
 *
 * The values from the first part have been verified against definitions on the
 * following platforms:
 * - Linux (http://elixir.free-electrons.com/linux/latest/source/include/uapi/asm-generic/errno-base.h)
 * - FreeBSD (https://github.com/freebsd/freebsd/blob/master/sys/sys/errno.h)
 * - NetBSD (https://github.com/IIJ-NetBSD/netbsd-src/blob/master/sys/sys/errno.h)
 * - OpenBSD (https://github.com/openbsd/src/blob/master/sys/sys/errno.h)
 * - macOS (https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX10.8.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/sys/errno.h)
 * - newlib (https://github.com/bminor/newlib/blob/master/newlib/libc/include/sys/errno.h)
 * - MinGW x86 (https://github.com/luzexi/MinGW/blob/master/x86/include/errno.h)
 * - MinGW x64 (https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/crt/errno.h)
 * - Microsoft Visual Studio (https://msdn.microsoft.com/en-us/library/t3ayayh1.aspx)
 * - lwIP (https://github.com/dreamcat4/lwip/blob/master/lwip/src/include/lwip/arch.h)
 */

/* ******** PORTABLE ERRNO CONSTANTS ******** */

#ifndef EPERM
#define EPERM 1 /**< Operation not permitted */
#endif

#ifndef ENOENT
#define ENOENT 2 /**< No such file or directory */
#endif

#ifndef ESRCH
#define ESRCH 3 /**< No such process */
#endif

#ifndef EINTR
#define EINTR 4 /**< Interrupted function */
#endif

#ifndef EIO
#define EIO 5 /**< I/O error */
#endif

#ifndef ENXIO
#define ENXIO 6 /**< No such device or address */
#endif

#ifndef E2BIG
#define E2BIG 7 /**< Argument list too long */
#endif

#ifndef ENOEXEC
#define ENOEXEC 8 /**< Executable file format error */
#endif

#ifndef EBADF
#define EBADF 9 /**<  Bad file descriptor */
#endif

#ifndef ECHILD
#define ECHILD 10 /**< No child processes */
#endif

/*
 * errno == 11 is assigned to EAGAIN on Linux, newlib and Windows, but to
 * EDEADLK on *BSD and macOS. Not defining.
 */

#ifndef ENOMEM
#define ENOMEM 12 /**< Not enough space */
#endif

#ifndef EACCES
#define EACCES 13 /**< Permission denied */
#endif

#ifndef EFAULT
#define EFAULT 14 /**< Bad address */
#endif

/*
 * errno == 15, if assigned, is ENOTBLK, but it's not present on Windows and not
 * defined in any of the Unix or C++ standards. Not defining.
 */

#ifndef EBUSY
#define EBUSY 16 /**< Device or resource busy */
#endif

#ifndef EEXIST
#define EEXIST 17 /**< File exists */
#endif

#ifndef EXDEV
#define EXDEV 18 /**< Cross-device link */
#endif

#ifndef ENODEV
#define ENODEV 19 /**< No such device */
#endif

#ifndef ENOTDIR
#define ENOTDIR 20 /**< Not a directory */
#endif

#ifndef EISDIR
#define EISDIR 21 /**< Is a directory */
#endif

#ifndef EINVAL
#define EINVAL 22 /**< Invalid argument */
#endif

#ifndef ENFILE
#define ENFILE 23 /**< Too many files open in system */
#endif

#ifndef EMFILE
#define EMFILE 24 /**< File descriptor value too large */
#endif

#ifndef ENOTTY
#define ENOTTY 25 /**< Inappropriate I/O control operation */
#endif

/*
 * errno == 26, if assigned, is ETXTBSY, but on Windows, it's not assigned
 * while ETXTBSY is defined to 139 (at least on MinGW-w64; not present on other
 * compilers). Not defining.
 */

#ifndef EFBIG
#define EFBIG 27 /**< File too large */
#endif

#ifndef ENOSPC
#define ENOSPC 28 /**< No space left on device */
#endif

#ifndef ESPIPE
#define ESPIPE 29 /**< Illegal seek */
#endif

#ifndef EROFS
#define EROFS 30 /**< Read-only file system */
#endif

#ifndef EMLINK
#define EMLINK 31 /**< Too many links */
#endif

#ifndef EPIPE
#define EPIPE 32 /**< Broken pipe */
#endif

/*
 * EDOM == 33 and ERANGE == 34 everywhere, but they are required to be defined
 * in errno.h as per the C standard, so not defining them here.
 */

/* ******** AVS_NET ERRNO CONSTANTS ******** */

#ifndef EADDRINUSE
extern const int AVS_NET_EADDRINUSE;
#define EADDRINUSE AVS_NET_EADDRINUSE /**< Address in use */
#endif

#ifndef EADDRNOTAVAIL
extern const int AVS_NET_EADDRNOTAVAIL;
#define EADDRNOTAVAIL AVS_NET_EADDRNOTAVAIL /**< Address not available */
#endif

#ifndef EAFNOSUPPORT
extern const int AVS_NET_EAFNOSUPPORT;
#define EAFNOSUPPORT AVS_NET_EAFNOSUPPORT /**< Address family not supported */
#endif

#ifndef EAGAIN
extern const int AVS_NET_EAGAIN;
#define EAGAIN AVS_NET_EAGAIN /**< Resource unavailable, try again */
#endif

#ifndef EALREADY
extern const int AVS_NET_EALREADY;
#define EALREADY AVS_NET_EALREADY /**< Connection already in progress */
#endif

#ifndef EBADMSG
extern const int AVS_NET_EBADMSG;
#define EBADMSG AVS_NET_EBADMSG /**< Bad message */
#endif

#ifndef ECONNABORTED
extern const int AVS_NET_ECONNABORTED;
#define ECONNABORTED AVS_NET_ECONNABORTED /**< Connection aborted */
#endif

#ifndef ECONNREFUSED
extern const int AVS_NET_ECONNREFUSED;
#define ECONNREFUSED AVS_NET_ECONNREFUSED /**< Connection refused */
#endif

#ifndef ECONNRESET
extern const int AVS_NET_ECONNRESET;
#define ECONNRESET AVS_NET_ECONNRESET /**< Connection reset */
#endif

#ifndef EDESTADDRREQ
extern const int AVS_NET_EDESTADDRREQ;
#define EDESTADDRREQ AVS_NET_EDESTADDRREQ /**< Destination address required */
#endif

#ifndef EHOSTUNREACH
extern const int AVS_NET_EHOSTUNREACH;
#define EHOSTUNREACH AVS_NET_EHOSTUNREACH /**< Host is unreachable */
#endif

#ifndef EINPROGRESS
extern const int AVS_NET_EINPROGRESS;
#define EINPROGRESS AVS_NET_EINPROGRESS /**< Operation in progress */
#endif

#ifndef EISCONN
extern const int AVS_NET_EISCONN;
#define EISCONN AVS_NET_EISCONN /**< Socket is connected */
#endif

#ifndef EMSGSIZE
extern const int AVS_NET_EMSGSIZE;
#define EMSGSIZE AVS_NET_EMSGSIZE /**< Message too large */
#endif

#ifndef ENAMETOOLONG
extern const int AVS_NET_ENAMETOOLONG;
#define ENAMETOOLONG AVS_NET_ENAMETOOLONG /**< Filename too long */
#endif

#ifndef ENETDOWN
extern const int AVS_NET_ENETDOWN;
#define ENETDOWN AVS_NET_ENETDOWN /**< Network is down */
#endif

#ifndef ENETUNREACH
extern const int AVS_NET_ENETUNREACH;
#define ENETUNREACH AVS_NET_ENETUNREACH /**< Network unreachable */
#endif

#ifndef ENOBUFS
extern const int AVS_NET_ENOBUFS;
#define ENOBUFS AVS_NET_ENOBUFS /**< No buffer space available */
#endif

#ifndef ENOLINK
extern const int AVS_NET_ENOLINK;
#define ENOLINK AVS_NET_ENOLINK /**< Link has been severed */
#endif

#ifndef ENOMSG
extern const int AVS_NET_ENOMSG;
#define ENOMSG AVS_NET_ENOMSG /**< No message of the desired type */
#endif

#ifndef ENOPROTOOPT
extern const int AVS_NET_ENOPROTOOPT;
#define ENOPROTOOPT AVS_NET_ENOPROTOOPT /**< Protocol not available */
#endif

#ifndef ENOSYS
extern const int AVS_NET_ENOSYS;
#define ENOSYS AVS_NET_ENOSYS /**< Function not supported */
#endif

#ifndef ENOTCONN
extern const int AVS_NET_ENOTCONN;
#define ENOTCONN AVS_NET_ENOTCONN /**< The socket is not connected */
#endif

#ifndef ENOTSOCK
extern const int AVS_NET_ENOTSOCK;
#define ENOTSOCK AVS_NET_ENOTSOCK /**< Not a socket */
#endif

#ifndef ENOTSUP
extern const int AVS_NET_ENOTSUP;
#define ENOTSUP AVS_NET_ENOTSUP /**< Not supported */
#endif

#ifndef EOPNOTSUPP
extern const int AVS_NET_EOPNOTSUPP;
#define EOPNOTSUPP AVS_NET_EOPNOTSUPP /**< Operation not supported on socket */
#endif

#ifndef EOVERFLOW
extern const int AVS_NET_EOVERFLOW;
/*** Value too large to be stored in data type */
#define EOVERFLOW AVS_NET_EOVERFLOW
#endif

#ifndef EPROTO
extern const int AVS_NET_EPROTO;
#define EPROTO AVS_NET_EPROTO /**< Protocol error */
#endif

#ifndef EPROTONOSUPPORT
extern const int AVS_NET_EPROTONOSUPPORT;
#define EPROTONOSUPPORT AVS_NET_EPROTONOSUPPORT /**< Protocol not supported */
#endif

#ifndef EPROTOTYPE
extern const int AVS_NET_EPROTOTYPE;
#define EPROTOTYPE AVS_NET_EPROTOTYPE /**< Protocol wrong type for socket */
#endif

#ifndef ETIMEDOUT
extern const int AVS_NET_ETIMEDOUT;
#define ETIMEDOUT AVS_NET_ETIMEDOUT /**<  Connection timed out */
#endif

#ifndef EWOULDBLOCK
extern const int AVS_NET_EWOULDBLOCK;
#define EWOULDBLOCK AVS_NET_EWOULDBLOCK /**< Operation would block */
#endif

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_ERRNO_H */
