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

#ifndef AVS_COMMONS_ERRNO_MAP_H
#define AVS_COMMONS_ERRNO_MAP_H

#include <avsystem/commons/avs_errno.h>

#ifdef __cplusplus
extern "C" {
#endif

// Note: It might seem more appropriate to write #ifndef errno, but even though
// ISO C defines errno as being a macro, on some platforms (e.g. lwIP) it isn't
// a macro, but rather just an external linkage symbol.
#ifndef EDOM
#    error "For this header to be useful, you have to include your system / library / whatever errno.h first."
#endif // EDOM

/**
 * A function that can be used to translate context specific errno values (i.e.
 * depending on the library / system / network layer used) to a set of portable
 * avs_errno_t constants.
 *
 * NOTE: due to POSIX allowance to have some errno codes with the same value:
 *  - EAGAIN and EWOULDBLOCK are coerced into single AVS_EAGAIN,
 *  - ENOTSUP and EOPNOTSUPP are coerced into single AVS_ENOTSUP.
 *
 * @param errno_value   Errno code to be translated.
 * @returns an appropriate @ref avs_errno_t code, or @ref AVS_UNKNOWN_ERROR if
 *          the @p errno_value could not be mapped to any code.
 */
static inline avs_errno_t avs_map_errno(int errno_value) {
    switch (errno_value) {
    case 0:
        return AVS_NO_ERROR;
#ifdef E2BIG
    case E2BIG:
        return AVS_E2BIG;
#endif
#ifdef EACCES
    case EACCES:
        return AVS_EACCES;
#endif
#ifdef EADDRINUSE
    case EADDRINUSE:
        return AVS_EADDRINUSE;
#endif
#ifdef EADDRNOTAVAIL
    case EADDRNOTAVAIL:
        return AVS_EADDRNOTAVAIL;
#endif
#ifdef EAFNOSUPPORT
    case EAFNOSUPPORT:
        return AVS_EAFNOSUPPORT;
#endif
/**
 * NOTE: EAGAIN and EWOULDBLOCK are allowed to have same value (thanks POSIX),
 * and we need to be prepared for that.
 */
#ifdef EAGAIN
    case EAGAIN:
        return AVS_EAGAIN;
#endif
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
    case EWOULDBLOCK:
        return AVS_EAGAIN;
#endif
#ifdef EALREADY
    case EALREADY:
        return AVS_EALREADY;
#endif
#ifdef EBADF
    case EBADF:
        return AVS_EBADF;
#endif
#ifdef EBADMSG
    case EBADMSG:
        return AVS_EBADMSG;
#endif
#ifdef EBUSY
    case EBUSY:
        return AVS_EBUSY;
#endif
#ifdef ECHILD
    case ECHILD:
        return AVS_ECHILD;
#endif
#ifdef ECONNABORTED
    case ECONNABORTED:
        return AVS_ECONNABORTED;
#endif
#ifdef ECONNREFUSED
    case ECONNREFUSED:
        return AVS_ECONNREFUSED;
#endif
#ifdef ECONNRESET
    case ECONNRESET:
        return AVS_ECONNRESET;
#endif
#ifdef EDEADLK
    case EDEADLK:
        return AVS_EDEADLK;
#endif
#ifdef EDESTADDRREQ
    case EDESTADDRREQ:
        return AVS_EDESTADDRREQ;
#endif
#ifdef EDOM
    case EDOM:
        return AVS_EDOM;
#endif
#ifdef EEXIST
    case EEXIST:
        return AVS_EEXIST;
#endif
#ifdef EFAULT
    case EFAULT:
        return AVS_EFAULT;
#endif
#ifdef EFBIG
    case EFBIG:
        return AVS_EFBIG;
#endif
#ifdef EHOSTUNREACH
    case EHOSTUNREACH:
        return AVS_EHOSTUNREACH;
#endif
#ifdef EINPROGRESS
    case EINPROGRESS:
        return AVS_EINPROGRESS;
#endif
#ifdef EINTR
    case EINTR:
        return AVS_EINTR;
#endif
#ifdef EINVAL
    case EINVAL:
        return AVS_EINVAL;
#endif
#ifdef EIO
    case EIO:
        return AVS_EIO;
#endif
#ifdef EISCONN
    case EISCONN:
        return AVS_EISCONN;
#endif
#ifdef EISDIR
    case EISDIR:
        return AVS_EISDIR;
#endif
#ifdef EMFILE
    case EMFILE:
        return AVS_EMFILE;
#endif
#ifdef EMLINK
    case EMLINK:
        return AVS_EMLINK;
#endif
#ifdef EMSGSIZE
    case EMSGSIZE:
        return AVS_EMSGSIZE;
#endif
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
        return AVS_ENAMETOOLONG;
#endif
#ifdef ENETDOWN
    case ENETDOWN:
        return AVS_ENETDOWN;
#endif
#ifdef ENETUNREACH
    case ENETUNREACH:
        return AVS_ENETUNREACH;
#endif
#ifdef ENFILE
    case ENFILE:
        return AVS_ENFILE;
#endif
#ifdef ENOBUFS
    case ENOBUFS:
        return AVS_ENOBUFS;
#endif
#ifdef ENODEV
    case ENODEV:
        return AVS_ENODEV;
#endif
#ifdef ENOENT
    case ENOENT:
        return AVS_ENOENT;
#endif
#ifdef ENOEXEC
    case ENOEXEC:
        return AVS_ENOEXEC;
#endif
#ifdef ENOLINK
    case ENOLINK:
        return AVS_ENOLINK;
#endif
#ifdef ENOMEM
    case ENOMEM:
        return AVS_ENOMEM;
#endif
#ifdef ENOMSG
    case ENOMSG:
        return AVS_ENOMSG;
#endif
#ifdef ENOPROTOOPT
    case ENOPROTOOPT:
        return AVS_ENOPROTOOPT;
#endif
#ifdef ENOSPC
    case ENOSPC:
        return AVS_ENOSPC;
#endif
#ifdef ENOSYS
    case ENOSYS:
        return AVS_ENOSYS;
#endif
#ifdef ENOTBLK
    case ENOTBLK:
        return AVS_ENOTBLK;
#endif
#ifdef ENOTCONN
    case ENOTCONN:
        return AVS_ENOTCONN;
#endif
#ifdef ENOTDIR
    case ENOTDIR:
        return AVS_ENOTDIR;
#endif
#ifdef ENOTSOCK
    case ENOTSOCK:
        return AVS_ENOTSOCK;
#endif
/**
 * NOTE: ENOTSUP and EOPNOTSUPP are allowed to have same value (thanks POSIX),
 * and we need to be prepared for that.
 */
#ifdef ENOTSUP
    case ENOTSUP:
        return AVS_ENOTSUP;
#endif
#if defined(EOPNOTSUPP) && (EOPNOTSUPP != ENOTSUP)
    case EOPNOTSUPP:
        return AVS_ENOTSUP;
#endif
#ifdef ENOTTY
    case ENOTTY:
        return AVS_ENOTTY;
#endif
#ifdef ENXIO
    case ENXIO:
        return AVS_ENXIO;
#endif
#ifdef EOVERFLOW
    case EOVERFLOW:
        return AVS_EOVERFLOW;
#endif
#ifdef EPERM
    case EPERM:
        return AVS_EPERM;
#endif
#ifdef EPIPE
    case EPIPE:
        return AVS_EPIPE;
#endif
#ifdef EPROTO
    case EPROTO:
        return AVS_EPROTO;
#endif
#ifdef EPROTONOSUPPORT
    case EPROTONOSUPPORT:
        return AVS_EPROTONOSUPPORT;
#endif
#ifdef EPROTOTYPE
    case EPROTOTYPE:
        return AVS_EPROTOTYPE;
#endif
#ifdef ERANGE
    case ERANGE:
        return AVS_ERANGE;
#endif
#ifdef EROFS
    case EROFS:
        return AVS_EROFS;
#endif
#ifdef ESPIPE
    case ESPIPE:
        return AVS_ESPIPE;
#endif
#ifdef ESRCH
    case ESRCH:
        return AVS_ESRCH;
#endif
#ifdef ETIMEDOUT
    case ETIMEDOUT:
        return AVS_ETIMEDOUT;
#endif
#ifdef ETXTBSY
    case ETXTBSY:
        return AVS_ETXTBSY;
#endif
#ifdef EXDEV
    case EXDEV:
        return AVS_EXDEV;
#endif
#ifdef ENETRESET
    case ENETRESET:
        return AVS_ENETRESET;
#endif
#ifdef ELOOP
    case ELOOP:
        return AVS_ELOOP;
#endif
#ifdef ENOTEMPTY
    case ENOTEMPTY:
        return AVS_ENOTEMPTY;
#endif
    default:
        return AVS_UNKNOWN_ERROR;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_ERRNO_MAP_H */
