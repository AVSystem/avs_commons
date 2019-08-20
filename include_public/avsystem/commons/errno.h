/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Errno constants are sometimes used in the Commons library, most notably in
 * the <c>avs_net</c> and <c>avs_stream</c> modules as error codes that may be
 * reported through @ref avs_net_socket_errno and @ref avs_stream_errno.
 *
 * The problem with errno, however, is that it is very poorly defined. In fact,
 * the C standard only specifies <c>EDOM</c>, <c>EILSEQ</c> and <c>ERANGE</c>
 * as standard, which is very limiting.
 *
 * In the past, we mitigated this problem by defining missing errno codes to
 * the values that are common across architectures. Unfortunately it often
 * resulted in problems with errno mapping between translation units (i.e.
 * depending on the actual errno.h included in a given translation unit the
 * errno values could have different meaning and it caused lots of issues
 * between different abstraction layers and even across different projects).
 *
 * As a final (hopefully) solution, we introduce an enum over all used errno
 * values. Values of that enum WILL BE consistent across translation units,
 * and methods that previously returned errno directly now have to remap that
 * errno to an appropriate <c>avs_errno_t</c> constant.
 *
 * To avoid boring errno remapping logic, we implemented a header only
 * @ref avs_map_errno() function (see <c>errno_map.h</c>), which, depending on
 * the context in which it is included is able to translate specific errno
 * values to and consistent set of <c>avs_errno_t</c> values.
 */
typedef enum avs_errno {
    AVS_UNKNOWN_ERROR = INT_MIN,
    AVS_NO_ERROR = 0,
    AVS_E2BIG,
    AVS_EACCES,
    AVS_EADDRINUSE,
    AVS_EADDRNOTAVAIL,
    AVS_EAFNOSUPPORT,
    AVS_EAGAIN,
    AVS_EALREADY,
    AVS_EBADF,
    AVS_EBADMSG,
    AVS_EBUSY,
    AVS_ECHILD,
    AVS_ECONNABORTED,
    AVS_ECONNREFUSED,
    AVS_ECONNRESET,
    AVS_EDEADLK,
    AVS_EDESTADDRREQ,
    AVS_EDOM,
    AVS_EEXIST,
    AVS_EFAULT,
    AVS_EFBIG,
    AVS_EHOSTUNREACH,
    AVS_EINPROGRESS,
    AVS_EINTR,
    AVS_EINVAL,
    AVS_EIO,
    AVS_EISCONN,
    AVS_EISDIR,
    AVS_ELOOP,
    AVS_EMFILE,
    AVS_EMLINK,
    AVS_EMSGSIZE,
    AVS_ENAMETOOLONG,
    AVS_ENETDOWN,
    AVS_ENETRESET,
    AVS_ENETUNREACH,
    AVS_ENFILE,
    AVS_ENOBUFS,
    AVS_ENODEV,
    AVS_ENOENT,
    AVS_ENOEXEC,
    AVS_ENOLINK,
    AVS_ENOMEM,
    AVS_ENOMSG,
    AVS_ENOPROTOOPT,
    AVS_ENOSPC,
    AVS_ENOSYS,
    AVS_ENOTBLK,
    AVS_ENOTCONN,
    AVS_ENOTDIR,
    AVS_ENOTEMPTY,
    AVS_ENOTSOCK,
    AVS_ENOTSUP,
    AVS_ENOTTY,
    AVS_ENXIO,
    AVS_EOVERFLOW,
    AVS_EPERM,
    AVS_EPIPE,
    AVS_EPROTO,
    AVS_EPROTONOSUPPORT,
    AVS_EPROTOTYPE,
    AVS_ERANGE,
    AVS_EROFS,
    AVS_ESPIPE,
    AVS_ESRCH,
    AVS_ETIMEDOUT,
    AVS_ETXTBSY,
    AVS_EXDEV
} avs_errno_t;

/**
 * Behaves like POSIX strerror(), but operates on @ref avs_errno_t values
 * instead.
 *
 * @param error Error whose string representation shall be returned.
 *
 * @returns pointer to a string literal describing the error.
 */
const char *avs_strerror(avs_errno_t error);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_ERRNO_H */
