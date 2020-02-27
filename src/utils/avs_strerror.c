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

#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_UTILS

#    include <avsystem/commons/avs_errno.h>

VISIBILITY_SOURCE_BEGIN

// Based on:
// https://code.woboq.org/userspace/glibc/sysdeps/gnu/errlist.c.html#_sys_errlist_internal
const char *avs_strerror(avs_errno_t error) {
    switch (error) {
    case AVS_NO_ERROR:
        return "Success";
    case AVS_E2BIG:
        return "Argument list too long";
    case AVS_EACCES:
        return "Permission denied";
    case AVS_EADDRINUSE:
        return "Address already in use";
    case AVS_EADDRNOTAVAIL:
        return "Cannot assign requested address";
    case AVS_EAFNOSUPPORT:
        return "Address family not supported by protocol";
    case AVS_EAGAIN:
        return "Resource temporarily unavailable";
    case AVS_EALREADY:
        return "Operation already in progress";
    case AVS_EBADF:
        return "Bad file descriptor";
    case AVS_EBADMSG:
        return "Bad message";
    case AVS_EBUSY:
        return "Device or resource busy";
    case AVS_ECHILD:
        return "No child processes";
    case AVS_ECONNABORTED:
        return "Software caused connection abort";
    case AVS_ECONNREFUSED:
        return "Connection refused";
    case AVS_ECONNRESET:
        return "Connection reset by peer";
    case AVS_EDEADLK:
        return "Resource deadlock avoided";
    case AVS_EDESTADDRREQ:
        return "Destination address required";
    case AVS_EDOM:
        return "Numerical argument out of domain";
    case AVS_EEXIST:
        return "File exists";
    case AVS_EFAULT:
        return "Bad address";
    case AVS_EFBIG:
        return "File too large";
    case AVS_EHOSTUNREACH:
        return "No route to host";
    case AVS_EINPROGRESS:
        return "Operation now in progress";
    case AVS_EINTR:
        return "Interrupted system call";
    case AVS_EINVAL:
        return "Invalid argument";
    case AVS_EIO:
        return "Input/output error";
    case AVS_EISCONN:
        return "Transport endpoint is already connected";
    case AVS_EISDIR:
        return "Is a directory";
    case AVS_ELOOP:
        return "Too many levels of symbolic links";
    case AVS_EMFILE:
        return "Too many open files";
    case AVS_EMLINK:
        return "Too many links";
    case AVS_EMSGSIZE:
        return "Message too long";
    case AVS_ENAMETOOLONG:
        return "File name too long";
    case AVS_ENETDOWN:
        return "Network is down";
    case AVS_ENETRESET:
        return "Network dropped connection on reset";
    case AVS_ENETUNREACH:
        return "Network is unreachable";
    case AVS_ENFILE:
        return "Too many open files in system";
    case AVS_ENOBUFS:
        return "No buffer space available";
    case AVS_ENODEV:
        return "No such device";
    case AVS_ENOENT:
        return "No such file or directory";
    case AVS_ENOEXEC:
        return "Exec format error";
    case AVS_ENOLINK:
        return "Link has been severed";
    case AVS_ENOMEM:
        return "Cannot allocate memory";
    case AVS_ENOMSG:
        return "No message of desired type";
    case AVS_ENOPROTOOPT:
        return "Protocol not available";
    case AVS_ENOSPC:
        return "No space left on device";
    case AVS_ENOSYS:
        return "Function not implemented";
    case AVS_ENOTBLK:
        return "Block device required";
    case AVS_ENOTCONN:
        return "Transport endpoint is not connected";
    case AVS_ENOTDIR:
        return "Not a directory";
    case AVS_ENOTEMPTY:
        return "Directory not empty";
    case AVS_ENOTSOCK:
        return "Socket operation on non-socket";
    case AVS_ENOTSUP:
        return "Not supported";
    case AVS_ENOTTY:
        return "Inappropriate ioctl for device";
    case AVS_ENXIO:
        return "No such device or address";
    case AVS_EOVERFLOW:
        return "Value too large for defined data type";
    case AVS_EPERM:
        return "Operation not permitted";
    case AVS_EPIPE:
        return "Broken pipe";
    case AVS_EPROTO:
        return "Protocol error";
    case AVS_EPROTONOSUPPORT:
        return "Protocol not supported";
    case AVS_EPROTOTYPE:
        return "Protocol wrong type for socket";
    case AVS_ERANGE:
        return "Numerical result out of range";
    case AVS_EROFS:
        return "Read-only file system";
    case AVS_ESPIPE:
        return "Illegal seek";
    case AVS_ESRCH:
        return "No such process";
    case AVS_ETIMEDOUT:
        return "Connection timed out";
    case AVS_ETXTBSY:
        return "Text file busy";
    case AVS_EXDEV:
        return "Invalid cross-device link";
    case AVS_UNKNOWN_ERROR:
        return "Unknown error";
    }
    return "<unsupported error code>";
}

#endif // AVS_COMMONS_WITH_AVS_UTILS
