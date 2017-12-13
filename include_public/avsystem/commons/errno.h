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
 * This file defines the subset of errno constants that is common to all sane
 * operating environments, i.e. the "de facto" standard values. The set of
 * available values is very limited compared to Unix or C++ standards, but it's
 * better than plain ISO C.
 *
 * The values have been verified against definitions on the following platforms:
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

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_ERRNO_H */
