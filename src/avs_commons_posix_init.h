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

#ifndef AVS_COMMONS_POSIX_INIT_H
#define AVS_COMMONS_POSIX_INIT_H

#include <avsystem/commons/avs_commons_config.h>

#ifndef AVS_COMMONS_POSIX_COMPAT_HEADER

// by default we try to compile in strict ISO C99 mode;
// if it's enabled, then declare _POSIX_C_SOURCE to enable POSIX APIs;
// unless on macOS - Apple's headers do not support strict ISO C99 mode in the
// way glibc and BSD libc do, and _POSIX_C_SOURCE only enables "strict POSIX"
// mode, i.e. disables a lot of APIs; it doesn't even properly recognize the
// 200809L value, so it disables a lot of APIs that actually are in POSIX...
#    if (defined(__STRICT_ANSI__) || defined(_ISOC99_SOURCE)) \
            && !defined(_POSIX_C_SOURCE) && !defined(__APPLE__)
#        define _POSIX_C_SOURCE 200809L
#    endif

#    include <arpa/inet.h>
#    include <fcntl.h>
#    include <net/if.h>
#    include <netdb.h>
#    include <netinet/in.h>
#    include <poll.h>
#    include <strings.h>
#    include <sys/select.h>
#    include <sys/socket.h>
#    include <sys/time.h>
#    include <sys/types.h>
#    include <sys/wait.h>
#    include <time.h>
#    include <unistd.h>
typedef int sockfd_t;
#else // AVS_COMMONS_POSIX_COMPAT_HEADER
#    include AVS_COMMONS_POSIX_COMPAT_HEADER
// If POSIX socket APIs are implemented as macros (e.g. LwIP), redefining
// common words like close to something else wreaks havoc all over the place.
#    ifndef _AVS_NEED_POSIX_SOCKET
#        ifdef accept
#            undef accept
#        endif
#        ifdef bind
#            undef bind
#        endif
#        ifdef shutdown
#            undef shutdown
#        endif
#        ifdef connect
#            undef connect
#        endif
#        ifdef listen
#            undef listen
#        endif
#        ifdef recv
#            undef recv
#        endif
#        ifdef send
#            undef send
#        endif
#        ifdef socket
#            undef socket
#        endif
#        ifdef select
#            undef select
#        endif
#        ifdef read
#            undef read
#        endif
#        ifdef write
#            undef write
#        endif
#        ifdef close
#            undef close
#        endif
#    endif // _AVS_NEED_POSIX_SOCKET
#endif     // AVS_COMMONS_POSIX_COMPAT_HEADER

#ifndef INVALID_SOCKET
#    define INVALID_SOCKET (-1)
#endif

#include <avs_commons_init.h>

#endif /* AVS_COMMONS_POSIX_INIT_H */
