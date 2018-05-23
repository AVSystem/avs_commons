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

#ifndef COMPAT_H
#define COMPAT_H

#include <winsock2.h>
#include <ws2tcpip.h>

#include <assert.h>
#include <time.h>

#ifdef ERROR
#undef ERROR
#endif

typedef u_short sa_family_t;

#define SHUT_RDWR SD_BOTH

#define close closesocket
#define getsockopt(Sockfd, Level, Name, Val, Len) \
        (getsockopt)((Sockfd), (Level), (Name), (char *) (Val), (Len))
#define setsockopt(Sockfd, Level, Name, Val, Len) \
        (setsockopt)((Sockfd), (Level), (Name), (const char *) (Val), (Len))

// The following are only used for locally implemented functions
// The values from Linux are used, but they can really be anything
#define F_SETFL 4
#define O_NONBLOCK 04000

static inline int fcntl(int fd, int cmd, int value) {
    assert(cmd == F_SETFL);
    u_long ulong_value = ((value & O_NONBLOCK) ? 1 : 0);
    return ioctlsocket(fd, FIONBIO, &ulong_value);
}

#warning "TODO: errno"

#endif /* COMPAT_H */
