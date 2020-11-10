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

#ifndef COMPAT_H
#define COMPAT_H

#if defined(_WINDOWS_) || defined(_WIN32_WINNT)
#    error "winsock-posix-compat.h needs to be included before windows.h or _mingw.h"
#endif

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x600 // minimum requirement: Windows NT 6.0 a.k.a. Vista

#include <winsock2.h>
#include <ws2tcpip.h>

#include <assert.h>
#include <time.h>

#include <errno.h>

#include <avsystem/commons/avs_errno_map.h>

#ifdef ERROR
// Windows headers are REALLY weird. winsock2.h includes windows.h, which
// includes wingdi.h, even with WIN32_LEAN_AND_MEAN. And wingdi.h defines
// a macro called ERROR, which conflicts with avs_log() usage.
#    undef ERROR
#endif // ERROR

typedef u_short sa_family_t;

#define SHUT_RDWR SD_BOTH

static inline int _avs_map_wsaerror(int wsaerror) {
    switch (wsaerror) {
    case WSAEWOULDBLOCK:
        return EWOULDBLOCK;
    case WSAEINPROGRESS:
        return EINPROGRESS;
    case WSAEALREADY:
        return EALREADY;
    case WSAENOTSOCK:
        return ENOTSOCK;
    case WSAEDESTADDRREQ:
        return EDESTADDRREQ;
    case WSAEMSGSIZE:
        return EMSGSIZE;
    case WSAEPROTOTYPE:
        return EPROTOTYPE;
    case WSAENOPROTOOPT:
        return ENOPROTOOPT;
    case WSAEPROTONOSUPPORT:
        return EPROTONOSUPPORT;
    case WSAEOPNOTSUPP:
        return EOPNOTSUPP;
    case WSAEAFNOSUPPORT:
        return EAFNOSUPPORT;
    case WSAEADDRINUSE:
        return EADDRINUSE;
    case WSAEADDRNOTAVAIL:
        return EADDRNOTAVAIL;
    case WSAENETDOWN:
        return ENETDOWN;
    case WSAENETUNREACH:
        return ENETUNREACH;
    case WSAENETRESET:
        return ENETRESET;
    case WSAECONNABORTED:
        return ECONNABORTED;
    case WSAECONNRESET:
        return ECONNRESET;
    case WSAENOBUFS:
        return ENOBUFS;
    case WSAEISCONN:
        return EISCONN;
    case WSAENOTCONN:
        return ENOTCONN;
    case WSAETIMEDOUT:
        return ETIMEDOUT;
    case WSAECONNREFUSED:
        return ECONNREFUSED;
    case WSAELOOP:
        return ELOOP;
    case WSAENAMETOOLONG:
        return ENAMETOOLONG;
    case WSAEHOSTUNREACH:
        return EHOSTUNREACH;
    case WSAENOTEMPTY:
        return ENOTEMPTY;
    default:
        return wsaerror;
    }
}

// The following functions are intended to be called as:
//
//     _avs_wsa_set_errno(WSASomething(...));
//
// They forward the result of the WSA function and assign the translated value
// of WSAGetLastError() to the standard errno variable.
//
// The three variants handle three possible return types of the WSA functions
// we use.

static inline int _avs_wsa_set_errno(int result) {
    errno = _avs_map_wsaerror(WSAGetLastError());
    return result;
}

static inline int _avs_wsa_set_errno_connect(int result) {
    int wsaerror = WSAGetLastError();
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms737625(v=vs.85).aspx
    // Of course Windows needs to use a completely different error code for
    // non-blocking connect() than the rest of the world :/
    if (wsaerror == WSAEWOULDBLOCK) {
        errno = EINPROGRESS;
    } else {
        errno = _avs_map_wsaerror(WSAGetLastError());
    }
    return result;
}

static inline SOCKET _avs_wsa_set_errno_socket(SOCKET result) {
    errno = _avs_map_wsaerror(WSAGetLastError());
    return result;
}

static inline const char *_avs_wsa_set_errno_str(const char *result) {
    errno = _avs_map_wsaerror(WSAGetLastError());
    return result;
}

#define AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GAI_STRERROR
#define AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_GETNAMEINFO
#define AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_INET_NTOP
#define AVS_COMMONS_NET_POSIX_AVS_SOCKET_HAVE_POLL

#define accept(...) _avs_wsa_set_errno_socket(accept(__VA_ARGS__))
#define bind(...) _avs_wsa_set_errno(bind(__VA_ARGS__))
#define close(...) _avs_wsa_set_errno(closesocket(__VA_ARGS__))
#define connect(...) _avs_wsa_set_errno_connect(connect(__VA_ARGS__))
#define getnameinfo(Addr, Addrlen, Host, Hostlen, Serv, Servlen, Flags) \
    _avs_wsa_set_errno(getnameinfo((Addr), (Addrlen), (Host),           \
                                   (DWORD) (Hostlen), (Serv),           \
                                   (DWORD) (Servlen), (Flags)))
#define getpeername(...) _avs_wsa_set_errno(getpeername(__VA_ARGS__))
#define getsockname(...) _avs_wsa_set_errno(getsockname(__VA_ARGS__))
#define getsockopt(Sockfd, Level, Name, Val, Len) \
    _avs_wsa_set_errno(                           \
            getsockopt((Sockfd), (Level), (Name), (char *) (Val), (Len)))
#define inet_ntop(Af, Src, Dst, Size)                                        \
    _avs_wsa_set_errno_str(inet_ntop((Af), (void *) (intptr_t) (Src), (Dst), \
                                     (size_t) (Size)))
#define listen(...) _avs_wsa_set_errno(listen(__VA_ARGS__))
#define poll(...) _avs_wsa_set_errno(WSAPoll(__VA_ARGS__))
#define recvfrom(Sockfd, Buf, Len, ...) \
    _avs_wsa_set_errno(                 \
            recvfrom((Sockfd), (char *) (Buf), (int) (Len), __VA_ARGS__))
#define send(Sockfd, Buf, Len, Flags) \
    _avs_wsa_set_errno(send((Sockfd), (Buf), (int) (Len), (Flags)))
#define sendto(Sockfd, Buf, Len, ...) \
    _avs_wsa_set_errno(               \
            sendto((Sockfd), (const char *) (Buf), (int) (Len), __VA_ARGS__))
#define setsockopt(Sockfd, Level, Name, Val, Len)            \
    _avs_wsa_set_errno(setsockopt((Sockfd), (Level), (Name), \
                                  (const char *) (Val), (Len)))
#define shutdown(...) _avs_wsa_set_errno(shutdown(__VA_ARGS__))
#define socket(...) _avs_wsa_set_errno_socket(socket(__VA_ARGS__))

// The following are only used for locally implemented functions
// The values from Linux are used, but they can really be anything
#define F_SETFL 4
#define O_NONBLOCK 04000

static inline int fcntl(SOCKET fd, int cmd, int value) {
    assert(cmd == F_SETFL);
    u_long ulong_value = ((value & O_NONBLOCK) ? 1 : 0);
    return _avs_wsa_set_errno(ioctlsocket(fd, (int) FIONBIO, &ulong_value));
}

#define HAVE_GLOBAL_COMPAT_STATE

static inline avs_error_t initialize_global_compat_state(void) {
    int result = WSAStartup(MAKEWORD(2, 2), &(WSADATA) { 0 });
    if (result) {
        return avs_errno(avs_map_errno(_avs_map_wsaerror(result)));
    }
    return AVS_OK;
}

static inline void cleanup_global_compat_state(void) {
    WSACleanup();
}

typedef SOCKET sockfd_t;

#endif /* COMPAT_H */
