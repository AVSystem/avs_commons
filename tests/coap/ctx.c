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

#include <avs_commons_posix_config.h>

#include <avsystem/commons/coap/ctx.h>

#include <signal.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if __linux__
#    include <sys/prctl.h>
#endif // __linux__

#include <avsystem/commons/errno.h>
#include <avsystem/commons/memory.h>
#include <avsystem/commons/stream.h>
#include <avsystem/commons/stream_v_table.h>
#include <avsystem/commons/unit/test.h>
#include <avsystem/commons/utils.h>

#include <avsystem/commons/coap/ctx.h>
#include <avsystem/commons/coap/msg_builder.h>

#include "utils.h"

#include "src/coap/coap_log.h"

#define TEST_PORT_DTLS 4321
#define TEST_PORT_UDP 4322

#define COAP_MSG_MAX_SIZE 1152

typedef enum { TYPE_DTLS, TYPE_UDP } socket_type_t;

typedef struct {
    pid_t pid;
    uint16_t port;
} server_t;

static AVS_LIST(server_t) dtls_servers;
static AVS_LIST(server_t) udp_servers;

static void set_sigusr1_mask(int action) {
    sigset_t set;
    AVS_UNIT_ASSERT_SUCCESS(sigemptyset(&set));
    AVS_UNIT_ASSERT_SUCCESS(sigaddset(&set, SIGUSR1));
    AVS_UNIT_ASSERT_SUCCESS(sigprocmask(action, &set, NULL));
}

static void wait_for_child(void) {
    sigset_t set;
    AVS_UNIT_ASSERT_SUCCESS(sigemptyset(&set));
    AVS_UNIT_ASSERT_SUCCESS(sigaddset(&set, SIGUSR1));
    sigwait(&set, &(int) { -1 });
}

static void kill_servers(void) {
    AVS_LIST_CLEAR(&dtls_servers) {
        kill(dtls_servers->pid, SIGTERM);
    }
    AVS_LIST_CLEAR(&udp_servers) {
        kill(udp_servers->pid, SIGTERM);
    }
}

static void spawn_dtls_echo_server(uint16_t port) {
    server_t *serv;
    AVS_LIST_FOREACH(serv, dtls_servers) {
        if (serv->port == port) {
            LOG(ERROR, _("another server running on port ") "%u", port);
            abort();
            return;
        }
    }

    char port_string[6];
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(port_string, sizeof(port_string), "%u", port)
            >= 0);

    char *cmdline[] = { "./dtls_echo_server",
                        "-cafile",
                        "../certs/server-and-root.crt",
                        "-pkeyfile",
                        "../certs/server.key",
                        "-p",
                        port_string,
                        NULL };
    set_sigusr1_mask(SIG_BLOCK);

    int pid = -1;
    switch (pid = fork()) {
    case 0:
#if __linux__
        if (prctl(PR_SET_PDEATHSIG, SIGHUP)) {
            LOG(WARNING, _("prctl failed: ") "%s", strerror(errno));
        }
#endif // __linux__
        execve(cmdline[0], cmdline, NULL);
        // fall-through
    case -1:
        LOG(ERROR, _("could not start DTLS echo server: ") "%s",
            strerror(errno));
        LOG(ERROR, _("command: ") "%s" _(" ") "%s" _(" ") "%s" _(" ") "%s",
            cmdline[0], cmdline[1], cmdline[2], cmdline[3]);
        abort();
    default:
        break;
    }

    atexit(kill_servers);

    serv = AVS_LIST_NEW_ELEMENT(server_t);
    AVS_UNIT_ASSERT_NOT_NULL(serv);
    serv->pid = pid;
    serv->port = port;
    AVS_LIST_INSERT(&dtls_servers, serv);

    wait_for_child();
    set_sigusr1_mask(SIG_UNBLOCK);
}

static ssize_t
udp_echo(const char *in, size_t in_size, char *out, size_t out_size) {
    if (in_size > out_size) {
        return -1;
    }

    memcpy(out, in, in_size);
    return (ssize_t) in_size;
}

static void udp_echo_serve(uint16_t port) {
    char in_buffer[65535];
    char out_buffer[65535];

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct pollfd sock_pollfd = {
        .fd = sock,
        .events = POLLIN,
        .revents = 0
    };

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
        LOG(ERROR, _("UDP server (127.0.0.1:") "%u" _(") bind failed: ") "%s",
            port, strerror(errno));
        goto cleanup;
    }

    // notify parent
    kill(getppid(), SIGUSR1);

    while (true) {
        if (poll(&sock_pollfd, 1, -1) < 0) {
            LOG(ERROR,
                _("UDP server (127.0.0.1:") "%u" _(") poll failed: ") "%s",
                port, strerror(errno));
            goto cleanup;
        }

        struct sockaddr_in remote_addr;
        memset(&remote_addr, 0, sizeof(remote_addr));
        socklen_t remote_addr_len = sizeof(remote_addr);

        ssize_t bytes_recv =
                recvfrom(sock, in_buffer, sizeof(in_buffer), 0,
                         (struct sockaddr *) &remote_addr, &remote_addr_len);
        if (bytes_recv < 0) {
            LOG(ERROR,
                _("UDP server (127.0.0.1:") "%u" _(") recvfrom failed: ") "%s",
                port, strerror(errno));
            goto cleanup;
        }

        ssize_t bytes_to_send = udp_echo(in_buffer, (size_t) bytes_recv,
                                         out_buffer, sizeof(out_buffer));
        if (bytes_to_send < 0) {
            LOG(ERROR, _("UDP server (127.0.0.1:") "%u" _(") udp_echo failed"),
                port);
            goto cleanup;
        }

        if (sendto(sock, out_buffer, (size_t) bytes_to_send, 0,
                   (struct sockaddr *) &remote_addr, remote_addr_len)
                != bytes_to_send) {
            LOG(ERROR,
                _("UDP server (127.0.0.1:") "%u" _(") sendto failed: ") "%s",
                port, strerror(errno));
            goto cleanup;
        }
    }

cleanup:
    close(sock);
    LOG(ERROR, _("UDP server (127.0.0.1:") "%u" _(") shutting down"), port);
}

static void spawn_udp_echo_server(uint16_t port) {
    server_t *serv;
    AVS_LIST_FOREACH(serv, udp_servers) {
        if (serv->port == port) {
            LOG(ERROR, _("another server running on port ") "%u", port);
            abort();
        }
    }

    set_sigusr1_mask(SIG_BLOCK);

    int pid = -1;
    switch (pid = fork()) {
    case 0:
#if __linux__
        if (prctl(PR_SET_PDEATHSIG, SIGHUP)) {
            LOG(WARNING, _("prctl failed: ") "%s", strerror(errno));
        }
#endif // __linux__
        udp_echo_serve(port);
        // fall-through
    case -1:
        LOG(ERROR, _("could not start UDP server on port ") "%u" _(": ") "%s",
            port, strerror(errno));
        abort();
    default:
        break;
    }

    atexit(kill_servers);

    serv = AVS_LIST_NEW_ELEMENT(server_t);
    AVS_UNIT_ASSERT_NOT_NULL(serv);
    serv->pid = pid;
    serv->port = port;
    AVS_LIST_INSERT(&udp_servers, serv);

    wait_for_child();
    set_sigusr1_mask(SIG_UNBLOCK);
}

static avs_net_socket_t *setup_socket(socket_type_t type, uint16_t port) {
    switch (type) {
    case TYPE_DTLS:
        spawn_dtls_echo_server(port);
        break;
    case TYPE_UDP:
        spawn_udp_echo_server(port);
        break;
    }

    bool use_nosec = (type == TYPE_UDP);
    avs_net_socket_t *backend = NULL;
    static const char *ROOT_CRT_FILE = "../certs/root.crt";
    static const char *CLIENT_CRT_FILE = "../certs/client.crt";
    static const char *CLIENT_KEY_FILE = "../certs/client.key";
    AVS_UNIT_ASSERT_SUCCESS(access(ROOT_CRT_FILE, F_OK));
    AVS_UNIT_ASSERT_SUCCESS(access(CLIENT_CRT_FILE, F_OK));
    AVS_UNIT_ASSERT_SUCCESS(access(CLIENT_KEY_FILE, F_OK));

    avs_net_ssl_configuration_t config = {
        .version = AVS_NET_SSL_VERSION_DEFAULT,
        .security = {
            .mode = AVS_NET_SECURITY_CERTIFICATE,
            .data.cert = {
                .server_cert_validation = true,
                .trusted_certs =
                        avs_net_trusted_cert_info_from_file(ROOT_CRT_FILE),
                .client_cert =
                        avs_net_client_cert_info_from_file(CLIENT_CRT_FILE),
                .client_key =
                        avs_net_client_key_info_from_file(CLIENT_KEY_FILE, NULL)
            }
        },
        .backend_configuration = {
            .address_family = AVS_NET_AF_INET4,
            .forced_mtu = 1500
        }
    };

    char port_str[8];
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(port_str, sizeof(port_str), "%u", port) >= 0);

    avs_net_socket_type_t sock_type =
            use_nosec ? AVS_NET_UDP_SOCKET : AVS_NET_DTLS_SOCKET;
    void *sock_config = use_nosec ? (void *) &config.backend_configuration
                                  : (void *) &config;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_create(&backend, sock_type, sock_config));
    // this doesn't actually do anything,
    // but ensures that bind() and connect() can be used together
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(backend, NULL, NULL));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_connect(backend, "localhost", port_str));

    return backend;
}

AVS_UNIT_TEST(coap_ctx, coap_udp) {
    avs_net_socket_opt_value_t mtu;
    // udp_client_send_recv
    avs_coap_ctx_t *ctx = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_create(&ctx, 0));

    avs_net_socket_t *backend = setup_socket(TYPE_UDP, TEST_PORT_UDP);

    avs_coap_msg_info_t info = avs_coap_msg_info_init();
    info.type = AVS_COAP_MSG_CONFIRMABLE;
    info.code = AVS_COAP_CODE_CONTENT;
    info.identity.msg_id = 4;

    size_t storage_size = COAP_MSG_MAX_SIZE;
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_NOT_NULL(msg);

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_get_opt(backend, AVS_NET_SOCKET_OPT_MTU, &mtu));
    AVS_UNIT_ASSERT_EQUAL(mtu.mtu, 1500);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
            backend, AVS_NET_SOCKET_OPT_INNER_MTU, &mtu));
    AVS_UNIT_ASSERT_EQUAL(mtu.mtu, 1472); // 20 bytes IPv4 + 8 bytes UDP

    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_send(ctx, backend, msg));

    avs_coap_msg_t *recv_msg __attribute__((cleanup(free_msg))) =
            (avs_coap_msg_t *) avs_malloc(COAP_MSG_MAX_SIZE);
    memset(recv_msg, 0, COAP_MSG_MAX_SIZE);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_ctx_recv(ctx, backend, recv_msg, COAP_MSG_MAX_SIZE));

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(recv_msg, msg, msg->length);
    avs_net_socket_cleanup(&backend);
    avs_free(storage);
    avs_coap_ctx_cleanup(&ctx);
}

#ifndef WITHOUT_SSL
AVS_UNIT_TEST(coap_ctx, coap_dtls) {
    avs_net_socket_opt_value_t mtu;
    avs_coap_ctx_t *ctx = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_create(&ctx, 0));

    avs_net_socket_t *backend = setup_socket(TYPE_DTLS, TEST_PORT_DTLS);

    avs_coap_msg_info_t info = avs_coap_msg_info_init();
    info.type = AVS_COAP_MSG_CONFIRMABLE;
    info.code = AVS_COAP_CODE_CONTENT;
    info.identity.msg_id = 4;

    size_t storage_size = COAP_MSG_MAX_SIZE;
    void *storage = avs_malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage), storage_size, &info);

    AVS_UNIT_ASSERT_NOT_NULL(msg);

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_get_opt(backend, AVS_NET_SOCKET_OPT_MTU, &mtu));
    AVS_UNIT_ASSERT_EQUAL(mtu.mtu, 1500);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
            backend, AVS_NET_SOCKET_OPT_INNER_MTU, &mtu));
    // The negotiated cipher is not well-defined, so it's a range:
    // -- minimum ---- maximum --------------------------------------------
    //         20           20      bytes of IPv4 header
    //          8            8      bytes of UDP header
    //         13           13      bytes of DTLS header
    //          0           16      bytes of explicit IV
    //          0           48      bytes of AEAD tag or MD+padding
    // --------------------------------------------------------------------
    //         41          105      bytes of headers subtracted from 1500
    AVS_UNIT_ASSERT_TRUE(mtu.mtu >= 1395 && mtu.mtu <= 1459);

    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_send(ctx, backend, msg));

    avs_coap_msg_t *recv_msg __attribute__((cleanup(free_msg))) =
            (avs_coap_msg_t *) avs_malloc(COAP_MSG_MAX_SIZE);
    memset(recv_msg, 0, COAP_MSG_MAX_SIZE);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_ctx_recv(ctx, backend, recv_msg, COAP_MSG_MAX_SIZE));

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(recv_msg, msg, msg->length);

    // check message truncation
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_send(ctx, backend, msg));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_ctx_recv(ctx, backend, recv_msg,
                                            msg->length + sizeof(msg->length)
                                                    - 1),
                          AVS_COAP_CTX_ERR_MSG_TOO_LONG);
    // check that we don't get any leftover data
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_set_opt(
            backend, AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
            (const avs_net_socket_opt_value_t) {
                .recv_timeout = avs_time_duration_from_scalar(100, AVS_TIME_MS)
            }));
    AVS_UNIT_ASSERT_EQUAL(avs_coap_ctx_recv(ctx, backend, recv_msg,
                                            COAP_MSG_MAX_SIZE),
                          AVS_COAP_CTX_ERR_TIMEOUT);

    avs_net_socket_cleanup(&backend);
    avs_coap_ctx_cleanup(&ctx);
    avs_free(storage);
}
#endif // WITHOUT_SSL
