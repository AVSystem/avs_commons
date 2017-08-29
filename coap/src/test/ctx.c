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
#include <config.h>
#include <posix-config.h>

#include <alloca.h>

#if __linux__
#include <sys/prctl.h>
#endif // __linux__

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include <avsystem/commons/stream.h>
#include <avsystem/commons/stream_v_table.h>
#include <avsystem/commons/unit/test.h>
#include <avsystem/commons/utils.h>

#include <avsystem/commons/coap/msg_builder.h>
#include <avsystem/commons/coap/ctx.h>

#define TEST_PORT_DTLS 4321
#define TEST_PORT_UDP 4322

#define COAP_MSG_MAX_SIZE 1152

typedef struct {
    uint16_t port;
    pid_t pid;
} dtls_server_t;

static AVS_LIST(dtls_server_t) dtls_servers;

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
    sigwait(&set, &(int){ -1 });
}

static void kill_servers(void) {
    AVS_LIST_CLEAR(&dtls_servers) {
        kill(dtls_servers->pid, SIGTERM);
    }
}

static void spawn_dtls_echo_server(uint16_t port) {
    dtls_server_t *serv;
    AVS_LIST_FOREACH(serv, dtls_servers) {
        if (serv->port == port) {
            LOG(ERROR, "another server running on port %u", port);
            abort();
            return;
        }
    }

    char port_string[6];
    AVS_UNIT_ASSERT_TRUE(avs_simple_snprintf(port_string, sizeof(port_string), "%u", port) >= 0);

    char *cmdline[] = {
        AVS_TEST_BIN_DIR "/../tools/dtls_echo_server",
        "-cafile", AVS_TEST_BIN_DIR "/certs/server-and-root.crt",
        "-pkeyfile", AVS_TEST_BIN_DIR "/certs/server.key",
        "-p", port_string,
        NULL
    };
    set_sigusr1_mask(SIG_BLOCK);

    int pid = -1;
    switch (pid = fork()) {
    case 0:
#if __linux__
        if (prctl(PR_SET_PDEATHSIG, SIGHUP)) {
            LOG(WARNING, "prctl failed: %s", strerror(errno));
        }
#endif // __linux__
        execve(cmdline[0], cmdline, NULL);
        // fall-through
    case -1:
        LOG(ERROR, "could not start DTLS echo server: %s", strerror(errno));
        LOG(ERROR, "command: %s %s %s %s", cmdline[0], cmdline[1], cmdline[2], cmdline[3]);
        abort();
    default:
        break;
    }

    atexit(kill_servers);

    serv = AVS_LIST_NEW_ELEMENT(dtls_server_t);
    AVS_UNIT_ASSERT_NOT_NULL(serv);
    serv->pid = pid;
    serv->port = port;
    AVS_LIST_INSERT(&dtls_servers, serv);

    wait_for_child();
    set_sigusr1_mask(SIG_UNBLOCK);
}

static avs_net_abstract_socket_t *setup_dtls_socket(uint16_t port) {
    spawn_dtls_echo_server(port);
    avs_net_abstract_socket_t *backend = NULL;
    static const char *ROOT_CRT_FILE = AVS_TEST_BIN_DIR "/certs/root.crt";
    static const char *CLIENT_CRT_FILE = AVS_TEST_BIN_DIR "/certs/client.crt";
    static const char *CLIENT_KEY_FILE = AVS_TEST_BIN_DIR "/certs/client.key";
    AVS_UNIT_ASSERT_SUCCESS(access(ROOT_CRT_FILE, F_OK));
    AVS_UNIT_ASSERT_SUCCESS(access(CLIENT_CRT_FILE, F_OK));
    AVS_UNIT_ASSERT_SUCCESS(access(CLIENT_KEY_FILE, F_OK));

    avs_net_ssl_configuration_t config = {
        .version = AVS_NET_SSL_VERSION_DEFAULT,
        .security = {
            .mode = AVS_NET_SECURITY_CERTIFICATE,
            .data.cert = {
                .server_cert_validation = true,
                .trusted_certs = avs_net_trusted_cert_source_from_paths(
                                        NULL, ROOT_CRT_FILE),
                .client_cert = avs_net_client_cert_from_file(
                                        CLIENT_CRT_FILE, NULL,
                                        AVS_NET_DATA_FORMAT_PEM),
                .client_key = avs_net_private_key_from_file(
                                        CLIENT_KEY_FILE, NULL,
                                        AVS_NET_DATA_FORMAT_PEM)
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

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_create(&backend, AVS_NET_DTLS_SOCKET, &config));
    // this doesn't actually do anything,
    // but ensures that bind() and connect() can be used together
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(backend, NULL, NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(backend, "localhost", port_str));

    return backend;
}

#if 0
AVS_UNIT_TEST(coap_ctx, coap_udp) {
    avs_net_socket_opt_value_t mtu;
    // udp_client_send_recv
    avs_coap_ctx_t *ctx = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_create(&ctx, 0));

    avs_net_abstract_socket_t *backend = setup_dtls_socket(TEST_PORT_DTLS);

    avs_coap_msg_info_t info = avs_coap_msg_info_init();
    info.type = AVS_COAP_MSG_CONFIRMABLE;
    info.code = AVS_COAP_CODE_CONTENT;
    info.identity.msg_id = 4;

    size_t storage_size = COAP_MSG_MAX_SIZE;
    void *storage = malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage),
            storage_size, &info);

    AVS_UNIT_ASSERT_NOT_NULL(msg);

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
            backend, AVS_NET_SOCKET_OPT_MTU, &mtu));
    AVS_UNIT_ASSERT_EQUAL(mtu.mtu, 1500);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
            backend, AVS_NET_SOCKET_OPT_INNER_MTU, &mtu));
    AVS_UNIT_ASSERT_EQUAL(mtu.mtu, 1472); // 20 bytes IPv4 + 8 bytes UDP

    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_send(ctx, backend, msg));

    avs_coap_msg_t *recv_msg =
            (avs_coap_msg_t *) alloca(COAP_MSG_MAX_SIZE);
    memset(recv_msg, 0, COAP_MSG_MAX_SIZE);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_ctx_recv(ctx, backend, recv_msg, COAP_MSG_MAX_SIZE));

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(recv_msg, msg, msg->length);
    avs_net_socket_cleanup(&backend);
    free(storage);
    avs_coap_ctx_cleanup(&ctx);
}
#endif

AVS_UNIT_TEST(coap_ctx, coap_dtls) {
    avs_net_socket_opt_value_t mtu;
    avs_coap_ctx_t *ctx = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_create(&ctx, 0));

    avs_net_abstract_socket_t *backend = setup_dtls_socket(TEST_PORT_DTLS);

    avs_coap_msg_info_t info = avs_coap_msg_info_init();
    info.type = AVS_COAP_MSG_CONFIRMABLE;
    info.code = AVS_COAP_CODE_CONTENT;
    info.identity.msg_id = 4;

    size_t storage_size = COAP_MSG_MAX_SIZE;
    void *storage = malloc(storage_size);

    const avs_coap_msg_t *msg = avs_coap_msg_build_without_payload(
            avs_coap_ensure_aligned_buffer(storage),
            storage_size, &info);

    AVS_UNIT_ASSERT_NOT_NULL(msg);

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
            backend, AVS_NET_SOCKET_OPT_MTU, &mtu));
    AVS_UNIT_ASSERT_EQUAL(mtu.mtu, 1500);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
            backend, AVS_NET_SOCKET_OPT_INNER_MTU, &mtu));
    // The negotiated cipher is not well-defined, so it's a range:
    // -- minimum ---- maximum --------------------------------------------
    //         20           20      bytes of IPv4 header
    //          8            8      bytes of UDP header
    //         13           13      bytes of DTLS header
    //          0            8      bytes of explicit IV
    //          0           16      bytes of AEAD tag or MD+padding
    // --------------------------------------------------------------------
    //         41           65      bytes of headers subtracted from 1500
    AVS_UNIT_ASSERT_TRUE(mtu.mtu >= 1435 && mtu.mtu <= 1459);

    AVS_UNIT_ASSERT_SUCCESS(avs_coap_ctx_send(ctx, backend, msg));

    avs_coap_msg_t *recv_msg =
            (avs_coap_msg_t *) alloca(COAP_MSG_MAX_SIZE);
    memset(recv_msg, 0, COAP_MSG_MAX_SIZE);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_coap_ctx_recv(ctx, backend, recv_msg, COAP_MSG_MAX_SIZE));

    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(recv_msg, msg, msg->length);
    avs_net_socket_cleanup(&backend);
    avs_coap_ctx_cleanup(&ctx);
    free(storage);
}
