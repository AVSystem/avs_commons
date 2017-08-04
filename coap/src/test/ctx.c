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

    char cmdline[] = AVS_COMMONS_BIN_DIR "/../tools/dtls_echo_server\0"
                     "-p\0"
                     "_____";
    char *args[4] = { cmdline };

    for (size_t i = 1; i < sizeof(args) / sizeof(args[0]) - 1; ++i) {
        args[i] = args[i - 1] + strlen(args[i - 1]) + 1;
    }

    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(args[2], strlen(args[2]), "%u", port) >= 0);

    set_sigusr1_mask(SIG_BLOCK);

    int pid = -1;
    switch (pid = fork()) {
    case 0:
#if __linux__
        if (prctl(PR_SET_PDEATHSIG, SIGHUP)) {
            LOG(WARNING, "prctl failed: %s", strerror(errno));
        }
#endif // __linux__
        execve(args[0], args, NULL);
        // fall-through
    case -1:
        LOG(ERROR, "could not start DTLS echo server: %s", strerror(errno));
        LOG(ERROR, "command: %s %s %s", args[0], args[1], args[2]);
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

static avs_coap_socket_t *setup_dtls_socket(uint16_t port) {
    spawn_dtls_echo_server(port);
    avs_coap_socket_t *socket = NULL;
    avs_net_abstract_socket_t *backend = NULL;
    avs_net_ssl_configuration_t config = {
        .version = AVS_NET_SSL_VERSION_DEFAULT,
        .security = {
            .mode = AVS_NET_SECURITY_CERTIFICATE,
            .data.cert = {
                .server_cert_validation = true,
                .trusted_certs = avs_net_trusted_cert_source_from_paths(
                                        NULL, "test_certs/root.crt"),
                .client_cert = avs_net_client_cert_from_file(
                                        "test_certs/client.crt", NULL,
                                        AVS_NET_DATA_FORMAT_PEM),
                .client_key = avs_net_private_key_from_file(
                                        "test_certs/client.key", NULL,
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
    AVS_UNIT_ASSERT_SUCCESS(avs_coap_socket_create(&socket, backend, 0));

    return socket;
}

#warning "TODO: fix coap_ctx::coap_ctx after setup_udp_echo_socket is ported"
#if 0
AVS_UNIT_TEST(coap_ctx, coap_ctx) {
    avs_net_socket_opt_value_t mtu;
    { // udp_client_send_recv
        avs_coap_socket_t *socket =
                setup_dtls_socket(TEST_PORT_UDP);

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

        avs_net_abstract_socket_t *backend =
                avs_coap_socket_get_backend(socket);
        AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
                backend, AVS_NET_SOCKET_OPT_MTU, &mtu));
        AVS_UNIT_ASSERT_EQUAL(mtu.mtu, 1500);
        AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
                backend, AVS_NET_SOCKET_OPT_INNER_MTU, &mtu));
        AVS_UNIT_ASSERT_EQUAL(mtu.mtu, 1472); // 20 bytes IPv4 + 8 bytes UDP

        AVS_UNIT_ASSERT_SUCCESS(avs_coap_socket_send(socket, msg));

        avs_coap_msg_t *recv_msg =
                (avs_coap_msg_t *) alloca(COAP_MSG_MAX_SIZE);
        memset(recv_msg, 0, COAP_MSG_MAX_SIZE);
        AVS_UNIT_ASSERT_SUCCESS(
                avs_coap_socket_recv(socket, recv_msg, COAP_MSG_MAX_SIZE));

        AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(recv_msg, msg, msg->length);
        avs_coap_socket_cleanup(&socket);
        free(storage);
    }
    { // dtls_client_send_recv
        avs_coap_socket_t *socket =
                setup_dtls_socket(TEST_PORT_DTLS);

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

        avs_net_abstract_socket_t *backend =
                avs_coap_socket_get_backend(socket);
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

        AVS_UNIT_ASSERT_SUCCESS(avs_coap_socket_send(socket, msg));

        avs_coap_msg_t *recv_msg =
                (avs_coap_msg_t *) alloca(COAP_MSG_MAX_SIZE);
        memset(recv_msg, 0, COAP_MSG_MAX_SIZE);
        AVS_UNIT_ASSERT_SUCCESS(
                avs_coap_socket_recv(socket, recv_msg, COAP_MSG_MAX_SIZE));

        AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(recv_msg, msg, msg->length);
        avs_coap_socket_cleanup(&socket);
        free(storage);
    }
}
