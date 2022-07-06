/*
 * Copyright 2022 AVSystem <avsystem@avsystem.com>
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

#define _GNU_SOURCE // for popen(), sigwait() and mkstemps()

#include <signal.h>
#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>

#include "socket_tls13_common.h"

static char *g_openssl_tls13_conf_file =
        (char[]){ "/tmp/openssl_tls13_XXXXXX.conf" };

static pid_t g_process_group;

static void kill_children(void) {
    // send SIGTERM to all children
    // ...but not to ourselves, so we need to block it first
    sigset_t set, oldset;
    sigemptyset(&set);
    sigemptyset(&oldset);
    sigaddset(&set, SIGTERM);
    sigprocmask(SIG_BLOCK, &set, &oldset);
    // kill(-PROCESS_GROUP) sends the signal to ourselves and all the children
    kill(-g_process_group, SIGTERM);
    // discard the SIGTERM that we've received
    AVS_UNIT_ASSERT_SUCCESS(sigwait(&set, &(int) { 0 }));
    // restore the original mask
    sigprocmask(SIG_SETMASK, &oldset, NULL);
}

static void remove_config(void) {
    unlink(g_openssl_tls13_conf_file);
}

AVS_UNIT_SUITE_INIT(tls13, verbose) {
    (void) verbose;
    // Create a new process group, so that we don't kill our parents
    g_process_group = setsid();
    if (g_process_group == (pid_t) -1) {
        // We are most likely already a leader, so don't bother
        g_process_group = 0;
    }
    atexit(kill_children);

    AVS_UNIT_ASSERT_NOT_EQUAL(mkstemps(g_openssl_tls13_conf_file, 5), -1);
    FILE *f = fopen(g_openssl_tls13_conf_file, "w");
    static const char OPENSSL_CONFIG[] = ".include /etc/ssl/openssl.cnf\n"
                                         "Options=-MiddleboxCompat\n";
    fwrite(OPENSSL_CONFIG, sizeof(char), strlen(OPENSSL_CONFIG), f);
    fclose(f);
    atexit(remove_config);
}

FILE *socket_tls13_test_launch_server(test_server_args_t args) {
    const char *credential_args;
    switch (args.mode) {
    case SERVER_CERT_VERIFY:
        credential_args =
                "-CAfile " CA_CERT_FILE " -Verify 9999 -cert " SERVER_CERT_FILE
                " -key " SERVER_KEY_FILE;
        break;
    case SERVER_CERT_NOVERIFY:
        credential_args = "-cert " SERVER_CERT_FILE " -key " SERVER_KEY_FILE;
        break;
    case SERVER_PSK:
        credential_args = "-nocert -psk_identity " PSK_IDENTITY
                          " -psk $(echo -n '" PSK_KEY "' | xxd -p)";
        break;
    }
    char buf[256];
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(
                    buf, sizeof(buf),
                    "OPENSSL_CONF=%s openssl s_server -port %s -4 -www -tls1_3 "
                    "%s %s",
                    g_openssl_tls13_conf_file, args.port, credential_args,
                    args.additional_args ? args.additional_args : "")
            >= 0);
    FILE *f = popen(buf, "r");
    AVS_UNIT_ASSERT_NOT_NULL(f);
    while (true) {
        AVS_UNIT_ASSERT_FALSE(feof(f));
        AVS_UNIT_ASSERT_FALSE(ferror(f));
        AVS_UNIT_ASSERT_NOT_NULL(fgets(buf, sizeof(buf), f));
        if (strcmp(buf, "ACCEPT\n") == 0) {
            break;
        }
    }
    return f;
}

void socket_tls13_test_cleanup_server(FILE **fptr) {
    // send SIGTERM to all children
    kill_children();
    // now close the pipe; NOTE: without the kill() above, this would hang,
    // because openssl s_server does NOT exit automatically
    pclose(*fptr);
    *fptr = NULL;
}

const char *socket_tls13_test_choose_ephemeral_port(void) {
    static char port_buf[8];
    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_tcp_socket_create(&socket,
                                      &(const avs_net_socket_configuration_t) {
                                          .reuse_addr = 1,
                                          .address_family = AVS_NET_AF_INET4
                                      }));
    // Bind to an ephemeral port
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, "127.0.0.1", ""));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_get_local_port(socket, port_buf, sizeof(port_buf)));
    avs_net_socket_cleanup(&socket);
    // This port should be reusable thanks to the reuse_addr option
    return port_buf;
}

avs_net_ssl_configuration_t
socket_tls13_test_default_config(avs_crypto_prng_ctx_t *prng_ctx,
                                 test_server_mode_t mode) {
    avs_net_ssl_configuration_t result;
    memset(&result, 0, sizeof(result));
    result.prng_ctx = prng_ctx;
    if (mode == SERVER_PSK) {
        result.security = avs_net_security_info_from_psk((avs_net_psk_info_t) {
            .key = avs_crypto_psk_key_info_from_buffer(PSK_KEY,
                                                       strlen(PSK_KEY)),
            .identity = avs_crypto_psk_identity_info_from_buffer(
                    PSK_IDENTITY, strlen(PSK_IDENTITY))
        });
    } else {
        avs_net_certificate_info_t info = {
            .server_cert_validation = true,
            .ignore_system_trust_store = true,
            .trusted_certs =
                    avs_crypto_certificate_chain_info_from_file(CA_CERT_FILE)
        };
        if (mode == SERVER_CERT_VERIFY) {
            info.client_cert = avs_crypto_certificate_chain_info_from_file(
                    CLIENT_CERT_FILE);
            info.client_key =
                    avs_crypto_private_key_info_from_file(CLIENT_KEY_FILE,
                                                          NULL);
        }
        result.security = avs_net_security_info_from_certificates(info);
    }
    return result;
}

void socket_tls13_test_assert_connectivity(avs_net_socket_t *socket) {
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_send(socket, "GET /\r\n", 7));
    size_t received = 0;
    char buf[16384];
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_receive(socket, &received, buf, sizeof(buf)));
    AVS_UNIT_ASSERT_TRUE(received < sizeof(buf));
    AVS_UNIT_ASSERT_EQUAL_BYTES(buf, "HTTP/1.0 200");
}

AVS_UNIT_TEST(tls13, noverify_noticket_with_explicit_version) {
    INIT_TLS13_TEST(SERVER_CERT_NOVERIFY, "-num_tickets 0");
    config.version = AVS_NET_SSL_VERSION_TLSv1_3;

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(tls13, ciphersuites) {
    INIT_TLS13_TEST(SERVER_CERT_NOVERIFY, "-num_tickets 0");
    config.version = AVS_NET_SSL_VERSION_TLSv1_3;
    // NOTE: There is no automatic verification that the ciphersuite is actually
    // applied. Please manually check in Wireshark if you're messing with
    // related code.
    config.ciphersuites.ids = &(uint32_t) { 0x1301 }; // TLS_AES_128_GCM_SHA256
    config.ciphersuites.num_ids = 1;

    avs_net_socket_t *socket = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, "localhost", port));
    socket_tls13_test_assert_connectivity(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}
