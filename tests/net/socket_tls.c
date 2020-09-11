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

#define _GNU_SOURCE // for memmem()

#include <stdio.h>
#include <string.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <avsystem/commons/avs_utils.h>

#include "socket_common.h"

//// avs_net_socket_get_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, ssl_get_opt) {
    avs_net_socket_t *socket = NULL;

    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}

//// avs_net_socket_get_opt after avs_net_socket_close /////////////////////////

AVS_UNIT_TEST(socket, ssl_get_opt_after_close) {
    avs_net_socket_t *socket = NULL;

    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { SUCCESS, AVS_NET_SOCKET_OPT_STATE },
        { SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU },
        { SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED }
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}

//// avs_net_socket_set_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, ssl_set_opt) {
    avs_net_socket_t *socket = NULL;

    avs_net_ssl_configuration_t config = create_default_ssl_config();
    AVS_UNIT_ASSERT_SUCCESS(avs_net_ssl_socket_create(&socket, &config));
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_bind(socket, DEFAULT_ADDRESS, DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        { SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT },
        { FAIL, AVS_NET_SOCKET_OPT_STATE },
        { FAIL, AVS_NET_SOCKET_OPT_ADDR_FAMILY },
        { FAIL, AVS_NET_SOCKET_OPT_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_INNER_MTU },
        { FAIL, AVS_NET_SOCKET_OPT_SESSION_RESUMED },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_SENT },
        { FAIL, AVS_NET_SOCKET_OPT_BYTES_RECEIVED }
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
    cleanup_default_ssl_config(&config);
}

#define SMTP_SERVER_HOSTNAME "smtp.gmail.com"
#define SMTP_SERVER_PORT "587"

static void assert_receive_smtp_status(avs_net_socket_t *socket, int status) {
    char line_beginning[16];
    char line_full[16];
    char buffer[1024];
    size_t received = 0;
    snprintf(line_beginning, sizeof(line_beginning), "%d ", status);
    snprintf(line_full, sizeof(line_full), "%d\r\n", status);
    while (1) {
        AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_receive(socket, &received,
                                                       buffer, sizeof(buffer)));
        AVS_UNIT_ASSERT_TRUE(received > 0);
        if (received >= strlen(line_full)
                && memcmp(buffer + received - 2, "\r\n", 2) == 0) {
            size_t line_start = received - 2;
            while (line_start > 0 && buffer[line_start - 1] != '\n') {
                --line_start;
            }
            if (memcmp(buffer + line_start, line_beginning,
                       strlen(line_beginning))
                            == 0
                    || memcmp(buffer + line_start, line_full, strlen(line_full))
                                   == 0) {
                break;
            }
        }
    }
}

#define EHLO_MSG "EHLO [127.0.0.1]\r\n"

static avs_net_socket_t *initiate_smtp_starttls(void) {
    static const char starttls_msg[] = "STARTTLS\r\n";
    avs_net_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_tcp_socket_create(&socket, NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_connect(socket, SMTP_SERVER_HOSTNAME,
                                                   SMTP_SERVER_PORT));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_send(socket, EHLO_MSG, strlen(EHLO_MSG)));
    assert_receive_smtp_status(socket, 250);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_send(socket, starttls_msg, strlen(starttls_msg)));
    assert_receive_smtp_status(socket, 220);

    return socket;
}

AVS_UNIT_TEST(starttls, starttls_smtp) {
    avs_net_socket_t *socket = initiate_smtp_starttls();

    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    avs_net_ssl_configuration_t ssl_config = {
        .version = AVS_NET_SSL_VERSION_TLSv1,
        .prng_ctx = prng_ctx
    };

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_ssl_socket_decorate_in_place(&socket, &ssl_config));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_send(socket, EHLO_MSG, strlen(EHLO_MSG)));
    assert_receive_smtp_status(socket, 250);

    avs_net_socket_cleanup(&socket);
    avs_crypto_prng_free(&prng_ctx);
}

AVS_UNIT_TEST(starttls, starttls_smtp_verify_failure) {
    avs_net_socket_t *socket = initiate_smtp_starttls();

    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    avs_net_ssl_configuration_t ssl_config = {
        .version = AVS_NET_SSL_VERSION_TLSv1,
        .security.data.cert = {
            .server_cert_validation = true,
            .ignore_system_trust_store = true
        },
        .prng_ctx = prng_ctx
    };

    AVS_UNIT_ASSERT_FAILED(
            avs_net_ssl_socket_decorate_in_place(&socket, &ssl_config));

    avs_net_socket_cleanup(&socket);
    avs_crypto_prng_free(&prng_ctx);
}

static bool is_pem_crt_file(const char *path) {
    struct stat statbuf;
    if (stat(path, &statbuf) || !S_ISREG(statbuf.st_mode)) {
        return false;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    bool result = false;
    static const char *needle = "-----BEGIN CERTIFICATE-----";
    void *ptr =
            mmap(NULL, (size_t) statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr) {
        if (memmem(ptr, (size_t) statbuf.st_size, needle, strlen(needle))) {
            result = true;
        }
        munmap(ptr, (size_t) statbuf.st_size);
    }
    close(fd);
    return result;
}

static AVS_LIST(avs_crypto_certificate_chain_info_t) load_trusted_certs(void) {
    // On *BSD, including macOS, all system-wide certs are in this one huge file
    static const char *const bsd_cert_pem_path = "/etc/ssl/cert.pem";
    AVS_LIST(avs_crypto_certificate_chain_info_t) result = NULL;
    if (is_pem_crt_file(bsd_cert_pem_path)) {
        AVS_LIST(avs_crypto_certificate_chain_info_t) entry =
                AVS_LIST_APPEND_NEW(avs_crypto_certificate_chain_info_t,
                                    &result);
        AVS_UNIT_ASSERT_NOT_NULL(entry);
        *entry = avs_crypto_certificate_chain_info_from_file(bsd_cert_pem_path);
    }

    // On typical Linux distros, this directory is used instead.
    // Or sometimes in addition to. There's no harm loading both.
    static const char *const linux_certs_dir = "/etc/ssl/certs";
    DIR *dir = opendir(linux_certs_dir);
    if (dir) {
        struct dirent *file_entry;
        while ((file_entry = readdir(dir))) {
            typedef struct {
                avs_crypto_certificate_chain_info_t entry;
                char path[256];
            } entry_with_path_t;
            AVS_LIST(entry_with_path_t) entry_with_path =
                    AVS_LIST_NEW_ELEMENT(entry_with_path_t);
            AVS_UNIT_ASSERT_NOT_NULL(entry_with_path);
            if (avs_simple_snprintf(entry_with_path->path,
                                    sizeof(entry_with_path->path), "%s/%s",
                                    linux_certs_dir, file_entry->d_name)
                            < 0
                    || !is_pem_crt_file(entry_with_path->path)) {
                AVS_LIST_DELETE(&entry_with_path);
            } else {
                entry_with_path->entry =
                        avs_crypto_certificate_chain_info_from_file(
                                entry_with_path->path);
                AVS_LIST_APPEND(&result,
                                (AVS_LIST(avs_crypto_certificate_chain_info_t))
                                        entry_with_path);
            }
        }
        closedir(dir);
    }

    return result;
}

AVS_UNIT_TEST(starttls, starttls_smtp_verify_list) {
    AVS_LIST(avs_crypto_certificate_chain_info_t) trusted_certs =
            load_trusted_certs();

    avs_net_socket_t *socket = initiate_smtp_starttls();

    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    avs_net_ssl_configuration_t ssl_config = {
        .version = AVS_NET_SSL_VERSION_TLSv1,
        .security.data.cert = {
            .server_cert_validation = true,
            .ignore_system_trust_store = true,
            .trusted_certs =
                    avs_crypto_certificate_chain_info_from_list(trusted_certs)
        },
        .prng_ctx = prng_ctx
    };

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_ssl_socket_decorate_in_place(&socket, &ssl_config));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_send(socket, EHLO_MSG, strlen(EHLO_MSG)));
    assert_receive_smtp_status(socket, 250);

    avs_net_socket_cleanup(&socket);
    avs_crypto_prng_free(&prng_ctx);
    AVS_LIST_CLEAR(&trusted_certs);
}

AVS_UNIT_TEST(starttls, starttls_smtp_verify_array) {
    AVS_LIST(avs_crypto_certificate_chain_info_t) trusted_cert_list =
            load_trusted_certs();
    size_t trusted_cert_count = AVS_LIST_SIZE(trusted_cert_list);
    avs_crypto_certificate_chain_info_t trusted_certs[trusted_cert_count];
    for (size_t i = 0; i < trusted_cert_count; ++i) {
        trusted_certs[i] = *AVS_LIST_NTH(trusted_cert_list, i);
    }

    avs_net_socket_t *socket = initiate_smtp_starttls();

    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    avs_net_ssl_configuration_t ssl_config = {
        .version = AVS_NET_SSL_VERSION_TLSv1,
        .security.data.cert = {
            .server_cert_validation = true,
            .ignore_system_trust_store = true,
            .trusted_certs = avs_crypto_certificate_chain_info_from_array(
                    trusted_certs, trusted_cert_count)
        },
        .prng_ctx = prng_ctx
    };

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_ssl_socket_decorate_in_place(&socket, &ssl_config));

    AVS_UNIT_ASSERT_SUCCESS(
            avs_net_socket_send(socket, EHLO_MSG, strlen(EHLO_MSG)));
    assert_receive_smtp_status(socket, 250);

    avs_net_socket_cleanup(&socket);
    avs_crypto_prng_free(&prng_ctx);
    AVS_LIST_CLEAR(&trusted_cert_list);
}
