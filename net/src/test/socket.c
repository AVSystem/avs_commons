/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#include <avsystem/commons/socket.h>
#include <avsystem/commons/unit/test.h>

typedef enum {
    SUCCESS,
    FAIL
} test_case_result_t;

typedef struct {
    test_case_result_t expected_result;
    avs_net_socket_opt_key_t tested_option;
} socket_opt_test_case_t;

static void
run_socket_get_opt_test_cases(avs_socket_t *socket,
                              const socket_opt_test_case_t test_cases[],
                              size_t test_cases_count) {
    avs_net_socket_opt_value_t opt_val;

    for (size_t i = 0; i < test_cases_count; i++) {
        if (test_cases[i].expected_result == SUCCESS) {
            AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_get_opt(
                socket, test_cases[i].tested_option, &opt_val));
        } else {
            AVS_UNIT_ASSERT_FAILED(avs_net_socket_get_opt(
                socket, test_cases[i].tested_option, &opt_val));
        }
    }
}

#define DEFAULT_ADDRESS "localhost"
#define DEFAULT_PORT "5683"
#define DEFAULT_IDENTITY "sesame"
#define DEFAULT_PSK "password"

static const avs_net_ssl_configuration_t DEFAULT_SSL_CONFIGURATION = {
    .version = AVS_NET_SSL_VERSION_DEFAULT,
    .security = {
        .mode = AVS_NET_SECURITY_PSK,
        .data.psk = {
            .psk = DEFAULT_PSK,
            .psk_size = sizeof(DEFAULT_PSK) - 1,
            .identity = DEFAULT_IDENTITY,
            .identity_size = sizeof(DEFAULT_IDENTITY) - 1
        }
    }
};

static void
run_socket_set_opt_test_cases(avs_socket_t *socket,
                              const socket_opt_test_case_t test_cases[],
                              size_t test_cases_count) {
    for (size_t i = 0; i < test_cases_count; i++) {
        avs_net_socket_opt_value_t opt_val;
        switch (test_cases[i].tested_option) {
        case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
            opt_val.recv_timeout =
                avs_time_duration_from_scalar(10, AVS_TIME_S);
            break;
        case AVS_NET_SOCKET_OPT_STATE:
            opt_val.state =  AVS_NET_SOCKET_STATE_CONNECTED;
            break;
        case AVS_NET_SOCKET_OPT_ADDR_FAMILY:
            opt_val.addr_family = AVS_NET_AF_INET4;
            break;
        case AVS_NET_SOCKET_OPT_MTU:
        case AVS_NET_SOCKET_OPT_INNER_MTU:
            opt_val.mtu = 5;
            break;
        case AVS_NET_SOCKET_OPT_SESSION_RESUMED:
            opt_val.flag = true;
            break;
        case AVS_NET_SOCKET_OPT_BYTES_SENT:
            opt_val.bytes_sent = 123;
            break;
        case AVS_NET_SOCKET_OPT_BYTES_RECEIVED:
            opt_val.bytes_received = 321;
            break;
        }

        if (test_cases[i].expected_result == SUCCESS) {
            AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_set_opt(
                socket, test_cases[i].tested_option, opt_val));
        } else {
            AVS_UNIT_ASSERT_FAILED(avs_net_socket_set_opt(
                socket, test_cases[i].tested_option, opt_val));
        }
    }
}

//// avs_net_socket_get_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, udp_get_opt) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_UDP_SOCKET,
                                                  NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {SUCCESS, AVS_NET_SOCKET_OPT_STATE},
        {SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, tcp_get_opt) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_TCP_SOCKET,
                                                  NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {SUCCESS, AVS_NET_SOCKET_OPT_STATE},
        {SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, ssl_get_opt) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_SSL_SOCKET,
                                                  &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {SUCCESS, AVS_NET_SOCKET_OPT_STATE},
        {SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU},
        {SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, dtls_get_opt) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_DTLS_SOCKET,
                                                  &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {SUCCESS, AVS_NET_SOCKET_OPT_STATE},
        {SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_get_opt after avs_net_socket_close /////////////////////////

AVS_UNIT_TEST(socket, udp_get_opt_after_close) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_UDP_SOCKET,
                                                  NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {SUCCESS, AVS_NET_SOCKET_OPT_STATE},
        {SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, tcp_get_opt_after_close) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_TCP_SOCKET,
                                                  NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {SUCCESS, AVS_NET_SOCKET_OPT_STATE},
        {SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, ssl_get_opt_after_close) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_SSL_SOCKET,
                                                  &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {SUCCESS, AVS_NET_SOCKET_OPT_STATE},
        {SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU},
        {SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, dtls_get_opt_after_close) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_DTLS_SOCKET,
                                                  &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {SUCCESS, AVS_NET_SOCKET_OPT_STATE},
        {SUCCESS, AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {SUCCESS, AVS_NET_SOCKET_OPT_INNER_MTU},
        {SUCCESS, AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_SENT},
        {SUCCESS, AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_get_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_set_opt ////////////////////////////////////////////////////

AVS_UNIT_TEST(socket, udp_set_opt) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_UDP_SOCKET,
                                                  NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {FAIL,    AVS_NET_SOCKET_OPT_STATE},
        {FAIL,    AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_SENT},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, tcp_set_opt) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_TCP_SOCKET,
                                                  NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {FAIL,    AVS_NET_SOCKET_OPT_STATE},
        {FAIL,    AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_SENT},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, ssl_set_opt) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_SSL_SOCKET,
                                                  &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {FAIL,    AVS_NET_SOCKET_OPT_STATE},
        {FAIL,    AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_SENT},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, dtls_set_opt) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_DTLS_SOCKET,
                                                  &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {FAIL,    AVS_NET_SOCKET_OPT_STATE},
        {FAIL,    AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_SENT},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

//// avs_net_socket_set_opt after avs_net_socket_close /////////////////////////

AVS_UNIT_TEST(socket, udp_set_opt_after_close) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_UDP_SOCKET,
                                                  NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {FAIL,    AVS_NET_SOCKET_OPT_STATE},
        {FAIL,    AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_SENT},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, tcp_set_opt_after_close) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_TCP_SOCKET,
                                                  NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {FAIL,    AVS_NET_SOCKET_OPT_STATE},
        {FAIL,    AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_SENT},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, ssl_set_opt_after_close) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_SSL_SOCKET,
                                                  &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {FAIL,    AVS_NET_SOCKET_OPT_STATE},
        {FAIL,    AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_SENT},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}

AVS_UNIT_TEST(socket, dtls_set_opt_after_close) {
    avs_socket_t *socket = NULL;

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_create(&socket, AVS_NET_DTLS_SOCKET,
                                                  &DEFAULT_SSL_CONFIGURATION));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_bind(socket, DEFAULT_ADDRESS,
                                                DEFAULT_PORT));
    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_close(socket));

    const socket_opt_test_case_t test_cases[] = {
        {SUCCESS, AVS_NET_SOCKET_OPT_RECV_TIMEOUT},
        {FAIL,    AVS_NET_SOCKET_OPT_STATE},
        {FAIL,    AVS_NET_SOCKET_OPT_ADDR_FAMILY},
        {FAIL,    AVS_NET_SOCKET_OPT_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_INNER_MTU},
        {FAIL,    AVS_NET_SOCKET_OPT_SESSION_RESUMED},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_SENT},
        {FAIL,    AVS_NET_SOCKET_OPT_BYTES_RECEIVED}
    };
    run_socket_set_opt_test_cases(socket, test_cases,
                                  AVS_ARRAY_SIZE(test_cases));

    AVS_UNIT_ASSERT_SUCCESS(avs_net_socket_cleanup(&socket));
}
