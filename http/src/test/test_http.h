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

#ifndef AVS_COMMONS_HTTP_TEST_HTTP_H
#define AVS_COMMONS_HTTP_TEST_HTTP_H

#include <avsystem/commons/net.h>

typedef struct expected_socket_struct {
    avs_net_abstract_socket_t *socket;
    avs_net_socket_type_t type;
} expected_socket_t;

extern expected_socket_t *avs_http_test_SOCKETS_TO_CREATE;

int avs_net_socket_create_TEST_WRAPPER(avs_net_abstract_socket_t **socket,
                                       avs_net_socket_type_t type,
                                       ...);

void avs_http_test_expect_create_socket(avs_net_abstract_socket_t *socket,
                                        avs_net_socket_type_t type);

#endif /* AVS_COMMONS_HTTP_TEST_HTTP_H */

