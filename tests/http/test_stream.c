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

#include <avsystem/commons/avs_unit_mocksock.h>
#include <avsystem/commons/avs_unit_test.h>

#include "test_http.h"

static void assert_equal_url(const avs_url_t *actual,
                             const avs_url_t *expected) {
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(actual),
                                 avs_url_protocol(expected));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(actual), avs_url_user(expected));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_password(actual),
                                 avs_url_password(expected));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(actual), avs_url_host(expected));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(actual), avs_url_port(expected));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(actual), avs_url_path(expected));
}

AVS_UNIT_TEST(http, init) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    http_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.nooooooooooooooo.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.nooooooooooooooo.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(
            (avs_stream_t **) &stream, client, AVS_HTTP_GET,
            AVS_HTTP_CONTENT_IDENTITY, url, NULL, NULL));
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_TRUE(stream->vtable == &http_vtable);
    AVS_UNIT_ASSERT_TRUE(stream->http == client);
    AVS_UNIT_ASSERT_EQUAL(stream->method, AVS_HTTP_GET);
    assert_equal_url(stream->url, url);
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream->backend);
    AVS_UNIT_ASSERT_TRUE(avs_stream_net_getsock(stream->backend) == socket);
    AVS_UNIT_ASSERT_FALSE(stream->flags.chunked_sending);
    AVS_UNIT_ASSERT_TRUE(stream->flags.keep_connection);
    AVS_UNIT_ASSERT_FALSE(stream->flags.no_expect);
    AVS_UNIT_ASSERT_NULL(stream->body_receiver);
    AVS_UNIT_ASSERT_EQUAL(stream->out_buffer_pos, 0);
    AVS_UNIT_ASSERT_EQUAL((int) stream->auth.state.flags.type,
                          HTTP_AUTH_TYPE_NONE);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.retried);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.use_md5_sess);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.use_qop_auth);
    AVS_UNIT_ASSERT_NULL(stream->auth.state.opaque);
    AVS_UNIT_ASSERT_NULL(stream->auth.credentials.user);
    AVS_UNIT_ASSERT_NULL(stream->auth.credentials.password);
    AVS_UNIT_ASSERT_EQUAL(stream->status, 0);
    AVS_UNIT_ASSERT_EQUAL(stream->redirect_count, 0);
    AVS_UNIT_ASSERT_NULL(stream->user_headers);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup((avs_stream_t **) &stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, init_fail) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse(
            "http://hasthelargehadroncolliderdestroyedtheworldyet.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_http_test_expect_create_socket(NULL, AVS_NET_TCP_SOCKET);
    AVS_UNIT_ASSERT_FAILED(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                AVS_HTTP_CONTENT_IDENTITY, url,
                                                NULL, NULL));
    AVS_UNIT_ASSERT_NULL(stream);
    avs_url_free(url);
    avs_http_free(client);
}

AVS_UNIT_TEST(http, init_https_auth1) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    http_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("https://madoka:kaname@boards.4chan.org/b/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_SSL_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "boards.4chan.org", "443");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(
            (avs_stream_t **) &stream, client, AVS_HTTP_POST,
            AVS_HTTP_CONTENT_IDENTITY, url, "haruhi", NULL));
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_TRUE(stream->vtable == &http_vtable);
    AVS_UNIT_ASSERT_TRUE(stream->http == client);
    AVS_UNIT_ASSERT_EQUAL(stream->method, AVS_HTTP_POST);
    assert_equal_url(stream->url, url);
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream->backend);
    AVS_UNIT_ASSERT_TRUE(avs_stream_net_getsock(stream->backend) == socket);
    AVS_UNIT_ASSERT_FALSE(stream->flags.chunked_sending);
    AVS_UNIT_ASSERT_TRUE(stream->flags.keep_connection);
    AVS_UNIT_ASSERT_FALSE(stream->flags.no_expect);
    AVS_UNIT_ASSERT_NULL(stream->body_receiver);
    AVS_UNIT_ASSERT_EQUAL(stream->out_buffer_pos, 0);
    AVS_UNIT_ASSERT_EQUAL((int) stream->auth.state.flags.type,
                          HTTP_AUTH_TYPE_BASIC);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.retried);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.use_md5_sess);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.use_qop_auth);
    AVS_UNIT_ASSERT_NULL(stream->auth.state.opaque);
    AVS_UNIT_ASSERT_EQUAL_STRING(stream->auth.credentials.user, "haruhi");
    AVS_UNIT_ASSERT_EQUAL_STRING(stream->auth.credentials.password, "kaname");
    AVS_UNIT_ASSERT_EQUAL(stream->status, 0);
    AVS_UNIT_ASSERT_EQUAL(stream->redirect_count, 0);
    AVS_UNIT_ASSERT_NULL(stream->user_headers);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup((avs_stream_t **) &stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, init_https_auth2) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    http_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("https://moot@boards.4chan.org/a/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_SSL_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "boards.4chan.org", "443");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(
            (avs_stream_t **) &stream, client, AVS_HTTP_PUT,
            AVS_HTTP_CONTENT_IDENTITY, url, NULL, ""));
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_TRUE(stream->vtable == &http_vtable);
    AVS_UNIT_ASSERT_TRUE(stream->http == client);
    AVS_UNIT_ASSERT_EQUAL(stream->method, AVS_HTTP_PUT);
    assert_equal_url(stream->url, url);
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream->backend);
    AVS_UNIT_ASSERT_TRUE(avs_stream_net_getsock(stream->backend) == socket);
    AVS_UNIT_ASSERT_FALSE(stream->flags.chunked_sending);
    AVS_UNIT_ASSERT_TRUE(stream->flags.keep_connection);
    AVS_UNIT_ASSERT_FALSE(stream->flags.no_expect);
    AVS_UNIT_ASSERT_NULL(stream->body_receiver);
    AVS_UNIT_ASSERT_EQUAL(stream->out_buffer_pos, 0);
    AVS_UNIT_ASSERT_EQUAL((int) stream->auth.state.flags.type,
                          HTTP_AUTH_TYPE_BASIC);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.retried);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.use_md5_sess);
    AVS_UNIT_ASSERT_FALSE(stream->auth.state.flags.use_qop_auth);
    AVS_UNIT_ASSERT_NULL(stream->auth.state.opaque);
    AVS_UNIT_ASSERT_EQUAL_STRING(stream->auth.credentials.user, "moot");
    AVS_UNIT_ASSERT_EQUAL_STRING(stream->auth.credentials.password, "");
    AVS_UNIT_ASSERT_EQUAL(stream->status, 0);
    AVS_UNIT_ASSERT_EQUAL(stream->redirect_count, 0);
    AVS_UNIT_ASSERT_NULL(stream->user_headers);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup((avs_stream_t **) &stream));
    avs_http_free(client);
}
