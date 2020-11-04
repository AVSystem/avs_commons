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

#include <avs_commons_init.h>

#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_GLOBAL_INIT(verbose) {
    if (!verbose) {
        avs_log_set_default_level(AVS_LOG_QUIET);
    }
}

AVS_UNIT_TEST(parse_url, without_credentials_port_and_path) {
    avs_url_t *parsed_url = avs_url_parse("http://acs.avsystem.com");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, without_credentials_and_port_with_path) {
    avs_url_t *parsed_url = avs_url_parse("http://acs.avsystem.com/~path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/~path");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, with_query_string) {
    avs_url_t *parsed_url = avs_url_parse("http://acs.avsystem.com/path?query");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path?query");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, with_query_string_only) {
    avs_url_t *parsed_url = avs_url_parse("http://acs.avsystem.com?query");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/?query");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, with_port_and_query_string) {
    avs_url_t *parsed_url =
            avs_url_parse("http://acs.avsystem.com:123/path?query");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path?query");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, with_port_and_query_string_only) {
    avs_url_t *parsed_url = avs_url_parse("http://acs.avsystem.com:123?query");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/?query");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, without_credentials_with_port_and_path) {
    avs_url_t *parsed_url =
            avs_url_parse("http://acs.avsystem.com:123/path/to/resource");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path/to/resource");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, without_password_with_user) {
    avs_url_t *parsed_url =
            avs_url_parse("http://user@acs.avsystem.com:123/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "user");
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, without_password_with_empty_user) {
    avs_url_t *parsed_url = avs_url_parse("http://@acs.avsystem.com:123/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "");
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, with_user_and_empty_password) {
    avs_url_t *parsed_url =
            avs_url_parse("http://user:@acs.avsystem.com:123/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "user");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_password(parsed_url), "");

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, with_empty_user_and_empty_password) {
    avs_url_t *parsed_url = avs_url_parse("http://:@acs.avsystem.com:123/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_password(parsed_url), "");

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, with_user_and_password) {
    avs_url_t *parsed_url =
            avs_url_parse("http://user:password@acs.avsystem.com:123/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "user");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_password(parsed_url), "password");

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, escaped_credentials) {
    avs_url_t *parsed_url = avs_url_parse(
            "http://user%25:p%40ssword@acs.avsystem.com:123/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "acs.avsystem.com");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "123");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/path");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "user%");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_password(parsed_url), "p@ssword");

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, slash_within_credentials) {
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http:///user:password@acs.avsystem.com"));
    /* A slash before : makes the first part of a username look like a valid
     * hostname, so it is acceptable. */

    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user:/password@acs.avsystem.com"));
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user:pass/word@acs.avsystem.com"));
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user:password/@acs.avsystem.com"));
}

AVS_UNIT_TEST(parse_url, space_within_credentials) {
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http:// user:password@acs.avsystem.com"));
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://us er:password@acs.avsystem.com"));
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user :password@acs.avsystem.com"));

    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user: password@acs.avsystem.com"));
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user:pass word@acs.avsystem.com"));
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user:password @acs.avsystem.com"));
}

AVS_UNIT_TEST(parse_url, null_in_username_and_password) {
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user%00:password@acs.avsystem.com/path"));
    AVS_UNIT_ASSERT_NULL(
            avs_url_parse("http://user:pas%00sword@acs.avsystem.com/path"));
}

AVS_UNIT_TEST(parse_url, port_length) {
    avs_url_t *parsed_url;

    parsed_url = avs_url_parse("http://acs.avsystem.com:1234/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    avs_url_free(parsed_url);

    parsed_url = avs_url_parse("http://acs.avsystem.com:12345/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    avs_url_free(parsed_url);

    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://acs.avsystem.com:123456/path"));
    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://acs.avsystem.com:1234567/path"));
    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://acs.avsystem.com:/path"));
}

AVS_UNIT_TEST(parse_url, port_invalid_characters) {
    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://acs.avsystem.com:1_234/path"));
    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://acs.avsystem.com:http/path"));
    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://acs.avsystem.com:12345_/path"));
}

#ifdef AVS_COMMONS_NET_WITH_IPV6
AVS_UNIT_TEST(parse_url, ftp_ipv6) {
    avs_url_t *parsed_url = avs_url_parse("ftp://[12::34]");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "ftp");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "12::34");
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, ipv6_address) {
    avs_url_t *parsed_url = avs_url_parse("http://[12::34]");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "12::34");
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, ipv6_address_with_port_and_path) {
    avs_url_t *parsed_url = avs_url_parse("http://[12::34]:56/78");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "12::34");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "56");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/78");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, ipv6_address_with_credentials) {
    avs_url_t *parsed_url =
            avs_url_parse("http://user%25:p%40ssword@[12::34]:56/78");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);

    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "http");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "12::34");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "56");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/78");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "user%");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_password(parsed_url), "p@ssword");

    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url, invalid_ipv6_address) {
    avs_url_t *parsed_url = avs_url_parse("http://acs.avsystem.com:1234/path");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    avs_url_free(parsed_url);

    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://12:ff:ff::34]"));
    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://[12:ff:ff::34"));
    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://[12:ff:ff::34]:"));
}
#endif // AVS_COMMONS_NET_WITH_IPV6

AVS_UNIT_TEST(parse_url, empty_host) {
    avs_url_t *parsed_url = avs_url_parse("http://host");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    avs_url_free(parsed_url);

    AVS_UNIT_ASSERT_NULL(avs_url_parse("http:///path"));
    AVS_UNIT_ASSERT_NULL(avs_url_parse("http://:123"));
}

AVS_UNIT_TEST(parse_url_lenient, empty_proto) {
    avs_url_t *parsed_url = avs_url_parse_lenient("hello/world");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    AVS_UNIT_ASSERT_NULL(avs_url_protocol(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_host(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "hello/world");
    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url_lenient, empty_proto_absolute) {
    avs_url_t *parsed_url =
            avs_url_parse_lenient("//user%25:p%40ssword@[12::34]:56/78");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    AVS_UNIT_ASSERT_NULL(avs_url_protocol(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "user%");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_password(parsed_url), "p@ssword");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "12::34");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "56");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/78");
    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url_lenient, empty_host) {
    avs_url_t *parsed_url =
            avs_url_parse_lenient("//user%25:p%40ssword@:12/34");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    AVS_UNIT_ASSERT_NULL(avs_url_protocol(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_user(parsed_url), "user%");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_password(parsed_url), "p@ssword");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "12");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/34");
    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url_lenient, empty_port) {
    avs_url_t *parsed_url = avs_url_parse_lenient("//:/wat");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    AVS_UNIT_ASSERT_NULL(avs_url_protocol(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url), "");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/wat");
    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url_lenient, long_port) {
    avs_url_t *parsed_url = avs_url_parse_lenient("//:83947283975891247591");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    AVS_UNIT_ASSERT_NULL(avs_url_protocol(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_port(parsed_url),
                                 "83947283975891247591");
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/");
    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url_lenient, empty_host_and_port) {
    avs_url_t *parsed_url = avs_url_parse_lenient("///wat");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    AVS_UNIT_ASSERT_NULL(avs_url_protocol(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_host(parsed_url), "");
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "/wat");
    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(parse_url_lenient, tel) {
    avs_url_t *parsed_url = avs_url_parse_lenient("tel:+48126194700");
    AVS_UNIT_ASSERT_NOT_NULL(parsed_url);
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_protocol(parsed_url), "tel");
    AVS_UNIT_ASSERT_NULL(avs_url_user(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_password(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_host(parsed_url));
    AVS_UNIT_ASSERT_NULL(avs_url_port(parsed_url));
    AVS_UNIT_ASSERT_EQUAL_STRING(avs_url_path(parsed_url), "+48126194700");
    avs_url_free(parsed_url);
}

AVS_UNIT_TEST(url_unescape, empty_string) {
    char data[] = "";
    size_t length;

    AVS_UNIT_ASSERT_SUCCESS(avs_url_percent_decode(data, &length));
    AVS_UNIT_ASSERT_EQUAL_STRING(data, "");
    AVS_UNIT_ASSERT_EQUAL(length, 0);
}

AVS_UNIT_TEST(url_unescape, nothing_to_escape) {
    char data[] = "avsystem";
    size_t length;

    AVS_UNIT_ASSERT_SUCCESS(avs_url_percent_decode(data, &length));
    AVS_UNIT_ASSERT_EQUAL_STRING(data, "avsystem");
    AVS_UNIT_ASSERT_EQUAL(length, strlen("avsystem"));
}

AVS_UNIT_TEST(url_unescape, example_data) {
    char data[] = "%25%40";
    size_t length;

    AVS_UNIT_ASSERT_SUCCESS(avs_url_percent_decode(data, &length));
    AVS_UNIT_ASSERT_EQUAL_STRING(data, "%@");
    AVS_UNIT_ASSERT_EQUAL(length, 2);
}

AVS_UNIT_TEST(url_unescape, invalid_format) {
    char data[] = "%0";
    size_t length;

    AVS_UNIT_ASSERT_FAILED(avs_url_percent_decode(data, &length));
}

AVS_UNIT_TEST(url_unescape, invalid_characters) {
    char data[] = "%8z";
    size_t length;

    AVS_UNIT_ASSERT_FAILED(avs_url_percent_decode(data, &length));
}

AVS_UNIT_TEST(url_unescape, lowercase_hex) {
    char data[] = "%3a%4b%7c%5d%6e%5f";
    size_t length;

    AVS_UNIT_ASSERT_SUCCESS(avs_url_percent_decode(data, &length));
    AVS_UNIT_ASSERT_EQUAL_STRING(data, ":K|]n_");
    AVS_UNIT_ASSERT_EQUAL(length, 6);
}

AVS_UNIT_TEST(url_unescape, uppercase_hex) {
    char data[] = "%3A%4B%7C%5D%6E%5F";
    size_t length;

    AVS_UNIT_ASSERT_SUCCESS(avs_url_percent_decode(data, &length));
    AVS_UNIT_ASSERT_EQUAL_STRING(data, ":K|]n_");
    AVS_UNIT_ASSERT_EQUAL(length, 6);
}

AVS_UNIT_TEST(url_unescape, null_character) {
    char data[] = "%40vsystem%00%40vsystem";
    size_t length;

    AVS_UNIT_ASSERT_SUCCESS(avs_url_percent_decode(data, &length));
    AVS_UNIT_ASSERT_EQUAL_STRING(data, "@vsystem");
    AVS_UNIT_ASSERT_EQUAL(data[8], '\0');
    AVS_UNIT_ASSERT_EQUAL_STRING(data + 9, "@vsystem");
    AVS_UNIT_ASSERT_EQUAL(length, 17);
}
