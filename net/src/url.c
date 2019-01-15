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

#include <avs_commons_config.h>

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/memory.h>
#include <avsystem/commons/url.h>
#include <avsystem/commons/utils.h>

#include "net_impl.h"

VISIBILITY_SOURCE_BEGIN

struct avs_url {
    size_t user_ptr;
    size_t password_ptr;
    size_t host_ptr;
    size_t port_ptr;
    size_t path_ptr;
    char data[];
};

static int url_parse_protocol(const char **url,
                              size_t *data_out_ptr,
                              size_t out_limit,
                              avs_url_t *parsed_url) {
    const char *proto_end = strstr(*url, "://");
    size_t proto_len = 0;
    if (!proto_end) {
        LOG(ERROR, "could not parse protocol");
        return -1;
    }
    proto_len = (size_t) (proto_end - *url);
    assert(*data_out_ptr + proto_len < out_limit);
    (void) out_limit;
    assert(*data_out_ptr == 0);
    memcpy(parsed_url->data, *url, proto_len);
    *data_out_ptr += proto_len;
    parsed_url->data[(*data_out_ptr)++] = '\0';
    *url += proto_len + sizeof("://") - 1;
    return 0;
}

int avs_url_percent_encode(avs_stream_abstract_t *stream,
                           const char *input,
                           const char *unreserved_chars) {
    const char *start = input;
    char escaped_buf[4];
    for (; *input; ++input) {
        if (*(const unsigned char *) input >= 0x80 // non-ASCII character
                || !(isalnum((unsigned char)*input)
                || strchr(unreserved_chars, *input))) {
            if (input - start > 0) {
                if (avs_stream_write(stream, start, (size_t) (input - start))) {
                    return -1;
                }
            }
            if (avs_simple_snprintf(escaped_buf, sizeof(escaped_buf), "%%%02x",
                                    (unsigned char) *input) != 3
                    || avs_stream_write(stream, escaped_buf, 3)) {
                return -1;
            }
            start = input + 1;
        }
    }
    if (input - start > 0) {
        if (avs_stream_write(stream, start, (size_t) (input - start))) {
            return -1;
        }
    }
    return 0;
}

int avs_url_percent_decode(char *data, size_t *unescaped_length) {
    char *src = data, *dst = data;

    if (!strchr(data, '%')) {
        /* nothing to unescape */
        *unescaped_length = strlen(data);
        return 0;
    }

    while (*src) {
        if (*src == '%') {
            if (isxdigit((unsigned char)src[1])
                    && isxdigit((unsigned char)src[2])) {
                char ascii[3];
                ascii[0] = src[1];
                ascii[1] = src[2];
                ascii[2] = '\0';
                *dst = (char) strtoul(ascii, NULL, 16);
                src += 3;
                dst += 1;
            } else {
                LOG(ERROR, "bad escape format (%%XX) ");
                return -1;
            }
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    *unescaped_length = (size_t) (dst - data);
    return 0;
}

static int prepare_string(char *data) {
    size_t new_length = 0;
    if (avs_url_percent_decode(data, &new_length)) {
        LOG(ERROR, "unescape failure");
        return -1;
    }
    if (new_length != strlen(data)) {
        LOG(ERROR, "string cannot include null byte");
        return -1;
    }
    return 0;
}

static int is_valid_credential_char(char c) {
    return isalnum((unsigned char)c)
        || strchr(";?&=" /* explicitly allowed for user/pass */
                  "$-_.+" /* "safe" set */
                  "!*'(),", /* "extra" set */
                  c) != NULL;
}

static int is_valid_escape_sequence(const char *str) {
    return str[0] == '%'
        && isxdigit((unsigned char)str[1])
        && isxdigit((unsigned char)str[2]);
}

static int is_valid_url_part(const char *str,
                             int (*is_unescaped_character_valid)(char)) {
    if (!str) {
        return 0;
    }

    while (*str) {
        if (is_unescaped_character_valid(*str)) {
            ++str;
        } else if (is_valid_escape_sequence(str)) {
            str += sizeof("%xx") - 1;
        } else {
            return 0;
        }
    }

    return 1;
}

static int is_valid_credential(const char *str) {
    return is_valid_url_part(str, is_valid_credential_char);
}

static int parse_username_and_password(const char *begin,
                                       const char *end,
                                       size_t *data_out_ptr,
                                       size_t out_limit,
                                       avs_url_t *parsed_url) {
    // parse username
    size_t user_ptr = *data_out_ptr;
    while (begin < end && *data_out_ptr < out_limit && *begin != ':') {
        parsed_url->data[(*data_out_ptr)++] = *begin++;
    }
    parsed_url->data[(*data_out_ptr)++] = '\0';
    assert(begin == end || *begin == ':');

    if (!is_valid_credential(&parsed_url->data[user_ptr])
            || prepare_string(&parsed_url->data[user_ptr])) {
        LOG(ERROR, "invalid username");
        return -1;
    }
    parsed_url->user_ptr = user_ptr;
    *data_out_ptr = user_ptr + strlen(&parsed_url->data[user_ptr]) + 1;

    if (begin >= end) {
        return 0; // no password
    }

    // parse password
    size_t password_ptr = *data_out_ptr;
    ++begin; // move after ':'
    while (begin < end && *data_out_ptr < out_limit) {
        parsed_url->data[(*data_out_ptr)++] = *begin++;
    }
    parsed_url->data[(*data_out_ptr)++] = '\0';
    assert(begin == end);

    if (!is_valid_credential(&parsed_url->data[password_ptr])
            || prepare_string(&parsed_url->data[password_ptr])) {
        LOG(ERROR, "invalid username");
        return -1;
    }
    parsed_url->password_ptr = password_ptr;
    *data_out_ptr = password_ptr + strlen(&parsed_url->data[password_ptr]) + 1;
    return 0;
}

static int url_parse_credentials(const char **url,
                                 size_t *data_out_ptr,
                                 size_t out_limit,
                                 avs_url_t *parsed_url) {
    /* According to grammar from RFC1738, username and password must not
     * contain slashes */
    const char *credentials_end = strchr(*url, '@');
    const char *first_slash = strchr(*url, '/');
    if (credentials_end && (!first_slash || credentials_end < first_slash)) {
        if (parse_username_and_password(*url, credentials_end,
                                        data_out_ptr, out_limit, parsed_url)) {
            LOG(ERROR, "cannot parse credentials from URL");
            return -1;
        }
        *url = credentials_end + 1;
    }
    return 0;
}

static int is_valid_url_domain_char(char c) {
    /* Assumes english locale.
     * According to RFC 1783, domains may not contain non-alphanumeric
     * characters beside dot and hyphen. The dot may only be used as
     * domain segment separator. */
    return c == '-' || isalnum((unsigned char)c);
}

static int is_valid_domain(const char *str) {
    const char *last_segment = str;
    char prev_c = '\0';

    while (*str) {
        char c = *str++;

        if (c == '.') {
            if (prev_c == '.') {
                LOG(ERROR, "consecutive dots in domain name");
                return 0;
            }

            last_segment = str;
        } else if (!is_valid_url_domain_char(c)) {
            LOG(ERROR, "invalid character in domain name: %c", c);
            return 0;
        }

        prev_c = c;
    }

    /* Last segment MUST start with a letter */
    if (!isalpha((unsigned char)last_segment[0])) {
        LOG(ERROR, "top-level domain does not start with a letter: %s",
            last_segment);
        return 0;
    }

    return 1;
}

static int is_valid_host(const char *str) {
    return avs_net_validate_ip_address(AVS_NET_AF_INET4, str) == 0
        || avs_net_validate_ip_address(AVS_NET_AF_INET6, str) == 0
        || is_valid_domain(str);
}

static int url_parse_host(const char **url,
                          size_t *data_out_ptr,
                          size_t out_limit,
                          avs_url_t *parsed_url) {
    parsed_url->host_ptr = *data_out_ptr;
    if (**url == '[') {
        ++*url;
        while (*data_out_ptr < out_limit && **url != '\0' && **url != ']') {
            parsed_url->data[(*data_out_ptr)++] = *(*url)++;
        }
        assert(**url == '\0' || **url == ']');
        if (*(*url)++ != ']') {
            LOG(ERROR, "expected ] at the end of host address");
            return -1;
        }
    } else {
        while (*data_out_ptr < out_limit
                && **url != '\0'
                && **url != '/'
                && **url != '?'
                && **url != ':') {
            parsed_url->data[(*data_out_ptr)++] = *(*url)++;
        }
        assert(**url == '\0' || **url == '/' || **url == '?' || **url == ':');
    }
    if (*data_out_ptr == parsed_url->host_ptr) {
        LOG(ERROR, "host part cannot be empty");
        return -1;
    }
    parsed_url->data[(*data_out_ptr)++] = '\0';

    if (!is_valid_host(&parsed_url->data[parsed_url->host_ptr])) {
        return -1;
    }
    return 0;
}

static int url_parse_port(const char **url,
                          size_t *data_out_ptr,
                          size_t out_limit,
                          avs_url_t *parsed_url) {
    if (**url != ':') {
        return 0;
    }

    parsed_url->port_ptr = *data_out_ptr;
    ++*url; // move after ':'
    size_t port_limit = AVS_MIN(out_limit, *data_out_ptr + 5);
    while (*data_out_ptr < port_limit && isdigit((unsigned char)**url)) {
        parsed_url->data[(*data_out_ptr)++] = *(*url)++;
    }
    if (isdigit((unsigned char)**url)) {
        LOG(ERROR, "port too long");
        return -1;
    }
    if (**url != '\0' && **url != '/' && **url != '?') {
        LOG(ERROR, "port should have numeric value");
        return -1;
    }
    if (*data_out_ptr == parsed_url->port_ptr) {
        LOG(ERROR, "expected at least 1 digit for port number");
        return -1;
    }
    parsed_url->data[(*data_out_ptr)++] = '\0';
    return 0;
}

static int is_valid_url_path_char(char c) {
    /* Assumes English locale. */
    return isalnum((unsigned char)c)
        || !!strchr("/"
                    "?~" /* these technically are reserved, but our
                            tests ensure it works too */
                    ";:@&="
                    "$-_.+" /* "safe" set defined in RFC 1738 */
                    "!*'(),", c); /* "extra" set */
}

static int is_valid_path(const char *str) {
    return is_valid_url_part(str, is_valid_url_path_char);
}

static int url_parse_path(const char **url,
                          size_t *data_out_ptr,
                          size_t out_limit,
                          avs_url_t *parsed_url) {
    parsed_url->path_ptr = *data_out_ptr;
    if (!**url || **url == '?') {
        parsed_url->data[(*data_out_ptr)++] = '/';
    }
    while (*data_out_ptr < out_limit && **url != '\0') {
        parsed_url->data[(*data_out_ptr)++] = *(*url)++;
    }
    assert(*data_out_ptr < out_limit);
    parsed_url->data[(*data_out_ptr)++] = '\0';

    if (!is_valid_path(&parsed_url->data[parsed_url->path_ptr])) {
        return -1;
    }
    return 0;
}

static int url_parsed(const char *url) {
    return (*url != '\0');
}

avs_url_t *avs_url_parse(const char *raw_url) {
    // In data, we store all the components from raw_url;
    // The input url, in its fullest possible form, looks like this:
    //
    //     proto://user:password@hostname:port/path\0
    //
    // The output data will look like this:
    //
    //     proto\0user\0password\0hostname\0port\0/path\0
    //
    // A copy of the original string would require strlen(raw_url)+1 bytes.
    // Then:
    // - we replace "://" with a single nullbyte                :  -2 bytes
    // - we replace ":" before password with nullbyte           : +-0 bytes
    // - we replace "@" before hostname with nullbyte           : +-0 bytes
    // - we replace ":" before port with nullbyte               : +-0 bytes
    // - we add a nullbyte before path's "/"                    :  +1 byte
    // - we add a "/" in path if it's empty or query string only:  +1 byte
    //                                                          -----------
    // TOTAL DIFFERENCE IN REQUIRED SIZE:                           0 bytes
    //
    // Thus, we know that we need out->data to be strlen(raw_url)+1 bytes long.
    size_t data_length = strlen(raw_url) + 1;
    avs_url_t *out =
            (avs_url_t *) avs_calloc(1, offsetof(avs_url_t, data) + data_length);
    if (!out) {
        LOG(ERROR, "out of memory");
        return NULL;
    }
    size_t data_out_ptr = 0;
    if (url_parse_protocol(&raw_url, &data_out_ptr, data_length, out)
            || url_parse_credentials(&raw_url,
                                     &data_out_ptr, data_length, out)
            || url_parse_host(&raw_url, &data_out_ptr, data_length, out)
            || url_parse_port(&raw_url, &data_out_ptr, data_length, out)
            || url_parse_path(&raw_url, &data_out_ptr, data_length, out)
            || url_parsed(raw_url)) {
        avs_free(out);
        return NULL;
    }
    return out;
}

avs_url_t *avs_url_copy(const avs_url_t *url) {
    const char *path = &url->data[url->path_ptr];
    const char *last_nullbyte = path + strlen(path);
    ptrdiff_t alloc_size = last_nullbyte + 1 - (const char *) url;
    assert(alloc_size > 0 && (size_t) alloc_size > offsetof(avs_url_t, data));
    avs_url_t *out = (avs_url_t *) avs_malloc((size_t) alloc_size);
    if (!out) {
        LOG(ERROR, "out of memory");
        return NULL;
    }
    memcpy(out, url, (size_t) alloc_size);
    return out;
}

const char *avs_url_protocol(const avs_url_t *url) {
    return url->data;
}

const char *avs_url_user(const avs_url_t *url) {
    return url->user_ptr ? &url->data[url->user_ptr] : NULL;
}

const char *avs_url_password(const avs_url_t *url) {
    return url->password_ptr ? &url->data[url->password_ptr] : NULL;
}

const char *avs_url_host(const avs_url_t *url) {
    return &url->data[url->host_ptr];
}

const char *avs_url_port(const avs_url_t *url) {
    return url->port_ptr ? &url->data[url->port_ptr] : NULL;
}

const char *avs_url_path(const avs_url_t *url) {
    return &url->data[url->path_ptr];
}

void avs_url_free(avs_url_t *url) {
    avs_free(url);
}

#ifdef AVS_UNIT_TESTING
#include "test/url.c"
#endif // AVS_UNIT_TESTING
