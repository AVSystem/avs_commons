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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/url.h>

#include "net.h"

#ifdef HAVE_VISIBILITY
#pragma GCC visibility push(hidden)
#endif

#define CWMP_TUNABLE_URL_HOSTNAME_SIZE 64
#define CWMP_TUNABLE_URL_PASSWORD_SIZE 64
#define CWMP_TUNABLE_URL_PATH_SIZE 256
#define CWMP_TUNABLE_URL_PROTO_SIZE 32
#define CWMP_TUNABLE_URL_USER_SIZE 64

struct avs_url {
    char protocol[CWMP_TUNABLE_URL_PROTO_SIZE];
    char user[CWMP_TUNABLE_URL_USER_SIZE];
    char password[CWMP_TUNABLE_URL_PASSWORD_SIZE];
    char host[NET_MAX_HOSTNAME_SIZE];
    char port[NET_PORT_SIZE];
    char path[CWMP_TUNABLE_URL_PATH_SIZE];
    bool password_set;
    bool user_set;
};

static int url_parse_protocol(const char **url, avs_url_t *parsed_url) {
    const char *proto_end = strstr(*url, "://");
    size_t proto_len = 0;
    if (!proto_end) {
        LOG(ERROR, "could not parse protocol");
        return -1;
    }
    proto_len = (size_t) (proto_end - *url);
    if (proto_len >= sizeof(parsed_url->protocol)) {
        LOG(ERROR, "protocol name too long");
        return -1;
    }
    memcpy(parsed_url->protocol, *url, proto_len);
    parsed_url->protocol[proto_len] = '\0';
    *url += proto_len + 3; /* 3 for "://" */
    return 0;
}

static int unescape(char *const data, size_t *unescaped_length) {
    char *src = data, *dst = data;

    if (!strchr(data, '%')) {
        /* nothing to unescape */
        *unescaped_length = strlen(data);
        return 0;
    }

    while (*src) {
        if (*src == '%') {
            if (isxdigit(src[1]) && isxdigit(src[2])) {
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
    if (unescape(data, &new_length)) {
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
    return isalnum(c) || strchr(";?&=" /* explicitly allowed for user/pass */
                                "$-_.+" /* "safe" set */
                                "!*'(),", /* "extra" set */
                                c) != NULL;
}

static int is_valid_escape_sequence(const char *str) {
    return str[0] == '%' && isxdigit(str[1]) && isxdigit(str[2]);
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
                                       avs_url_t *parsed_url) {
    parsed_url->user[0] = '\0';
    parsed_url->user_set = true;
    parsed_url->password[0] = '\0';
    parsed_url->password_set = false;
    if (end > begin) {
        {
            char *user = parsed_url->user;
            char *user_limit = parsed_url->user + sizeof(parsed_url->user) - 1;
            while ((begin < end) && (user < user_limit) && (*begin != ':')) {
                *user++ = *begin++;
            }
            *user = '\0';
            if ((begin != end) && (*begin != ':')) {
                LOG(ERROR, "username too long");
                return -1;
            }
        }
        if (begin < end) { /* this means that *begin == ':' */
            char *password = parsed_url->password;
            char *password_limit
                    = parsed_url->password + sizeof(parsed_url->password) - 1;
            ++begin; /* move after ':' */
            while ((begin < end) && (password < password_limit)) {
                *password++ = *begin++;
            }
            *password = '\0';
            if (begin != end) {
                LOG(ERROR, "password too long");
                return -1;
            }
            parsed_url->password_set = true;
        }
    }

    if (!is_valid_credential(parsed_url->user)
            || !is_valid_credential(parsed_url->password)) {
        LOG(ERROR, "invalid username or password");
        return -1;
    }

    if (prepare_string(parsed_url->user)) {
        LOG(ERROR, "cannot decode user");
        return -1;
    }
    if (prepare_string(parsed_url->password)) {
        LOG(ERROR, "cannot decode password");
        return -1;
    }
    return 0;
}

static int url_parse_credentials(const char **url, avs_url_t *parsed_url) {
    /* According to grammar from RFC1738, username and password must not
     * contain slashes */
    const char *credentials_end = strchr(*url, '@');
    const char *first_slash = strchr(*url, '/');
    if (credentials_end && (!first_slash || credentials_end < first_slash)) {
        if (parse_username_and_password(*url, credentials_end, parsed_url)) {
            LOG(ERROR, "cannot parse credentials from URL");
            return -1;
        }
        *url = credentials_end + 1;
    } else {
        parsed_url->user[0] = '\0';
        parsed_url->user_set = false;
        parsed_url->password[0] = '\0';
        parsed_url->password_set = false;
    }
    return 0;
}

static int is_valid_url_domain_char(char c) {
    /* Assumes english locale.
     * According to RFC 1783, domains may not contain non-alphanumeric
     * characters beside dot and hyphen. The dot may only be used as
     * domain segment separator. */
    return c == '-' || isalnum(c);
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
    if (!isalpha(last_segment[0])) {
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

static int url_parse_host(const char **url, avs_url_t *parsed_url) {
    const char *raw_url = *url;
    char *host = parsed_url->host;
    char *host_limit = parsed_url->host + sizeof(parsed_url->host) - 1;

    if (*raw_url == '[') {
        ++raw_url;
        while ((host < host_limit)
                && (*raw_url != '\0')
                && (*raw_url != ']')) {
            *host++ = *raw_url++;
        }
        if ((*raw_url != '\0') && (*raw_url != ']')) {
            LOG(ERROR, "host address too long");
            return -1;
        }
        if (*raw_url++ != ']') {
            LOG(ERROR, "expected ] at the end of host address");
            return -1;
        }
    } else {
        while ((host < host_limit)
                && (*raw_url != '\0')
                && (*raw_url != '/')
                && (*raw_url != ':')) {
            *host++ = *raw_url++;
        }
        if ((*raw_url != '\0') && (*raw_url != '/') && (*raw_url != ':')) {
            LOG(ERROR, "host address too long");
            return -1;
        }
    }
    if (host == parsed_url->host) {
        LOG(ERROR, "host part cannot be empty");
        return -1;
    }
    *host = '\0';
    *url = raw_url;

    if (!is_valid_host(parsed_url->host)) {
        return -1;
    }
    return 0;
}

static int url_parse_port(const char **url, avs_url_t *parsed_url) {
    const char *raw_url = *url;
    char *port = parsed_url->port;
    char *port_limit = parsed_url->port + sizeof(parsed_url->port) - 1;

    if (*raw_url == ':') {
        ++raw_url; /* move after ':' */
        while ((port < port_limit) && isdigit(*raw_url)) {
            *port++ = *raw_url++;
        }
        if (isdigit(*raw_url)) {
            LOG(ERROR, "port too long");
            return -1;
        }
        if (*raw_url != '\0' && *raw_url != '/') {
            LOG(ERROR, "port should have numeric value");
            return -1;
        }
        if (port == parsed_url->port) {
            LOG(ERROR, "expected at least 1 digit for port number");
            return -1;
        }
    }
    *port = '\0';

    *url = raw_url;
    return 0;
}

static int is_valid_url_path_char(char c) {
    /* Assumes English locale. */
    return isalnum(c) || !!strchr("/"
                                  "?" /* this technically is reserved, but our
                                         tests ensure it works too */
                                  ";:@&="
                                  "$-_.+" /* "safe" set defined in RFC 1783 */
                                  "!*'(),", c); /* "extra" set */
}

static int is_valid_path(const char *str) {
    return is_valid_url_part(str, is_valid_url_path_char);
}

static int url_parse_path(const char **url, avs_url_t *parsed_url) {
    const char *raw_url = *url;
    char *path = parsed_url->path;
    char *path_limit = parsed_url->path + sizeof(parsed_url->path) - 1;
    /* parse path */
    if (*raw_url) {
        while ((path < path_limit) && (*raw_url != '\0')) {
            *path++ = *raw_url++;
        }
        if ((*raw_url != '\0')) {
            LOG(ERROR, "path is too long in url");
            return -1;
        }
    } else {
        *path++ = '/';
    }
    *path = '\0';
    *url = raw_url;

    if (!is_valid_path(parsed_url->path)) {
        return -1;
    }
    return 0;
}

static int url_parsed(const char *url) {
    return (*url != '\0');
}

avs_url_t *avs_url_parse(const char *raw_url) {
    avs_url_t *out = (avs_url_t *) malloc(sizeof(avs_url_t));
    if (!out) {
        LOG(ERROR, "out of memory");
        return NULL;
    }
    if (url_parse_protocol(&raw_url, out)
            || url_parse_credentials(&raw_url, out)
            || url_parse_host(&raw_url, out)
            || url_parse_port(&raw_url, out)
            || url_parse_path(&raw_url, out)
            || url_parsed(raw_url)) {
        free(out);
        return NULL;
    }
    return out;
}

avs_url_t *avs_url_copy(const avs_url_t *url) {
    avs_url_t *out = (avs_url_t *) malloc(sizeof(avs_url_t));
    if (!out) {
        LOG(ERROR, "out of memory");
        return NULL;
    }
    *out = *url;
    return out;
}

const char *avs_url_protocol(const avs_url_t *url) {
    return url->protocol;
}

const char *avs_url_user(const avs_url_t *url) {
    return url->user_set ? url->user : NULL;
}

const char *avs_url_password(const avs_url_t *url) {
    return url->password_set ? url->password : NULL;
}

const char *avs_url_host(const avs_url_t *url) {
    return url->host;
}

const char *avs_url_port(const avs_url_t *url) {
    return url->port[0] != '\0' ? url->port : NULL;
}

const char *avs_url_path(const avs_url_t *url) {
    return url->path;
}

void avs_url_free(avs_url_t *url) {
    free(url);
}
