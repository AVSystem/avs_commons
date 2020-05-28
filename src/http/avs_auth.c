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

#ifdef AVS_COMMONS_WITH_AVS_HTTP

#    include <ctype.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_auth.h"
#    include "avs_http_stream.h"

#    include "avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

static void http_auth_new_header(http_auth_t *auth) {
    auth->state.flags.type = HTTP_AUTH_TYPE_NONE;
    auth->state.flags.use_md5_sess = 0;
    auth->state.flags.use_qop_auth = 0;
    avs_free(auth->state.opaque);
    auth->state.opaque = NULL;
}

void _avs_http_auth_reset(http_auth_t *auth) {
    avs_free(auth->state.nonce);
    avs_free(auth->state.realm);
    avs_free(auth->state.opaque);
    memset(&auth->state, 0, sizeof(auth->state));
}

static char *consume_alloc_quotable_token(const char **src) {
    const char *src_copy = *src;
    avs_consume_quotable_token(&src_copy, NULL, 0, "," AVS_SPACES);
    size_t bufsize = (size_t) (src_copy - *src) + 1;
    char *buf = (char *) avs_malloc(bufsize);
    if (buf) {
        avs_consume_quotable_token(src, buf, bufsize, "," AVS_SPACES);
    }
    return buf;
}

int _avs_http_auth_setup(http_auth_t *auth, const char *challenge) {
    http_auth_new_header(auth);
    if (avs_match_token(&challenge, "Basic", AVS_SPACES) == 0) {
        LOG(TRACE, _("Basic authentication"));
        auth->state.flags.type = HTTP_AUTH_TYPE_BASIC;
    } else if (avs_match_token(&challenge, "Digest", AVS_SPACES) == 0) {
        LOG(TRACE, _("Digest authentication"));
        auth->state.flags.type = HTTP_AUTH_TYPE_DIGEST;
    } else {
        /* unknown scheme, ignore */
        LOG(WARNING, _("No authentication"));
        return 0;
    }

    while (*challenge) {
        if (avs_match_token(&challenge, "realm", "=") == 0) {
            avs_free(auth->state.realm);
            if (!(auth->state.realm =
                          consume_alloc_quotable_token(&challenge))) {
                LOG(ERROR, _("Could not allocate memory for auth realm"));
                return -1;
            }
            LOG(TRACE, _("Auth realm: ") "%s", auth->state.realm);
        } else if (avs_match_token(&challenge, "nonce", "=") == 0) {
            avs_free(auth->state.nonce);
            if (!(auth->state.nonce =
                          consume_alloc_quotable_token(&challenge))) {
                LOG(ERROR, _("Could not allocate memory for auth nonce"));
                return -1;
            }
            auth->state.nc = 1;
            LOG(TRACE, _("Auth nonce: ") "%s", auth->state.nonce);
        } else if (avs_match_token(&challenge, "opaque", "=") == 0) {
            avs_free(auth->state.opaque);
            if (!(auth->state.opaque =
                          consume_alloc_quotable_token(&challenge))) {
                LOG(ERROR, _("Could not allocate memory for auth opaque"));
                return -1;
            }
            LOG(TRACE, _("Auth opaque: ") "%s", auth->state.opaque);
        } else if (avs_match_token(&challenge, "algorithm", "=") == 0) {
            char algorithm[16];
            avs_consume_quotable_token(&challenge, algorithm, sizeof(algorithm),
                                       "," AVS_SPACES);
            if (avs_strcasecmp(algorithm, "MD5-sess") == 0) {
                auth->state.flags.use_md5_sess = 1;
                LOG(TRACE, _("Auth algorithm: MD5-sess"));
            } else if (avs_strcasecmp(algorithm, "MD5") == 0) {
                LOG(TRACE, _("Auth algorithm: MD5"));
            } else {
                LOG(ERROR, _("Unknown auth algorithm: ") "%s", algorithm);
                return -1;
            }
        } else if (avs_match_token(&challenge, "qop", "=") == 0) {
            char *qop_options_buf = consume_alloc_quotable_token(&challenge);
            if (!qop_options_buf) {
                LOG(ERROR, _("Could not allocate memory for qop"));
                return -1;
            }
            char *qop_options_tmp, *qop_options = qop_options_buf;
            const char *qop_option;
            while ((qop_option = avs_strtok(qop_options, "," AVS_SPACES,
                                            &qop_options_tmp))) {
                qop_options = NULL;
                LOG(TRACE, _("Auth qop: ") "%s", qop_option);
                if (avs_strcasecmp(qop_option, "auth") == 0) {
                    auth->state.flags.use_qop_auth = 1;
                    break;
                }
            }
            avs_free(qop_options_buf);
            if (!auth->state.flags.use_qop_auth) {
                LOG(ERROR,
                    _("qop option present, but qop=\"auth\" not supported"));
                return -1;
            }
        } else {
            avs_consume_quotable_token(&challenge, NULL, 0, "," AVS_SPACES);
        }
    }
    return 0;
}

avs_error_t _avs_http_auth_send_header(http_stream_t *stream) {
    LOG(TRACE, _("http_send_auth_header"));
    switch (stream->auth.state.flags.type) {
    case HTTP_AUTH_TYPE_NONE:
        LOG(TRACE, _("HTTP_AUTH_NONE"));
        return AVS_OK;

    case HTTP_AUTH_TYPE_BASIC:
        LOG(TRACE, _("HTTP_AUTH_BASIC"));
        return _avs_http_auth_send_header_basic(stream);

    case HTTP_AUTH_TYPE_DIGEST:
        LOG(TRACE, _("HTTP_AUTH_DIGEST"));
        return _avs_http_auth_send_header_digest(stream);

    default:
        LOG(ERROR, _("unknown auth type ") "%d",
            (int) stream->auth.state.flags.type);
        return avs_errno(AVS_EPROTO);
    }
}

int _avs_http_auth_setup_stream(http_stream_t *stream,
                                const avs_url_t *parsed_url,
                                const char *auth_username,
                                const char *auth_password) {
    avs_free(stream->auth.credentials.user);
    stream->auth.credentials.user = NULL;
    if (auth_username) {
        if (!(stream->auth.credentials.user = avs_strdup(auth_username))) {
            goto error;
        }
    } else {
        const char *user = avs_url_user(parsed_url);
        if (user && !(stream->auth.credentials.user = avs_strdup(user))) {
            goto error;
        }
    }

    avs_free(stream->auth.credentials.password);
    stream->auth.credentials.password = NULL;
    if (auth_password) {
        if (!(stream->auth.credentials.password = avs_strdup(auth_password))) {
            goto error;
        }
    } else {
        const char *password = avs_url_password(parsed_url);
        if (password
                && !(stream->auth.credentials.password =
                             avs_strdup(password))) {
            goto error;
        }
    }
    return 0;

error:
    _avs_http_auth_clear(&stream->auth);
    return -1;
}

void _avs_http_auth_clear(http_auth_t *auth) {
    _avs_http_auth_reset(auth);
    avs_free(auth->credentials.user);
    auth->credentials.user = NULL;
    avs_free(auth->credentials.password);
    auth->credentials.password = NULL;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
