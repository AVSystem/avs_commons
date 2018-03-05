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

#include <avs_commons_config.h>

#include <inttypes.h>

#include <avsystem/commons/stream/md5.h>
#include <avsystem/commons/utils.h>

#include "../auth.h"
#include "../client.h"
#include "../http_log.h"
#include "../http_stream.h"

VISIBILITY_SOURCE_BEGIN

typedef char md5_hexbuf_t[33];

static int http_auth_ha1(avs_stream_abstract_t *md5,
                         const http_auth_t *auth,
                         const char *cnonce,
                         md5_hexbuf_t *hexbuf) {
    int result;
    char bytebuf[16];

    if ((result = avs_stream_write_f(md5, "%s:%s:%s",
                                     auth->credentials.user
                                             ? auth->credentials.user : "",
                                     auth->state.realm,
                                     auth->credentials.password
                                             ? auth->credentials.password : ""))
            || (result = avs_stream_finish_message(md5))
            || (result = avs_stream_read_reliably(md5, bytebuf,
                                                  sizeof(bytebuf)))) {
        return result;
    }
    if (avs_hexlify(*hexbuf, sizeof(*hexbuf), bytebuf, sizeof(bytebuf))
            != sizeof(*bytebuf)) {
        return -1;
    }

    if (auth->state.flags.use_md5_sess) {
        if ((result = avs_stream_write_f(md5, "%s:%s:%s",
                                         *hexbuf, auth->state.nonce, cnonce))
                || (result = avs_stream_finish_message(md5))
                || (result = avs_stream_read_reliably(md5, bytebuf,
                                                      sizeof(bytebuf)))) {
            return result;
        }
        if (avs_hexlify(*hexbuf, sizeof(*hexbuf), bytebuf, sizeof(bytebuf))
                != sizeof(*bytebuf)) {
            return -1;
        }
    }

    return 0;
}

static int http_auth_ha2(avs_stream_abstract_t *md5,
                         avs_http_method_t method,
                         const char *digest_uri,
                         md5_hexbuf_t *hexbuf) {
    int result;
    char bytebuf[16];

    if ((result = avs_stream_write_f(md5, "%s:%s",
                                     _AVS_HTTP_METHOD_NAMES[method],
                                     digest_uri))
            || (result = avs_stream_finish_message(md5))
            || (result = avs_stream_read_reliably(md5, bytebuf,
                                                  sizeof(bytebuf)))) {
        return result;
    }
    if (avs_hexlify(*hexbuf, sizeof(*hexbuf), bytebuf, sizeof(bytebuf))
            != sizeof(*bytebuf)) {
        return -1;
    }

    return 0;
}

static int http_auth_response(avs_stream_abstract_t *md5,
                              const http_auth_t *auth,
                              const char *ha1,
                              const char *ha2,
                              const char *nonce,
                              const char *nc,
                              const char *cnonce,
                              md5_hexbuf_t *hexbuf) {
    int result;
    char bytebuf[16];

    if ((result = avs_stream_write_f(md5, "%s:%s:", ha1, nonce))
            || (auth->state.flags.use_qop_auth
                    && (result = avs_stream_write_f(md5, "%s:%s:auth:",
                                                    nc, cnonce)))
            || (result = avs_stream_write_f(md5, "%s", ha2))
            || (result = avs_stream_finish_message(md5))
            || (result = avs_stream_read_reliably(md5, bytebuf,
                                                  sizeof(bytebuf)))) {
        return result;
    }
    if (avs_hexlify(*hexbuf, sizeof(*hexbuf), bytebuf, sizeof(bytebuf))
            != sizeof(*bytebuf)) {
        return -1;
    }

    return 0;
}

static void generate_random_nonce(char out[17], unsigned *random_seed) {
    size_t i;
    uint64_t client_nonce;
    for (i = 0; i < sizeof(client_nonce); ++i) {
        ((unsigned char *) &client_nonce)[i] =
                (unsigned char) (avs_rand_r(random_seed) & 0xFF);
    }
    sprintf(out, "%016" PRIX64, client_nonce);
}

int _avs_http_auth_send_header_digest(http_stream_t *stream) {
    md5_hexbuf_t HA1hex, HA2hex, hash;
    char nc[9];
    int result = -1;
    char client_nonce[17];
    avs_stream_abstract_t *md5 = avs_stream_md5_create();

    if (!md5) {
        goto auth_digest_error;
    }

    sprintf(nc, "%08x", stream->auth.state.nc++);
    generate_random_nonce(client_nonce, &stream->random_seed);

    if (http_auth_ha1(md5, &stream->auth, client_nonce, &HA1hex)
            || http_auth_ha2(md5, stream->method, avs_url_path(stream->url),
                             &HA2hex)
            || http_auth_response(md5, &stream->auth,
                                  HA1hex, HA2hex, stream->auth.state.nonce, nc,
                                  client_nonce, &hash)) {
        goto auth_digest_error;
    }

    result = (avs_stream_write_f(stream->backend, "Authorization: Digest")
            || avs_stream_write_f(stream->backend, " username=\"%s\"",
                                  stream->auth.credentials.user
                                          ? stream->auth.credentials.user : "")
            || avs_stream_write_f(stream->backend, ", realm=\"%s\"",
                                  stream->auth.state.realm)
            || avs_stream_write_f(stream->backend, ", nonce=\"%s\"",
                                  stream->auth.state.nonce)
            || avs_stream_write_f(stream->backend, ", uri=\"%s\"",
                                  avs_url_path(stream->url))
            || avs_stream_write_f(stream->backend, ", response=\"%s\"", hash)
            || avs_stream_write_f(stream->backend, ", algorithm=%s",
                                  stream->auth.state.flags.use_md5_sess
                                          ? "MD5-sess" : "MD5")
            || (stream->auth.state.opaque
                && avs_stream_write_f(stream->backend, ", opaque=\"%s\"",
                                      stream->auth.state.opaque))
            || (stream->auth.state.flags.use_qop_auth
                && (avs_stream_write_f(stream->backend, ", qop=auth")
                    || avs_stream_write_f(stream->backend, ", cnonce=\"%s\"",
                                          client_nonce)
                    || avs_stream_write_f(stream->backend, ", nc=%s", nc)))
            || avs_stream_write_f(stream->backend, "\r\n"));
auth_digest_error:
    if (result) {
        LOG(ERROR, "error calculating digest auth md5");
    }
    avs_stream_cleanup(&md5);
    return result;
}
