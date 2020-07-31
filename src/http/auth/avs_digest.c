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

#    include <inttypes.h>

#    include <avsystem/commons/avs_stream_md5.h>
#    include <avsystem/commons/avs_utils.h>

#    include "../avs_auth.h"
#    include "../avs_client.h"
#    include "../avs_http_stream.h"

#    include "../avs_http_log.h"

VISIBILITY_SOURCE_BEGIN

typedef char md5_hexbuf_t[33];

static avs_error_t http_auth_ha1(avs_stream_t *md5,
                                 const http_auth_t *auth,
                                 const char *cnonce,
                                 md5_hexbuf_t *hexbuf) {
    avs_error_t err;
    char bytebuf[16];

    if (avs_is_err(
                (err = avs_stream_write_f(
                         md5, "%s:%s:%s",
                         auth->credentials.user ? auth->credentials.user : "",
                         auth->state.realm,
                         auth->credentials.password ? auth->credentials.password
                                                    : "")))
            || avs_is_err((err = avs_stream_finish_message(md5)))
            || avs_is_err((err = avs_stream_read_reliably(md5, bytebuf,
                                                          sizeof(bytebuf))))) {
        return err;
    }
    size_t bytes_hexlified;
    if (avs_hexlify(*hexbuf, sizeof(*hexbuf), &bytes_hexlified, bytebuf,
                    sizeof(bytebuf))
            || bytes_hexlified != sizeof(bytebuf)) {
        return avs_errno(AVS_EPROTO);
    }

    if (auth->state.flags.use_md5_sess) {
        if (avs_is_err((err = avs_stream_write_f(md5, "%s:%s:%s", *hexbuf,
                                                 auth->state.nonce, cnonce)))
                || avs_is_err((err = avs_stream_finish_message(md5)))
                || avs_is_err((err = avs_stream_read_reliably(
                                       md5, bytebuf, sizeof(bytebuf))))) {
            return err;
        }
        if (avs_hexlify(*hexbuf, sizeof(*hexbuf), &bytes_hexlified, bytebuf,
                        sizeof(bytebuf))
                || bytes_hexlified != sizeof(bytebuf)) {
            return avs_errno(AVS_EPROTO);
        }
    }

    return AVS_OK;
}

static avs_error_t http_auth_ha2(avs_stream_t *md5,
                                 avs_http_method_t method,
                                 const char *digest_uri,
                                 md5_hexbuf_t *hexbuf) {
    avs_error_t err;
    char bytebuf[16];

    if (avs_is_err((err = avs_stream_write_f(md5, "%s:%s",
                                             _AVS_HTTP_METHOD_NAMES[method],
                                             digest_uri)))
            || avs_is_err((err = avs_stream_finish_message(md5)))
            || avs_is_err((err = avs_stream_read_reliably(md5, bytebuf,
                                                          sizeof(bytebuf))))) {
        return err;
    }
    size_t bytes_hexlified;
    if (avs_hexlify(*hexbuf, sizeof(*hexbuf), &bytes_hexlified, bytebuf,
                    sizeof(bytebuf))
            || bytes_hexlified != sizeof(bytebuf)) {
        return avs_errno(AVS_EPROTO);
    }

    return AVS_OK;
}

static avs_error_t http_auth_response(avs_stream_t *md5,
                                      const http_auth_t *auth,
                                      const char *ha1,
                                      const char *ha2,
                                      const char *nonce,
                                      const char *nc,
                                      const char *cnonce,
                                      md5_hexbuf_t *hexbuf) {
    avs_error_t err;
    char bytebuf[16];

    if (avs_is_err((err = avs_stream_write_f(md5, "%s:%s:", ha1, nonce)))
            || (auth->state.flags.use_qop_auth
                && avs_is_err((err = avs_stream_write_f(md5, "%s:%s:auth:", nc,
                                                        cnonce))))
            || avs_is_err((err = avs_stream_write_f(md5, "%s", ha2)))
            || avs_is_err((err = avs_stream_finish_message(md5)))
            || avs_is_err((err = avs_stream_read_reliably(md5, bytebuf,
                                                          sizeof(bytebuf))))) {
        return err;
    }
    size_t bytes_hexlified;
    if (avs_hexlify(*hexbuf, sizeof(*hexbuf), &bytes_hexlified, bytebuf,
                    sizeof(bytebuf))
            || bytes_hexlified != sizeof(bytebuf)) {
        return avs_errno(AVS_EPROTO);
    }

    return AVS_OK;
}

typedef struct {
    char data[2 * sizeof(uint64_t) + 1];
} nonce_t;

static void generate_random_nonce(nonce_t *nonce, unsigned *random_seed) {
    size_t i;
    uint64_t client_nonce;
    for (i = 0; i < sizeof(client_nonce); ++i) {
        ((unsigned char *) &client_nonce)[i] =
                (unsigned char) (avs_rand_r(random_seed) & 0xFF);
    }
    (void) avs_hexlify(nonce->data, sizeof(nonce->data), NULL, &client_nonce,
                       sizeof(uint64_t));
}

avs_error_t _avs_http_auth_send_header_digest(http_stream_t *stream) {
    md5_hexbuf_t HA1hex, HA2hex, hash;
    char nc[9];
    avs_error_t err = avs_errno(AVS_ENOMEM);
    avs_error_t stream_cleanup_err;
    nonce_t client_nonce;
    avs_stream_t *md5 = avs_stream_md5_create();

    if (!md5) {
        goto auth_digest_error;
    }

    sprintf(nc, "%08" PRIx32, stream->auth.state.nc++);
    generate_random_nonce(&client_nonce, &stream->random_seed);

    if (avs_is_err((err = http_auth_ha1(md5, &stream->auth, client_nonce.data,
                                        &HA1hex)))
            || avs_is_err((err = http_auth_ha2(md5, stream->method,
                                               avs_url_path(stream->url),
                                               &HA2hex)))
            || avs_is_err((err = http_auth_response(
                                   md5, &stream->auth, HA1hex, HA2hex,
                                   stream->auth.state.nonce, nc,
                                   client_nonce.data, &hash)))) {
        goto auth_digest_error;
    }

    (void) (avs_is_err((err = avs_stream_write_f(stream->backend,
                                                 "Authorization: Digest")))
            || avs_is_err((err = avs_stream_write_f(
                                   stream->backend, " username=\"%s\"",
                                   stream->auth.credentials.user
                                           ? stream->auth.credentials.user
                                           : "")))
            || avs_is_err((err = avs_stream_write_f(stream->backend,
                                                    ", realm=\"%s\"",
                                                    stream->auth.state.realm)))
            || avs_is_err((err = avs_stream_write_f(stream->backend,
                                                    ", nonce=\"%s\"",
                                                    stream->auth.state.nonce)))
            || avs_is_err((err = avs_stream_write_f(stream->backend,
                                                    ", uri=\"%s\"",
                                                    avs_url_path(stream->url))))
            || avs_is_err((err = avs_stream_write_f(stream->backend,
                                                    ", response=\"%s\"", hash)))
            || avs_is_err((err = avs_stream_write_f(
                                   stream->backend, ", algorithm=%s",
                                   stream->auth.state.flags.use_md5_sess
                                           ? "MD5-sess"
                                           : "MD5")))
            || (stream->auth.state.opaque
                && avs_is_err((err = avs_stream_write_f(
                                       stream->backend, ", opaque=\"%s\"",
                                       stream->auth.state.opaque))))
            || (stream->auth.state.flags.use_qop_auth
                && (avs_is_err((err = avs_stream_write_f(stream->backend,
                                                         ", qop=auth")))
                    || avs_is_err((err = avs_stream_write_f(stream->backend,
                                                            ", cnonce=\"%s\"",
                                                            client_nonce.data)))
                    || avs_is_err((err = avs_stream_write_f(stream->backend,
                                                            ", nc=%s", nc)))))
            || avs_is_err((err = avs_stream_write_f(stream->backend, "\r\n"))));
auth_digest_error:
    if (avs_is_err((stream_cleanup_err = avs_stream_cleanup(&md5)))) {
        LOG(ERROR, _("failed to close MD5 stream"));
    }
    if (avs_is_err(err)) {
        LOG(ERROR, _("error calculating digest auth md5"));
        return err;
    }
    return stream_cleanup_err;
}

#endif // AVS_COMMONS_WITH_AVS_HTTP
