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

#if defined(AVS_COMMONS_WITH_AVS_NET) && defined(AVS_COMMONS_WITH_MBEDTLS) \
        && defined(AVS_COMMONS_NET_WITH_X509)

#    include "../avs_api.h"
#    include "avs_mbedtls_data_loader.h"

#    include <assert.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_utils.h>

#    define MODULE_NAME avs_net_data_loader
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

#    define CREATE_OR_FAIL(type, ptr)                     \
        do {                                              \
            avs_free(*ptr);                               \
            *ptr = (type *) avs_calloc(1, sizeof(**ptr)); \
            if (!*ptr) {                                  \
                LOG(ERROR, _("Out of memory"));           \
                return avs_errno(AVS_ENOMEM);             \
            }                                             \
        } while (0)

static avs_error_t append_cert_from_buffer(mbedtls_x509_crt *chain,
                                           const void *buffer,
                                           size_t len) {
    return mbedtls_x509_crt_parse(chain, (const unsigned char *) buffer, len)
                   ? avs_errno(AVS_EPROTO)
                   : AVS_OK;
}

static avs_error_t load_cert_from_file(mbedtls_x509_crt *chain,
                                       const char *name) {
#    ifdef MBEDTLS_FS_IO
    LOG(DEBUG, _("certificate <") "%s" _(">: going to load"), name);

    int retval = -1;
    avs_error_t err = ((retval = mbedtls_x509_crt_parse_file(chain, name))
                               ? avs_errno(AVS_EPROTO)
                               : AVS_OK);
    if (avs_is_ok(err)) {
        LOG(DEBUG, _("certificate <") "%s" _(">: loaded"), name);
    } else {
        LOG(ERROR, _("certificate <") "%s" _(">: failed to load, result ") "%d",
            name, retval);
    }
    return err;
#    else  // MBEDTLS_FS_IO
    (void) chain;
    (void) name;
    LOG(DEBUG,
        _("certificate <") "%s" _(
                ">: mbed TLS configured without file system support, ")
                _("cannot load"),
        name);
    return avs_errno(AVS_ENOTSUP);
#    endif // MBEDTLS_FS_IO
}

static avs_error_t load_ca_from_path(mbedtls_x509_crt *chain,
                                     const char *path) {
#    ifdef MBEDTLS_FS_IO
    LOG(DEBUG, _("certificates from path <") "%s" _(">: going to load"), path);

    int retval = -1;
    // Note: this function returns negative value if nothing was loaded or
    // everything failed to load, and positive value indicating a number of
    // files that failed to load otherwise.
    avs_error_t err = ((retval = mbedtls_x509_crt_parse_path(chain, path)) < 0
                               ? avs_errno(AVS_EPROTO)
                               : AVS_OK);
    if (avs_is_ok(err)) {
        LOG(DEBUG,
            _("certificates from path <") "%s" _(
                    ">: some loaded; not loaded: ") "%d",
            path, retval);
    } else {
        LOG(ERROR,
            _("certificates from path <") "%s" _(
                    ">: failed to load, result ") "%d",
            path, retval);
    }
    return err;
#    else  // MBEDTLS_FS_IO
    (void) chain;
    (void) path;
    LOG(DEBUG,
        _("certificates from path <") "%s" _(
                ">: mbed TLS configured without file system ")
                _("support, cannot load"),
        path);
    return avs_errno(AVS_ENOTSUP);
#    endif // MBEDTLS_FS_IO
}

avs_error_t
_avs_net_mbedtls_load_ca_certs(mbedtls_x509_crt **out,
                               const avs_net_trusted_cert_info_t *info) {
    CREATE_OR_FAIL(mbedtls_x509_crt, out);
    mbedtls_x509_crt_init(*out);

    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR,
                _("attempt to load CA cert from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_cert_from_file(*out, info->desc.info.file.filename);
    case AVS_NET_DATA_SOURCE_PATH:
        if (!info->desc.info.path.path) {
            LOG(ERROR, _("attempt to load CA cert from path, but path=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_ca_from_path(*out, info->desc.info.path.path);
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load CA cert from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return append_cert_from_buffer(*out, info->desc.info.buffer.buffer,
                                       info->desc.info.buffer.buffer_size);
    default:
        AVS_UNREACHABLE("invalid data source");
        return avs_errno(AVS_EINVAL);
    }
}

avs_error_t
_avs_net_mbedtls_load_client_cert(mbedtls_x509_crt **out,
                                  const avs_net_client_cert_info_t *info) {
    CREATE_OR_FAIL(mbedtls_x509_crt, out);
    mbedtls_x509_crt_init(*out);

    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR,
                _("attempt to load client cert from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_cert_from_file(*out, info->desc.info.file.filename);
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load client cert from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return append_cert_from_buffer(*out, info->desc.info.buffer.buffer,
                                       info->desc.info.buffer.buffer_size);
    default:
        AVS_UNREACHABLE("invalid data source");
        return avs_errno(AVS_EINVAL);
    }
}

static avs_error_t load_private_key_from_buffer(mbedtls_pk_context *client_key,
                                                const void *buffer,
                                                size_t len,
                                                const char *password) {
    const unsigned char *pwd = (const unsigned char *) password;
    const size_t pwd_len = password ? strlen(password) : 0;
    return mbedtls_pk_parse_key(client_key, (const unsigned char *) buffer, len,
                                pwd, pwd_len)
                   ? avs_errno(AVS_EPROTO)
                   : AVS_OK;
}

static avs_error_t load_private_key_from_file(mbedtls_pk_context *client_key,
                                              const char *filename,
                                              const char *password) {
#    ifdef MBEDTLS_FS_IO
    LOG(DEBUG, _("private key <") "%s" _(">: going to load"), filename);

    int retval = -1;
    avs_error_t err =
            ((retval = mbedtls_pk_parse_keyfile(client_key, filename, password))
                     ? avs_errno(AVS_EPROTO)
                     : AVS_OK);
    if (avs_is_ok(err)) {
        LOG(DEBUG, _("private key <") "%s" _(">: loaded"), filename);
    } else {
        LOG(ERROR, _("private key <") "%s" _(">: failed, result ") "%d",
            filename, retval);
    }
    return err;
#    else  // MBEDTLS_FS_IO
    (void) client_key;
    (void) filename;
    (void) password;
    LOG(DEBUG,
        _("private key <") "%s" _(
                ">: mbed TLS configured without file system support, ")
                _("cannot load"),
        filename);
    return avs_errno(AVS_ENOTSUP);
#    endif // MBEDTLS_FS_IO
}

avs_error_t
_avs_net_mbedtls_load_client_key(mbedtls_pk_context **client_key,
                                 const avs_net_client_key_info_t *info) {
    CREATE_OR_FAIL(mbedtls_pk_context, client_key);
    mbedtls_pk_init(*client_key);

    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR,
                _("attempt to load client key from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_private_key_from_file(*client_key,
                                          info->desc.info.file.filename,
                                          info->desc.info.file.password);
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load client key from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_private_key_from_buffer(*client_key,
                                            info->desc.info.buffer.buffer,
                                            info->desc.info.buffer.buffer_size,
                                            info->desc.info.buffer.password);
    default:
        AVS_UNREACHABLE("invalid data source");
        return avs_errno(AVS_EINVAL);
    }
}

#endif // defined(AVS_COMMONS_WITH_AVS_NET) && defined(AVS_COMMONS_WITH_MBEDTLS)
       // && defined(AVS_COMMONS_NET_WITH_X509)
