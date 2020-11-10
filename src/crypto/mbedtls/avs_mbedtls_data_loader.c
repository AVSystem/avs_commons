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

#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) && defined(AVS_COMMONS_WITH_MBEDTLS) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)

// this uses some symbols such as "printf" - include it before poisoning them
#    include <mbedtls/platform.h>

#    include <avs_commons_poison.h>

#    include "avs_mbedtls_data_loader.h"

#    include <assert.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_utils.h>

#    define MODULE_NAME avs_crypto_data_loader
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static avs_error_t append_cert_from_buffer(mbedtls_x509_crt *chain,
                                           const void *buffer,
                                           size_t len) {
    return mbedtls_x509_crt_parse(chain, (const unsigned char *) buffer, len)
                   ? avs_errno(AVS_EPROTO)
                   : AVS_OK;
}

static avs_error_t append_cert_from_file(mbedtls_x509_crt *chain,
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

#    ifdef MBEDTLS_X509_CRL_PARSE_C
static avs_error_t
append_crl_from_buffer(mbedtls_x509_crl *crl, const void *buffer, size_t len) {
    return mbedtls_x509_crl_parse(crl, (const unsigned char *) buffer, len)
                   ? avs_errno(AVS_EPROTO)
                   : AVS_OK;
}

static avs_error_t append_crl_from_file(mbedtls_x509_crl *crl,
                                        const char *name) {
#        ifdef MBEDTLS_FS_IO
    LOG(DEBUG, _("CRL <") "%s" _(">: going to load"), name);

    int retval = -1;
    avs_error_t err = ((retval = mbedtls_x509_crl_parse_file(crl, name))
                               ? avs_errno(AVS_EPROTO)
                               : AVS_OK);
    if (avs_is_ok(err)) {
        LOG(DEBUG, _("CRL <") "%s" _(">: loaded"), name);
    } else {
        LOG(ERROR, _("CRL <") "%s" _(">: failed to load, result ") "%d", name,
            retval);
    }
    return err;
#        else  // MBEDTLS_FS_IO
    (void) crl;
    (void) name;
    LOG(DEBUG,
        _("CRL <") "%s" _(">: mbed TLS configured without file system support, "
                          "cannot load"),
        name);
    return avs_errno(AVS_ENOTSUP);
#        endif // MBEDTLS_FS_IO
}
#    endif // MBEDTLS_X509_CRL_PARSE_C

static avs_error_t append_ca_from_path(mbedtls_x509_crt *chain,
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

static avs_error_t
append_certs(mbedtls_x509_crt *out,
             const avs_crypto_certificate_chain_info_t *info) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_ENGINE:
        LOG(ERROR, "PKSC11 with mbedtls not supported");
        return avs_errno(AVS_ENOTSUP);
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR, _("attempt to load certificate chain from file, but "
                         "filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return append_cert_from_file(out, info->desc.info.file.filename);
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        if (!info->desc.info.path.path) {
            LOG(ERROR, _("attempt to load certificate chain from path, but "
                         "path=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return append_ca_from_path(out, info->desc.info.path.path);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load certificate chain from buffer, but "
                  "buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return append_cert_from_buffer(out, info->desc.info.buffer.buffer,
                                       info->desc.info.buffer.buffer_size);
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < info->desc.info.array.element_count;
             ++i) {
            err = append_certs(
                    out,
                    AVS_CONTAINER_OF(&info->desc.info.array.array_ptr[i],
                                     const avs_crypto_certificate_chain_info_t,
                                     desc));
        }
        return err;
    }
#    ifdef AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_LIST: {
        AVS_LIST(avs_crypto_security_info_union_t) entry;
        AVS_LIST_FOREACH(entry, info->desc.info.list.list_head) {
            avs_error_t err = append_certs(
                    out,
                    AVS_CONTAINER_OF(entry,
                                     const avs_crypto_certificate_chain_info_t,
                                     desc));
            if (avs_is_err(err)) {
                return err;
            }
        }
        return AVS_OK;
    }
#    endif // AVS_COMMONS_WITH_AVS_LIST
    default:
        AVS_UNREACHABLE("invalid data source");
        return avs_errno(AVS_EINVAL);
    }
}

void _avs_crypto_mbedtls_x509_crt_cleanup(mbedtls_x509_crt **crt) {
    if (crt && *crt) {
        mbedtls_x509_crt_free(*crt);
        mbedtls_free(*crt);
        *crt = NULL;
    }
}

avs_error_t _avs_crypto_mbedtls_load_certs(
        mbedtls_x509_crt **out,
        const avs_crypto_certificate_chain_info_t *info) {
    if (info == NULL) {
        LOG(ERROR, "Given cert info is empty.");
        return avs_errno(AVS_EINVAL);
    }

    assert(!*out);
    *out = (mbedtls_x509_crt *) mbedtls_calloc(1, sizeof(**out));
    if (!*out) {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }
    mbedtls_x509_crt_init(*out);
    avs_error_t err = append_certs(*out, info);
    if (avs_is_err(err)) {
        _avs_crypto_mbedtls_x509_crt_cleanup(out);
    }
    return err;
}

static avs_error_t
append_crls(mbedtls_x509_crl *out,
            const avs_crypto_cert_revocation_list_info_t *info) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_ENGINE:
        LOG(ERROR, "PKSC11 with mbedtls not supported");
        return avs_errno(AVS_ENOTSUP);
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
#    ifdef MBEDTLS_X509_CRL_PARSE_C
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        assert(out);
        if (!info->desc.info.file.filename) {
            LOG(ERROR, _("attempt to load CRL from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return append_crl_from_file(out, info->desc.info.file.filename);
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        LOG(ERROR, _("CRL cannot be loaded from path"));
        return avs_errno(AVS_EINVAL);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        assert(out);
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR, _("attempt to load CRL from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return append_crl_from_buffer(out, info->desc.info.buffer.buffer,
                                      info->desc.info.buffer.buffer_size);
#    else  // MBEDTLS_X509_CRL_PARSE_C
    case AVS_CRYPTO_DATA_SOURCE_FILE:
    case AVS_CRYPTO_DATA_SOURCE_PATH:
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        LOG(DEBUG, _("Mbed TLS compiled without CRL support"));
        return avs_errno(AVS_ENOTSUP);
#    endif // MBEDTLS_X509_CRL_PARSE_C
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < info->desc.info.array.element_count;
             ++i) {
            err = append_crls(
                    out, AVS_CONTAINER_OF(
                                 &info->desc.info.array.array_ptr[i],
                                 const avs_crypto_cert_revocation_list_info_t,
                                 desc));
        }
        return err;
    }
#    ifdef AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_LIST: {
        AVS_LIST(avs_crypto_security_info_union_t) entry;
        AVS_LIST_FOREACH(entry, info->desc.info.list.list_head) {
            avs_error_t err = append_crls(
                    out, AVS_CONTAINER_OF(
                                 entry,
                                 const avs_crypto_cert_revocation_list_info_t,
                                 desc));
            if (avs_is_err(err)) {
                return err;
            }
        }
        return AVS_OK;
    }
#    endif // AVS_COMMONS_WITH_AVS_LIST
    default:
        AVS_UNREACHABLE("invalid data source");
        return avs_errno(AVS_EINVAL);
    }
}

void _avs_crypto_mbedtls_x509_crl_cleanup(mbedtls_x509_crl **crl) {
    if (crl && *crl) {
#    ifdef MBEDTLS_X509_CRL_PARSE_C
        mbedtls_x509_crl_free(*crl);
        mbedtls_free(*crl);
        *crl = NULL;
#    else  // MBEDTLS_X509_CRL_PARSE_C
        AVS_UNREACHABLE("Mbed TLS compiled without CRL support");
#    endif // MBEDTLS_X509_CRL_PARSE_C
    }
}

avs_error_t _avs_crypto_mbedtls_load_crls(
        mbedtls_x509_crl **out,
        const avs_crypto_cert_revocation_list_info_t *info) {
    if (info == NULL) {
        LOG(ERROR, "Given CRL info is empty.");
        return avs_errno(AVS_EINVAL);
    }

    assert(!*out);
#    ifdef MBEDTLS_X509_CRL_PARSE_C
    *out = (mbedtls_x509_crl *) mbedtls_calloc(1, sizeof(**out));
    if (!*out) {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }
    mbedtls_x509_crl_init(*out);
#    endif // MBEDTLS_X509_CRL_PARSE_C
    avs_error_t err = append_crls(*out, info);
    if (avs_is_err(err)) {
        _avs_crypto_mbedtls_x509_crl_cleanup(out);
    }
    return err;
}

static avs_error_t load_private_key_from_buffer(mbedtls_pk_context *client_key,
                                                const void *buffer,
                                                size_t len,
                                                const char *password) {
    unsigned char *refined_buffer = (unsigned char *) (intptr_t) buffer;
    if (refined_buffer[len - 1] != '\0'
            && _avs_crypto_detect_cert_encoding(buffer, len) == ENCODING_PEM) {
        refined_buffer = (unsigned char *) avs_malloc(len + 1);
        memcpy(refined_buffer, buffer, len);
        refined_buffer[len] = '\0';
        len++;
    }

    const unsigned char *pwd = (const unsigned char *) password;
    const size_t pwd_len = password ? strlen(password) : 0;
    avs_error_t err =
            mbedtls_pk_parse_key(client_key, refined_buffer, len, pwd, pwd_len)
                    ? avs_errno(AVS_EPROTO)
                    : AVS_OK;
    if (refined_buffer != buffer) {
        avs_free(refined_buffer);
    }
    return err;
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

void _avs_crypto_mbedtls_pk_context_cleanup(mbedtls_pk_context **ctx) {
    if (ctx && *ctx) {
        mbedtls_pk_free(*ctx);
        avs_free(*ctx);
        *ctx = NULL;
    }
}

avs_error_t _avs_crypto_mbedtls_load_private_key(
        mbedtls_pk_context **client_key,
        const avs_crypto_private_key_info_t *info) {
    if (info == NULL) {
        LOG(ERROR, "Given key info is empty.");
        return avs_errno(AVS_EINVAL);
    }

    assert(!*client_key);
    *client_key = (mbedtls_pk_context *) avs_calloc(1, sizeof(**client_key));
    if (!*client_key) {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }
    mbedtls_pk_init(*client_key);

    avs_error_t err = avs_errno(AVS_EINVAL);
    switch (info->desc.source) {
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_ENGINE:
        LOG(ERROR, "PKSC11 with mbedtls not supported");
        return avs_errno(AVS_ENOTSUP);
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR,
                _("attempt to load client key from file, but filename=NULL"));
        } else {
            err = load_private_key_from_file(*client_key,
                                             info->desc.info.file.filename,
                                             info->desc.info.file.password);
        }
        break;
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        LOG(ERROR, _("client key cannot be loaded from path"));
        break;
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load client key from buffer, but buffer=NULL"));
        } else {
            err = load_private_key_from_buffer(
                    *client_key, info->desc.info.buffer.buffer,
                    info->desc.info.buffer.buffer_size,
                    info->desc.info.buffer.password);
        }
        break;
    default:
        AVS_UNREACHABLE("invalid data source");
    }

    if (avs_is_err(err)) {
        _avs_crypto_mbedtls_pk_context_cleanup(client_key);
    }
    return err;
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
