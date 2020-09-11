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

// NOTE: OpenSSL headers sometimes (depending on a version) contain some of the
// symbols poisoned via inclusion of avs_commons_init.h. Therefore they must
// be included before poison.
#define AVS_SUPPRESS_POISONING
#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO) && defined(AVS_COMMONS_WITH_OPENSSL) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)

#    include <openssl/ssl.h>

#    include <avs_commons_poison.h>

#    include "avs_openssl_common.h"
#    include "avs_openssl_data_loader.h"

#    include <assert.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_utils.h>

#    ifdef AVS_COMMONS_STREAM_WITH_FILE
#        include <avsystem/commons/avs_stream_file.h>
#        include <avsystem/commons/avs_stream_membuf.h>
#    endif // AVS_COMMONS_STREAM_WITH_FILE

#    define MODULE_NAME avs_crypto_data_loader
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static avs_error_t load_crl_from_file(X509_STORE *store, const char *file) {
    assert(file);
    LOG(DEBUG, _("CRL <file=") "%s" _(">: going to load"), file);

    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL) {
        return avs_errno(AVS_ENOMEM);
    }
    if (X509_load_crl_file(lookup, file, X509_FILETYPE_PEM) > 0) {
        return AVS_OK;
    }
    if (X509_load_crl_file(lookup, file, X509_FILETYPE_ASN1) > 0) {
        return AVS_OK;
    }
    log_openssl_error();
    return avs_errno(AVS_EPROTO);
}

typedef enum { ENCODING_UNKNOWN, ENCODING_PEM, ENCODING_DER } encoding_t;

#    define PEM_PREFIX "-----BEGIN "

static encoding_t detect_encoding(const void *buffer, int len) {
    assert(len >= 0);
    assert(buffer || !len);
    if (!memcmp(buffer, PEM_PREFIX, (size_t) len)) {
        return ENCODING_PEM;
    } else {
        return ENCODING_DER;
    }
}

static encoding_t detect_encoding_in_bio(BIO *bio) {
    char buffer[sizeof(PEM_PREFIX) - 1];
    encoding_t result = ENCODING_UNKNOWN;
    if (BIO_read(bio, buffer, sizeof(buffer)) == sizeof(buffer)) {
        result = detect_encoding(buffer, sizeof(buffer));
    }
    BIO_reset(bio);
    return result;
}

#    undef PEM_PREFIX

static avs_error_t
load_crl_from_buffer(X509_STORE *store, const void *buffer, const size_t len) {
    BIO *bio = BIO_new_mem_buf((void *) (intptr_t) buffer, (int) len);
    if (!bio) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }

    X509_CRL *crl = NULL;
    switch (detect_encoding_in_bio(bio)) {
    case ENCODING_PEM:
        // Convert PEM to DER.
        crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
        break;
    case ENCODING_DER:
        crl = d2i_X509_CRL_bio(bio, NULL);
        break;
    default:
        LOG(ERROR, _("unknown CRL format"));
    }

    BIO_free(bio);
    if (!crl) {
        log_openssl_error();
        return avs_errno(AVS_EPROTO);
    }
    avs_error_t err = AVS_OK;
    if (!store || !X509_STORE_add_crl(store, crl)) {
        log_openssl_error();
        err = avs_errno(AVS_ENOMEM);
    }
    X509_CRL_free(crl);
    return err;
}

avs_error_t _avs_crypto_openssl_load_crls(
        X509_STORE *store, const avs_crypto_cert_revocation_list_info_t *info) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR, _("attempt to load CRL from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_crl_from_file(store, info->desc.info.file.filename);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR, _("attempt to load CRL from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_crl_from_buffer(store, info->desc.info.buffer.buffer,
                                    info->desc.info.buffer.buffer_size);
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < info->desc.info.array.element_count;
             ++i) {
            err = _avs_crypto_openssl_load_crls(
                    store, AVS_CONTAINER_OF(
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
            avs_error_t err = _avs_crypto_openssl_load_crls(
                    store,
                    AVS_CONTAINER_OF(
                            entry, const avs_crypto_cert_revocation_list_info_t,
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

static int password_cb(char *buf, int num, int rwflag, void *userdata) {
    if (!userdata) {
        buf[0] = '\0';
        return 0;
    }
    int retval = snprintf(buf, (size_t) num, "%s", (const char *) userdata);
    (void) rwflag;
    return (retval < 0 || retval >= num) ? -1 : retval;
}

static avs_error_t
parse_key(EVP_PKEY **out_key, BIO *bio, const char *password) {
    *out_key = NULL;
    switch (detect_encoding_in_bio(bio)) {
    case ENCODING_PEM: {
        *out_key = PEM_read_bio_PrivateKey(bio, NULL, password_cb,
                                           (void *) (intptr_t) password);
        break;
    }
    case ENCODING_DER: {
        *out_key = d2i_PrivateKey_bio(bio, NULL);
        break;
    }
    default:
        LOG(ERROR, _("unknown key format"));
        break;
    }
    return *out_key ? AVS_OK : avs_errno(AVS_EPROTO);
}

avs_error_t
_avs_crypto_openssl_load_client_key(EVP_PKEY **out_key,
                                    const avs_crypto_private_key_info_t *info) {
    assert(out_key && !*out_key);
    BIO *bio = NULL;
    avs_error_t err = AVS_OK;
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_FILE: {
        if (!info->desc.info.file.filename) {
            LOG(ERROR,
                _("attempt to load client key from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        LOG(DEBUG, _("client key <") "%s" _(">: going to load"),
            info->desc.info.file.filename);
        if (!(bio = BIO_new_file(info->desc.info.file.filename, "rb"))) {
            err = avs_errno(AVS_EIO);
        }
        break;
    }
    case AVS_CRYPTO_DATA_SOURCE_BUFFER: {
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load client key from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        if (!(bio = BIO_new_mem_buf(
                      (void *) (intptr_t) info->desc.info.buffer.buffer,
                      (int) info->desc.info.buffer.buffer_size))) {
            err = avs_errno(AVS_ENOMEM);
        }
        break;
    }
    default:
        AVS_UNREACHABLE("invalid data source");
        err = avs_errno(AVS_EINVAL);
    }
    if (avs_is_ok(err)) {
        AVS_STATIC_ASSERT(
                offsetof(avs_crypto_security_info_union_internal_file_t,
                         password)
                        == offsetof(
                                   avs_crypto_security_info_union_internal_buffer_t,
                                   password),
                password_offset_consistent);
        assert(bio);
        err = parse_key(out_key, bio, info->desc.info.file.password);
        BIO_free(bio);
    }
    assert(!!*out_key == avs_is_ok(err));
    return err;
}

static avs_error_t
load_file_into_buffer(void **out_buf, int *out_buf_size, const char *filename) {
#    ifdef AVS_COMMONS_STREAM_WITH_FILE
    avs_stream_t *membuf = avs_stream_membuf_create();
    if (!membuf) {
        LOG(ERROR, _("Out of memory"));
        return avs_errno(AVS_ENOMEM);
    }

    avs_error_t err = AVS_OK;
    avs_stream_t *file_stream =
            avs_stream_file_create(filename, AVS_STREAM_FILE_READ);
    if (!file_stream) {
        LOG(ERROR, _("Cannot open file: ") "%s", filename);
        err = avs_errno(AVS_EIO);
    }

    void *buf = NULL;
    size_t buf_size;
    (void) (avs_is_err(err)
            || avs_is_err((err = avs_stream_copy(membuf, file_stream)))
            || avs_is_err((err = avs_stream_membuf_take_ownership(membuf, &buf,
                                                                  &buf_size))));
    avs_stream_cleanup(&file_stream);
    avs_stream_cleanup(&membuf);
    if (avs_is_ok(err)) {
        *out_buf_size = (int) buf_size;
        if (*out_buf_size < 0 || (size_t) *out_buf_size != buf_size) {
            avs_free(buf);
            LOG(ERROR, _("Buffer too big"));
            return avs_errno(AVS_E2BIG);
        }
        *out_buf = buf;
    }
    return err;
#    else  // AVS_COMMONS_STREAM_WITH_FILE
    (void) out_buf;
    (void) out_buf_size;
    (void) filename;
    LOG(ERROR,
        _("Not opening file <") "%s" _(
                "> because file stream support is disabled"),
        filename);
    return avs_errno(AVS_ENOTSUP);
#    endif // AVS_COMMONS_STREAM_WITH_FILE
}

static avs_error_t
load_certs_from_buffer(const void *buffer,
                       int len,
                       avs_crypto_openssl_load_certs_cb_t *cb,
                       void *cb_arg) {
    assert(buffer || !len);
    assert(cb);
    switch (detect_encoding(buffer, len)) {
    case ENCODING_PEM: {
        BIO *bio = BIO_new_mem_buf((void *) (intptr_t) buffer, len);
        if (!bio) {
            log_openssl_error();
            return avs_errno(AVS_ENOMEM);
        }
        avs_error_t err = AVS_OK;
        X509 *cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
        if (!cert) {
            log_openssl_error();
            err = avs_errno(AVS_EPROTO);
        } else {
            err = cb(cb_arg, cert);
            X509_free(cert);
        }
        while (avs_is_ok(err)) {
            if (!(cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL))) {
                if (ERR_GET_REASON(ERR_peek_last_error())
                        == PEM_R_NO_START_LINE) {
                    ERR_clear_error();
                    break;
                } else {
                    log_openssl_error();
                    err = avs_errno(AVS_EPROTO);
                }
            } else {
                err = cb(cb_arg, cert);
                X509_free(cert);
            }
        }
        return err;
    }
    case ENCODING_DER: {
        const unsigned char *ptr = (const unsigned char *) buffer;
        X509 *cert = d2i_X509_AUX(NULL, &ptr, len);
        if (!cert) {
            log_openssl_error();
            return avs_errno(AVS_EPROTO);
        }
        avs_error_t err;
        if (ptr - (const unsigned char *) buffer != len) {
            LOG(ERROR, _("Garbage data after DER-encoded certificate"));
            err = avs_errno(AVS_EPROTO);
        } else {
            err = cb(cb_arg, cert);
        }
        X509_free(cert);
        return err;
    }
    default:
        LOG(ERROR, _("unknown certificate format"));
        return avs_errno(AVS_EIO);
    }
}

static avs_error_t load_certs_from_file(const char *filename,
                                        avs_crypto_openssl_load_certs_cb_t *cb,
                                        void *cb_arg) {
    assert(filename);
    LOG(DEBUG, _("certificate <file=") "%s" _(">: going to load"), filename);
    void *buffer = NULL;
    int buffer_size = 0;
    avs_error_t err;
    (void) (avs_is_err((err = load_file_into_buffer(&buffer, &buffer_size,
                                                    filename)))
            || avs_is_err((err = load_certs_from_buffer(buffer, buffer_size, cb,
                                                        cb_arg))));
    avs_free(buffer);
    return err;
}

avs_error_t _avs_crypto_openssl_load_client_certs(
        const avs_crypto_certificate_chain_info_t *info,
        avs_crypto_openssl_load_certs_cb_t *cb,
        void *cb_arg) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR, _("attempt to load certificate chain from file, but "
                         "filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_certs_from_file(info->desc.info.file.filename, cb, cb_arg);
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        LOG(ERROR, _("Certificate path sources cannot be used as client "
                     "certificate chains"));
        return avs_errno(AVS_ENOTSUP);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER: {
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR, _("attempt to load certificate chain from buffer, but "
                         "buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        int buffer_size = (int) info->desc.info.buffer.buffer_size;
        if (buffer_size < 0
                || (size_t) buffer_size != info->desc.info.buffer.buffer_size) {
            LOG(ERROR, _("Buffer too big"));
            return avs_errno(AVS_E2BIG);
        }
        return load_certs_from_buffer(info->desc.info.buffer.buffer,
                                      buffer_size, cb, cb_arg);
    }
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < info->desc.info.array.element_count;
             ++i) {
            err = _avs_crypto_openssl_load_client_certs(
                    AVS_CONTAINER_OF(&info->desc.info.array.array_ptr[i],
                                     const avs_crypto_certificate_chain_info_t,
                                     desc),
                    cb, cb_arg);
        }
        return err;
    }
#    ifdef AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_LIST: {
        AVS_LIST(avs_crypto_security_info_union_t) entry;
        AVS_LIST_FOREACH(entry, info->desc.info.list.list_head) {
            avs_error_t err = _avs_crypto_openssl_load_client_certs(
                    AVS_CONTAINER_OF(entry,
                                     const avs_crypto_certificate_chain_info_t,
                                     desc),
                    cb, cb_arg);
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

static avs_error_t load_into_store(void *store_, X509 *cert) {
    X509_STORE *store = (X509_STORE *) store_;
    if (!X509_STORE_add_cert(store, cert)) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }
    return AVS_OK;
}

avs_error_t _avs_crypto_openssl_load_ca_certs(
        X509_STORE *store, const avs_crypto_certificate_chain_info_t *info) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        if (!info->desc.info.path.path) {
            LOG(ERROR, _("attempt to load certificate chain from path, but "
                         "path=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        LOG(DEBUG, _("certificate <path=") "%s" _(">: going to load"),
            info->desc.info.path.path);
        if (!X509_STORE_load_locations(store, NULL,
                                       info->desc.info.path.path)) {
            log_openssl_error();
            return avs_errno(AVS_EPROTO);
        }
        return AVS_OK;
#    warning "TODO: deduplicate compound handling"
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < info->desc.info.array.element_count;
             ++i) {
            err = _avs_crypto_openssl_load_ca_certs(
                    store,
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
            avs_error_t err = _avs_crypto_openssl_load_ca_certs(
                    store,
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
        return _avs_crypto_openssl_load_client_certs(info, load_into_store,
                                                     store);
    }
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_OPENSSL) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
