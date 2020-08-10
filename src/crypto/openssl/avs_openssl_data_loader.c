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

#    define MODULE_NAME avs_crypto_data_loader
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static avs_error_t load_ca_certs_from_file(X509_STORE *store,
                                           const char *file) {
    assert(file);
    LOG(DEBUG, _("CA certificate <file=") "%s" _(">: going to load"), file);

    /**
     * SSL_CTX_load_verify_locations() allows PEM certificates only to be
     * loaded. Underneath it uses X509_LOOKUP_load_file with type hardcoded
     * to X509_FILETYPE_PEM, but it is also possible to use
     * X509_FILETYPE_ASN1.
     */
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL) {
        return avs_errno(AVS_ENOMEM);
    }
    if (X509_LOOKUP_load_file(lookup, file, X509_FILETYPE_PEM) == 1) {
        return AVS_OK;
    }
    if (X509_LOOKUP_load_file(lookup, file, X509_FILETYPE_ASN1) == 1) {
        return AVS_OK;
    }
    log_openssl_error();
    return avs_errno(AVS_EPROTO);
}

static avs_error_t load_ca_certs_from_path(X509_STORE *store,
                                           const char *path) {
    assert(path);
    LOG(DEBUG, _("CA certificate <path=") "%s" _(">: going to load"), path);

    if (!X509_STORE_load_locations(store, NULL, path)) {
        log_openssl_error();
        return avs_errno(AVS_EPROTO);
    }
    return AVS_OK;
}

typedef enum { ENCODING_UNKNOWN, ENCODING_PEM, ENCODING_DER } encoding_t;

static encoding_t detect_encoding(BIO *bio) {
#    define PEM_PREFIX "-----BEGIN "
    char buffer[sizeof(PEM_PREFIX) - 1];
    encoding_t result = ENCODING_UNKNOWN;
    if (BIO_read(bio, buffer, sizeof(buffer)) == sizeof(buffer)) {
        if (!memcmp(buffer, PEM_PREFIX, sizeof(buffer))) {
            result = ENCODING_PEM;
        } else {
            result = ENCODING_DER;
        }
    }
    BIO_reset(bio);
    return result;
#    undef PEM_PREFIX
}

static X509 *parse_cert_from_bio(BIO *bio) {
    assert(bio);
    switch (detect_encoding(bio)) {
    case ENCODING_PEM: {
        // Convert PEM to DER.
        return PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }
    case ENCODING_DER: {
        return d2i_X509_bio(bio, NULL);
    }
    default:
        LOG(ERROR, _("unknown certificate format"));
        return NULL;
    }
}

static avs_error_t
parse_cert(X509 **out_cert, const void *buffer, const size_t len) {
    BIO *bio = BIO_new_mem_buf((void *) (intptr_t) buffer, (int) len);
    if (!bio) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }
    *out_cert = parse_cert_from_bio(bio);
    BIO_free(bio);
    if (!*out_cert) {
        log_openssl_error();
        return avs_errno(AVS_EPROTO);
    }
    return AVS_OK;
}

static avs_error_t load_ca_cert_from_buffer(X509_STORE *store,
                                            const void *buffer,
                                            const size_t len) {
    X509 *cert = NULL;
    avs_error_t err = parse_cert(&cert, buffer, len);
    if (avs_is_err(err)) {
        return err;
    }
    assert(cert);
    if (!store || !X509_STORE_add_cert(store, cert)) {
        log_openssl_error();
        err = avs_errno(AVS_ENOMEM);
    }
    X509_free(cert);
    return err;
}

avs_error_t
_avs_crypto_openssl_load_ca_certs(X509_STORE *store,
                                  const avs_crypto_trusted_cert_info_t *info) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR,
                _("attempt to load CA cert from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_ca_certs_from_file(store, info->desc.info.file.filename);
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        if (!info->desc.info.path.path) {
            LOG(ERROR, _("attempt to load CA cert from path, but path=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_ca_certs_from_path(store, info->desc.info.path.path);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load CA cert from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_ca_cert_from_buffer(store, info->desc.info.buffer.buffer,
                                        info->desc.info.buffer.buffer_size);
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < info->desc.info.array.element_count;
             ++i) {
            err = _avs_crypto_openssl_load_ca_certs(
                    store, AVS_CONTAINER_OF(
                                   &info->desc.info.array.array_ptr[i],
                                   const avs_crypto_trusted_cert_info_t, desc));
        }
        return err;
    }
#    ifdef AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_LIST: {
        AVS_LIST(avs_crypto_security_info_union_t) entry;
        AVS_LIST_FOREACH(entry, info->desc.info.list.list_head) {
            avs_error_t err = _avs_crypto_openssl_load_ca_certs(
                    store,
                    AVS_CONTAINER_OF(
                            entry, const avs_crypto_trusted_cert_info_t, desc));
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

static avs_error_t load_client_cert_from_file(X509 **out_cert,
                                              const char *filename) {
    LOG(DEBUG, _("client certificate <") "%s" _(">: going to load"), filename);
    BIO *bio = BIO_new_file(filename, "rb");
    if (!bio) {
        log_openssl_error();
        return avs_errno(AVS_EIO);
    }
    *out_cert = parse_cert_from_bio(bio);
    BIO_free(bio);
    if (!*out_cert) {
        log_openssl_error();
        return avs_errno(AVS_EPROTO);
    }
    return AVS_OK;
}

avs_error_t _avs_crypto_openssl_load_client_cert(
        X509 **out_cert, const avs_crypto_client_cert_info_t *info) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR,
                _("attempt to load client cert from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_client_cert_from_file(out_cert,
                                          info->desc.info.file.filename);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load client cert from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return parse_cert(out_cert, info->desc.info.buffer.buffer,
                          info->desc.info.buffer.buffer_size);
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
    switch (detect_encoding(bio)) {
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
                                    const avs_crypto_client_key_info_t *info) {
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

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_OPENSSL) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
