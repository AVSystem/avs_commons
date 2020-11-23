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
#    include "avs_openssl_engine.h"

#    include "../avs_crypto_global.h"

#    include <assert.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_errno.h>
#    include <avsystem/commons/avs_utils.h>

#    ifdef AVS_COMMONS_STREAM_WITH_FILE
#        include <avsystem/commons/avs_stream_file.h>
#        include <avsystem/commons/avs_stream_membuf.h>
#    endif // AVS_COMMONS_STREAM_WITH_FILE

#    define MODULE_NAME avs_crypto_data_loader
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

static int password_cb(char *buf, int num, int rwflag, void *userdata) {
    (void) rwflag;
    if (!userdata) {
        buf[0] = '\0';
        return 0;
    }
    return avs_simple_snprintf(buf, (size_t) num, "%s",
                               (const char *) userdata);
}

typedef enum {
    AVS_OSSL_OBJECT_X509_CRL,
    AVS_OSSL_OBJECT_EVP_PKEY,
    AVS_OSSL_OBJECT_X509
} avs_ossl_object_type_t;

static void *avs_ossl_object_pem_read(BIO *bio,
                                      const char *password,
                                      avs_ossl_object_type_t type) {
    switch (type) {
    case AVS_OSSL_OBJECT_X509_CRL:
        return PEM_read_bio_X509_CRL(bio, NULL, password_cb,
                                     (void *) (intptr_t) password);
    case AVS_OSSL_OBJECT_EVP_PKEY:
        return PEM_read_bio_PrivateKey(bio, NULL, password_cb,
                                       (void *) (intptr_t) password);
    case AVS_OSSL_OBJECT_X509:
        return PEM_read_bio_X509(bio, NULL, password_cb,
                                 (void *) (intptr_t) password);
    default:
        AVS_UNREACHABLE("Invalid object type");
        return NULL;
    }
}

static void *avs_ossl_object_der_read(const unsigned char **in,
                                      int len,
                                      avs_ossl_object_type_t type) {
    switch (type) {
    case AVS_OSSL_OBJECT_X509_CRL:
        return d2i_X509_CRL(NULL, in, len);
    case AVS_OSSL_OBJECT_EVP_PKEY:
        return d2i_AutoPrivateKey(NULL, in, len);
    case AVS_OSSL_OBJECT_X509:
        return d2i_X509(NULL, in, len);
    default:
        AVS_UNREACHABLE("Invalid object type");
        return NULL;
    }
}

static void avs_ossl_object_free(void *obj, avs_ossl_object_type_t type) {
    switch (type) {
    case AVS_OSSL_OBJECT_X509_CRL:
        X509_CRL_free((X509_CRL *) obj);
        break;
    case AVS_OSSL_OBJECT_EVP_PKEY:
        EVP_PKEY_free((EVP_PKEY *) obj);
        break;
    case AVS_OSSL_OBJECT_X509:
        X509_free((X509 *) obj);
        break;
    default:
        AVS_UNREACHABLE("Invalid object type");
    }
}

static avs_error_t load_pem_objects(const void *buffer,
                                    size_t len,
                                    const char *password,
                                    avs_ossl_object_type_t type,
                                    avs_crypto_ossl_object_load_t *load_cb,
                                    void *load_cb_arg) {
    BIO *bio = BIO_new_mem_buf((void *) (intptr_t) buffer, (int) len);
    if (!bio) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }

    avs_error_t err;
    void *obj = avs_ossl_object_pem_read(bio, password, type);
    if (!obj) {
        log_openssl_error();
        err = avs_errno(AVS_EPROTO);
    } else {
        err = load_cb(obj, load_cb_arg);
        avs_ossl_object_free(obj, type);
    }
    while (avs_is_ok(err)) {
        if (!(obj = avs_ossl_object_pem_read(bio, password, type))) {
            if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) {
                ERR_clear_error();
                break;
            } else {
                log_openssl_error();
                err = avs_errno(AVS_EPROTO);
            }
        } else {
            err = load_cb(obj, load_cb_arg);
            avs_ossl_object_free(obj, type);
        }
    }
    BIO_free(bio);
    return err;
}

static avs_error_t load_der_object(const void *buffer,
                                   size_t len,
                                   avs_ossl_object_type_t type,
                                   avs_crypto_ossl_object_load_t *load_cb,
                                   void *load_cb_arg) {
    const unsigned char *ptr = (const unsigned char *) buffer;
    if (len > INT_MAX) {
        LOG(ERROR, _("Buffer too big"));
        return avs_errno(AVS_E2BIG);
    }
    int len_as_int = (int) len;

    void *obj = avs_ossl_object_der_read(&ptr, len_as_int, type);
    if (!obj) {
        log_openssl_error();
        return avs_errno(AVS_EPROTO);
    }

    avs_error_t err = AVS_OK;
    if (ptr - (const unsigned char *) buffer != len_as_int) {
        LOG(ERROR, _("Garbage data after DER-encoded data"));
        err = avs_errno(AVS_EIO);
    } else {
        err = load_cb(obj, load_cb_arg);
    }
    avs_ossl_object_free(obj, type);
    return err;
}

static avs_error_t
load_pem_or_der_objects(const void *buffer,
                        size_t len,
                        const char *password,
                        avs_ossl_object_type_t type,
                        avs_crypto_ossl_object_load_t *load_cb,
                        void *load_cb_arg) {
    assert(buffer || !len);
    switch (_avs_crypto_detect_cert_encoding(buffer, len)) {
    case ENCODING_PEM:
        return load_pem_objects(buffer, len, password, type, load_cb,
                                load_cb_arg);
    case ENCODING_DER:
        return load_der_object(buffer, len, type, load_cb, load_cb_arg);
    default:
        AVS_UNREACHABLE("invalid encoding");
        return avs_errno(AVS_EIO);
    }
}

static avs_error_t load_crl_cb(void *crl, void *store) {
    if (!store || !X509_STORE_add_crl((X509_STORE *) store, (X509_CRL *) crl)) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }
    return AVS_OK;
}

static avs_error_t
load_crls_from_buffer(X509_STORE *store, const void *buffer, size_t len) {
    return load_pem_or_der_objects(buffer, len, NULL, AVS_OSSL_OBJECT_X509_CRL,
                                   load_crl_cb, store);
}

static avs_error_t load_crl_from_file(X509_STORE *store, const char *file) {
    assert(file);
    LOG(DEBUG, _("CRL <file=") "%s" _(">: going to load"), file);

    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL) {
        return avs_errno(AVS_ENOMEM);
    }
    if (X509_load_crl_file(lookup, file, X509_FILETYPE_PEM) > 0
            || X509_load_crl_file(lookup, file, X509_FILETYPE_ASN1) > 0) {
        return AVS_OK;
    }
    log_openssl_error();
    return avs_errno(AVS_EPROTO);
}

avs_error_t _avs_crypto_openssl_load_crls(
        X509_STORE *store, const avs_crypto_cert_revocation_list_info_t *info) {
    if (info == NULL) {
        LOG(ERROR, "Given CRL info is empty.");
        return avs_errno(AVS_EINVAL);
    }

    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_ENGINE:
        if (!info->desc.info.engine.query) {
            LOG(ERROR, _("attempt to load CRL from engine, but query=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return _avs_crypto_openssl_engine_load_crls(
                store, info->desc.info.engine.query);
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR, _("attempt to load CRL from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_crl_from_file(store, info->desc.info.file.filename);
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        LOG(ERROR, _("CRL cannot be loaded from path"));
        return avs_errno(AVS_EINVAL);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR, _("attempt to load CRL from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_crls_from_buffer(store, info->desc.info.buffer.buffer,
                                     info->desc.info.buffer.buffer_size);
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < info->desc.info.array.element_count;
             ++i) {
            err = _avs_crypto_openssl_load_crls(
                    store,
                    AVS_CONTAINER_OF(
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

static avs_error_t load_file_into_buffer(void **out_buf,
                                         size_t *out_buf_size,
                                         const char *filename) {
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

    (void) (avs_is_err(err)
            || avs_is_err((err = avs_stream_copy(membuf, file_stream)))
            || avs_is_err((err = avs_stream_membuf_take_ownership(
                                   membuf, out_buf, out_buf_size))));
    avs_stream_cleanup(&file_stream);
    avs_stream_cleanup(&membuf);
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

static avs_error_t load_key_cb(void *key_, void *out_key_ptr) {
    EVP_PKEY **out_key = (EVP_PKEY **) out_key_ptr;
    if (*out_key) {
        LOG(ERROR, "More than one private key specified");
        EVP_PKEY_free(*out_key);
        *out_key = NULL;
        return avs_errno(AVS_EIO);
    }
    EVP_PKEY *key = (EVP_PKEY *) key_;
    if (!EVP_PKEY_up_ref(key)) {
        log_openssl_error();
        return avs_errno(AVS_ENOMEM);
    }
    *out_key = key;
    return AVS_OK;
}

static avs_error_t load_key_from_buffer(EVP_PKEY **out_key,
                                        const void *buffer,
                                        size_t len,
                                        const char *password) {
    *out_key = NULL;
    avs_error_t err = load_pem_or_der_objects(buffer, len, password,
                                              AVS_OSSL_OBJECT_EVP_PKEY,
                                              load_key_cb, out_key);
    assert(avs_is_err(err) == !*out_key);
    return err;
}

static avs_error_t load_certs_from_file(const char *filename,
                                        avs_crypto_ossl_object_load_t *load_cb,
                                        void *cb_arg) {
    assert(filename);
    LOG(DEBUG, _("certificate <file=") "%s" _(">: going to load"), filename);
    void *buffer = NULL;
    size_t buffer_size = 0;
    avs_error_t err;
    (void) (avs_is_err((err = load_file_into_buffer(&buffer, &buffer_size,
                                                    filename)))
            || avs_is_err((err = load_pem_or_der_objects(
                                   buffer, buffer_size, NULL,
                                   AVS_OSSL_OBJECT_X509, load_cb, cb_arg))));
    avs_free(buffer);
    return err;
}

static avs_error_t load_key_from_file(EVP_PKEY **out_key,
                                      const char *filename,
                                      const char *password) {
    assert(filename);
    LOG(DEBUG, _("client key <") "%s" _(">: going to load"), filename);
    void *buffer = NULL;
    size_t buffer_size = 0;
    avs_error_t err;
    (void) (avs_is_err((err = load_file_into_buffer(&buffer, &buffer_size,
                                                    filename)))
            || avs_is_err((err = load_key_from_buffer(out_key, buffer,
                                                      buffer_size, password))));
    avs_free(buffer);
    return err;
}

avs_error_t _avs_crypto_openssl_load_private_key(
        EVP_PKEY **out_key, const avs_crypto_private_key_info_t *info) {
    if (info == NULL) {
        LOG(ERROR, "Given key info is empty.");
        return avs_errno(AVS_EINVAL);
    }

    assert(out_key && !*out_key);
    switch (info->desc.source) {
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_ENGINE:
        if (!info->desc.info.engine.query) {
            LOG(ERROR,
                _("attempt to load private key from engine, but query=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        *out_key = _avs_crypto_openssl_engine_load_private_key(
                info->desc.info.engine.query);
        return AVS_OK;
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_FILE: {
        if (!info->desc.info.file.filename) {
            LOG(ERROR,
                _("attempt to load private key from file, but filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_key_from_file(out_key, info->desc.info.file.filename,
                                  info->desc.info.file.password);
    }
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        LOG(ERROR, _("private key cannot be loaded from path"));
        return avs_errno(AVS_EINVAL);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER: {
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load private key from buffer, but buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_key_from_buffer(out_key, info->desc.info.buffer.buffer,
                                    info->desc.info.buffer.buffer_size,
                                    info->desc.info.buffer.password);
    }
    default:
        AVS_UNREACHABLE("invalid data source");
        return avs_errno(AVS_EINVAL);
    }
}

typedef avs_error_t
load_cert_cb_t(void *arg, const avs_crypto_certificate_chain_info_t *leaf_info);

static avs_error_t
load_cert_tree(const avs_crypto_certificate_chain_info_t *info,
               load_cert_cb_t *cb,
               void *cb_arg) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < info->desc.info.array.element_count;
             ++i) {
            err = load_cert_tree(
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
            avs_error_t err = load_cert_tree(
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
        return cb(cb_arg, info);
    }
}

typedef struct {
    avs_crypto_ossl_object_load_t *cb;
    void *cb_arg;
} load_certs_cb_info_t;

static avs_error_t
pass_cert_to_cb(void *cb_info_,
                const avs_crypto_certificate_chain_info_t *info) {
    load_certs_cb_info_t *cb_info = (load_certs_cb_info_t *) cb_info_;
    switch (info->desc.source) {
#    ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_ENGINE:
        if (!info->desc.info.engine.query) {
            LOG(ERROR, _("attempt to load certificate chain from engine, but "
                         "query=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return _avs_crypto_openssl_engine_load_certs(
                info->desc.info.engine.query, cb_info->cb, cb_info->cb_arg);
#    endif // AVS_COMMONS_WITH_AVS_CRYPTO_ENGINE
    case AVS_CRYPTO_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR, _("attempt to load certificate chain from file, but "
                         "filename=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_certs_from_file(info->desc.info.file.filename, cb_info->cb,
                                    cb_info->cb_arg);
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        LOG(ERROR, _("Certificate path sources cannot be used as client "
                     "certificate chains"));
        return avs_errno(AVS_ENOTSUP);
    case AVS_CRYPTO_DATA_SOURCE_BUFFER: {
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR,
                _("attempt to load certificate chain from buffer, but "
                  "buffer=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        return load_pem_or_der_objects(info->desc.info.buffer.buffer,
                                       info->desc.info.buffer.buffer_size, NULL,
                                       AVS_OSSL_OBJECT_X509, cb_info->cb,
                                       cb_info->cb_arg);
    }
    default:
        AVS_UNREACHABLE("invalid data source");
        return avs_errno(AVS_EINVAL);
    }
}

avs_error_t _avs_crypto_openssl_load_client_certs(
        const avs_crypto_certificate_chain_info_t *info,
        avs_crypto_ossl_object_load_t *load_cb,
        void *cb_arg) {
    if (info == NULL) {
        LOG(ERROR, "Given cert info is empty.");
        return avs_errno(AVS_EINVAL);
    }

    return load_cert_tree(info, pass_cert_to_cb,
                          &(load_certs_cb_info_t) {
                              .cb = load_cb,
                              .cb_arg = cb_arg
                          });
}

static avs_error_t load_single_cert_to_store(void *cert, void *store) {
    if (X509_STORE_add_cert((X509_STORE *) store, (X509 *) cert)) {
        return AVS_OK;
    }
    unsigned long err = ERR_peek_error();
    if (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
        ERR_get_error();
        return AVS_OK;
    }
    log_openssl_error();
    return avs_errno(AVS_ENOMEM);
}

static avs_error_t
load_certs_to_store(void *store,
                    const avs_crypto_certificate_chain_info_t *info) {
    switch (info->desc.source) {
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        if (!info->desc.info.path.path) {
            LOG(ERROR, _("attempt to load certificate chain from path, but "
                         "path=NULL"));
            return avs_errno(AVS_EINVAL);
        }
        LOG(DEBUG, _("certificate <path=") "%s" _(">: going to load"),
            info->desc.info.path.path);
        if (!X509_STORE_load_locations((X509_STORE *) store, NULL,
                                       info->desc.info.path.path)) {
            log_openssl_error();
            return avs_errno(AVS_EPROTO);
        }
        return AVS_OK;
    default:
        return pass_cert_to_cb(&(load_certs_cb_info_t) {
                                   .cb = load_single_cert_to_store,
                                   .cb_arg = store
                               },
                               info);
    }
}

avs_error_t _avs_crypto_openssl_load_ca_certs(
        X509_STORE *store, const avs_crypto_certificate_chain_info_t *info) {
    if (info == NULL) {
        LOG(ERROR, "Given cert info is empty.");
        return avs_errno(AVS_EINVAL);
    }

    return load_cert_tree(info, load_certs_to_store, store);
}

static avs_error_t load_first_cert(void *cert_, void *out_cert_ptr_) {
    X509 *cert = (X509 *) cert_;
    X509 **out_cert_ptr = (X509 **) out_cert_ptr_;
    if (!*out_cert_ptr) {
        if (!X509_up_ref(cert)) {
            log_openssl_error();
            return avs_errno(AVS_ENOMEM);
        }
        *out_cert_ptr = cert;
    }
    return AVS_OK;
}

avs_error_t _avs_crypto_openssl_load_first_client_cert(
        X509 **out_cert, const avs_crypto_certificate_chain_info_t *info) {
    assert(out_cert && !*out_cert);
    return _avs_crypto_openssl_load_client_certs(info, load_first_cert,
                                                 out_cert);
}

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_OPENSSL) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)
