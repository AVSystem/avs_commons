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

// NOTE: OpenSSL headers sometimes (depending on a version) contain some of the
// symbols poisoned via inclusion of avs_commons_config.h. Therefore they must
// be included first.
#include <openssl/ssl.h>

#include <avs_commons_config.h>

#define MODULE_NAME avs_net_data_loader
#include <x_log_config.h>

#include "common.h"
#include "data_loader.h"

#include "../api.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/utils.h>

VISIBILITY_SOURCE_BEGIN

static int password_cb(char *buf, int num, int rwflag, void *userdata) {
    if (!userdata) {
        buf[0] = '\0';
        return 0;
    }
    int retval = snprintf(buf, (size_t) num, "%s", (const char *) userdata);
    (void) rwflag;
    return (retval < 0 || retval >= num) ? -1 : retval;
}

static inline void setup_password_callback(SSL_CTX *ctx, const char *password) {
    SSL_CTX_set_default_passwd_cb_userdata(
            ctx,
            /* const_cast */ (void *) (intptr_t) password);
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
}

static int load_ca_certs_from_paths(SSL_CTX *ctx,
                                    const char *file,
                                    const char *path) {
    AVS_ASSERT(!!file != !!path, "cannot use path and file at the same time");
    LOG(DEBUG, "CA certificate <file=%s, path=%s>: going to load",
        file ? file : "(null)", path ? path : "(null)");

    if (file) {
        /**
         * SSL_CTX_load_verify_locations() allows PEM certificates only to be
         * loaded. Underneath it uses X509_LOOKUP_load_file with type hardcoded
         * to X509_FILETYPE_PEM, but it is also possible to use
         * X509_FILETYPE_ASN1.
         */
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (lookup == NULL) {
            return -1;
        }
        if (X509_LOOKUP_load_file(lookup, file, X509_FILETYPE_PEM) == 1) {
            return 0;
        }
        if (X509_LOOKUP_load_file(lookup, file, X509_FILETYPE_ASN1) == 1) {
            return 0;
        }
        log_openssl_error();
        return -1;
    } else {
        if (!SSL_CTX_load_verify_locations(ctx, NULL, path)) {
            log_openssl_error();
            return -1;
        }
    }
    return 0;
}

typedef enum {
    ENCODING_UNKNOWN,
    ENCODING_PEM,
    ENCODING_DER
} encoding_t;

static encoding_t detect_encoding(const char *buffer, size_t len) {
    static const char *pem_prefix = "-----BEGIN ";
    if (len < strlen(pem_prefix)) {
        // clearly not PEM and too short to be DER
        return ENCODING_UNKNOWN;
    } else if (!strncmp(buffer, pem_prefix, strlen(pem_prefix))) {
        return ENCODING_PEM;
    } else {
        return ENCODING_DER;
    }
}

// NOTE: This function exists only because OpenSSL does not seem to have a
// method of loading in-buffer PEM encoded certificates.
static X509 *parse_cert(const void *buffer, const size_t len) {
    X509 *cert = NULL;
    switch (detect_encoding((const char *) buffer, len)) {
    case ENCODING_PEM: {
        // Convert PEM to DER.
        BIO *bio = BIO_new_mem_buf((void *) (intptr_t) buffer, (int) len);
        if (!bio) {
            return NULL;
        }
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        break;
    }
    case ENCODING_DER: {
        const unsigned char *data = (const unsigned char *)buffer;
        cert = d2i_X509(NULL, &data, (int) len);
        break;
    }
    default:
        LOG(ERROR, "unknown in-memory certificate format");
        break;
    }
    return cert;
}

static int load_ca_cert_from_buffer(SSL_CTX *ctx,
                                    const void *buffer,
                                    const size_t len) {
    X509 *cert = parse_cert(buffer, len);
    if (!cert) {
        return -1;
    }
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store || !X509_STORE_add_cert(store, cert)) {
        log_openssl_error();
        X509_free(cert);
        return -1;
    }
    return 0;
}

int _avs_net_openssl_load_ca_certs(SSL_CTX *ctx,
                                   const avs_net_trusted_cert_info_t *info) {
    setup_password_callback(ctx, NULL);
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        LOG(WARNING, "could not set default CA verify paths");
        log_openssl_error();
    }

    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR, "attempt to load CA cert from file, but filename=NULL");
            return -1;
        }
        return load_ca_certs_from_paths(ctx, info->desc.info.file.filename,
                                        NULL);
    case AVS_NET_DATA_SOURCE_PATH:
        if (!info->desc.info.path.path) {
            LOG(ERROR, "attempt to load CA cert from path, but path=NULL");
            return -1;
        }
        return load_ca_certs_from_paths(ctx, NULL, info->desc.info.path.path);
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR, "attempt to load CA cert from buffer, but buffer=NULL");
            return -1;
        }
        return load_ca_cert_from_buffer(ctx, info->desc.info.buffer.buffer,
                                        info->desc.info.buffer.buffer_size);
    default:
        AVS_UNREACHABLE("invalid data source");
        return -1;
    }
}

static int load_client_cert_from_file(SSL_CTX *ctx,
                                      const char *filename) {
    LOG(DEBUG, "client certificate <%s>: going to load", filename);
    // Try PEM.
    if (SSL_CTX_use_certificate_file(ctx, filename, SSL_FILETYPE_PEM) == 1) {
        return 0;
    }
    // Try DER.
    if (SSL_CTX_use_certificate_file(ctx, filename, SSL_FILETYPE_ASN1) == 1) {
        return 0;
    }
    log_openssl_error();
    return -1;
}

static int
load_client_cert_from_buffer(SSL_CTX *ctx, const void *buffer, size_t len) {
    X509 *cert = parse_cert(buffer, len);
    if (!cert) {
        return -1;
    }
    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        X509_free(cert);
        log_openssl_error();
        return -1;
    }
    return 0;
}

int _avs_net_openssl_load_client_cert(SSL_CTX *ctx,
                                      const avs_net_client_cert_info_t *info) {
    setup_password_callback(ctx, NULL);

    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR, "attempt to load client cert from file, but filename=NULL");
            return -1;
        }
        return load_client_cert_from_file(ctx, info->desc.info.file.filename);
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR, "attempt to load client cert from buffer, but buffer=NULL");
            return -1;
        }
        return load_client_cert_from_buffer(ctx, info->desc.info.buffer.buffer,
                                            info->desc.info.buffer.buffer_size);
    default:
        AVS_UNREACHABLE("invalid data source");
        return -1;
    }
}

static int load_client_key_from_file(SSL_CTX *ctx,
                                     const char *filename,
                                     const char *password) {
    LOG(DEBUG, "client key <%s>: going to load", filename);
    setup_password_callback(ctx, password);

    // Try PEM.
    if (SSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM) == 1) {
        return 0;
    }
    // Try DER.
    if (SSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_ASN1) == 1) {
        return 0;
    }
    log_openssl_error();
    return -1;
}

// NOTE: This function exists only because OpenSSL does not seem to have a
// method of loading in-buffer PEM encoded private keys.
static EVP_PKEY *
parse_key(const void *buffer, const size_t len, const char *password) {
    EVP_PKEY *key = NULL;
    BIO *bio = BIO_new_mem_buf((void *) (intptr_t) buffer, (int) len);
    if (!bio) {
        return NULL;
    }
    switch (detect_encoding((const char *) buffer, len)) {
    case ENCODING_PEM: {
        key = PEM_read_bio_PrivateKey(bio, NULL, password_cb,
                                      (void *) (intptr_t) password);
        break;
    }
    case ENCODING_DER: {
        key = d2i_PrivateKey_bio(bio, NULL);
        break;
    }
    default:
        LOG(ERROR, "unknown in-memory certificate format");
        break;
    }
    BIO_free(bio);
    return key;
}

static int load_client_key_from_buffer(SSL_CTX *ctx,
                                       const void *buffer,
                                       size_t len,
                                       const char *password) {
    setup_password_callback(ctx, password);

    EVP_PKEY *key = parse_key(buffer, len, password);
    if (!key) {
        return -1;
    }
    if (SSL_CTX_use_PrivateKey(ctx, key) != 1) {
        log_openssl_error();
        return -1;
    }
    return 0;
}

int _avs_net_openssl_load_client_key(SSL_CTX *ctx,
                                     const avs_net_client_key_info_t *info) {
    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (!info->desc.info.file.filename) {
            LOG(ERROR, "attempt to load client key from file, but filename=NULL");
            return -1;
        }
        return load_client_key_from_file(ctx, info->desc.info.file.filename,
                                         info->desc.info.file.password);
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (!info->desc.info.buffer.buffer) {
            LOG(ERROR, "attempt to load client key from buffer, but buffer=NULL");
            return -1;
        }
        return load_client_key_from_buffer(ctx, info->desc.info.buffer.buffer,
                                           info->desc.info.buffer.buffer_size,
                                           info->desc.info.buffer.password);
    default:
        AVS_UNREACHABLE("invalid data source");
        return -1;
    }
}
