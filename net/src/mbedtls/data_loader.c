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

#define MODULE_NAME avs_net_data_loader
#include <x_log_config.h>

#include "data_loader.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/utils.h>

VISIBILITY_SOURCE_BEGIN

#define CREATE_OR_FAIL(type, ptr) \
do { \
    free(*ptr); \
    *ptr = (type *) calloc(1, sizeof(**ptr)); \
    if (!*ptr) {\
        LOG(ERROR, "memory allocation error"); \
        return -1; \
    } \
} while (0)

static int
append_cert_from_buffer(mbedtls_x509_crt *chain, const void *buffer, size_t len) {
    return mbedtls_x509_crt_parse(chain, (const unsigned char *) buffer, len);
}

static int load_cert_from_file(mbedtls_x509_crt *chain, const char *name) {
    LOG(DEBUG, "certificate <%s>: going to load", name);

    int retval = mbedtls_x509_crt_parse_file(chain, name);
    if (retval) {
        LOG(ERROR, "certificate <%s>: failed to load, result %d", name, retval);
    } else {
        LOG(DEBUG, "certificate <%s>: loaded", name);
    }
    return retval;
}

static int load_ca_from_path(mbedtls_x509_crt *chain, const char *path) {
    LOG(DEBUG, "certificates from path <%s>: going to load", path);

    int retval = mbedtls_x509_crt_parse_path(chain, path);
    if (retval) {
        LOG(ERROR, "certificates from path <%s>: failed to load, result %d",
            path, retval);
    } else {
        LOG(DEBUG, "certificates from path <%s>: loaded", path);
    }
    return retval;
}

int _avs_net_load_ca_certs(mbedtls_x509_crt **out,
                           const avs_net_trusted_cert_info_t *info) {
    assert(info->desc.is_trusted_cert);
    CREATE_OR_FAIL(mbedtls_x509_crt, out);
    mbedtls_x509_crt_init(*out);

    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (info->desc.info.file.password) {
            LOG(WARNING, "password protected CA are not supported - the "
                         "password will be ignored");
        }
        return load_cert_from_file(*out, info->desc.info.file.filename);
    case AVS_NET_DATA_SOURCE_PATHS: {
        int retfile = -1;
        int retpath = -1;
        if (info->desc.info.paths.filename) {
            retfile = load_cert_from_file(*out, info->desc.info.paths.filename);
        }
        if (info->desc.info.paths.path) {
            retpath = load_ca_from_path(*out, info->desc.info.paths.path);
        }
        return retpath < 0 && retfile < 0 ? -1 : 0;
    }
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (info->desc.info.buffer.password) {
            LOG(WARNING, "password protected CA are not supported - the "
                         "password will be ignored");
        }
        return append_cert_from_buffer(*out, info->desc.info.buffer.buffer,
                                       info->desc.info.buffer.buffer_size);
    default:
        assert(0 && "invalid data source");
        return -1;
    }
    return 0;
}

int _avs_net_load_client_cert(mbedtls_x509_crt **out,
                              const avs_net_client_cert_info_t *info) {
    assert(info->desc.is_client_cert);
    CREATE_OR_FAIL(mbedtls_x509_crt, out);
    mbedtls_x509_crt_init(*out);

    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        if (info->desc.info.file.password) {
            LOG(WARNING, "password protected client certificates are not "
                         "supported - the password will be ignored");
        }
        return load_cert_from_file(*out, info->desc.info.file.filename);
    case AVS_NET_DATA_SOURCE_BUFFER:
        if (info->desc.info.buffer.password) {
            LOG(WARNING, "password protected client certificates are not "
                         "supported - the password will be ignored");
        }
        return append_cert_from_buffer(*out, info->desc.info.buffer.buffer,
                                       info->desc.info.buffer.buffer_size);
    default:
        assert(0 && "invalid data source");
        return -1;
    }
    return 0;
}

static int load_private_key_from_buffer(mbedtls_pk_context *client_key,
                                        const void *buffer,
                                        size_t len,
                                        const char *password) {
    const unsigned char *pwd = (const unsigned char *) password;
    const size_t pwd_len = password ? strlen(password) : 0;
    return mbedtls_pk_parse_key(client_key, (const unsigned char *) buffer,
                                len, pwd, pwd_len);
}

static int load_private_key_from_file(mbedtls_pk_context *client_key,
                                      const char *filename,
                                      const char *password) {
    LOG(DEBUG, "private key <%s>: going to load", filename);

    int retval = mbedtls_pk_parse_keyfile(client_key, filename, password);
    if (retval) {
        LOG(ERROR, "private key <%s>: failed, result %d", filename, retval);
    } else {
        LOG(DEBUG, "private key <%s>: loaded", filename);
    }
    return retval;
}

int _avs_net_load_client_key(mbedtls_pk_context **client_key,
                             const avs_net_client_key_info_t *info) {
    assert(info->desc.is_client_key);
    CREATE_OR_FAIL(mbedtls_pk_context, client_key);
    mbedtls_pk_init(*client_key);

    switch (info->desc.source) {
    case AVS_NET_DATA_SOURCE_FILE:
        return load_private_key_from_file(*client_key,
                                          info->desc.info.file.filename,
                                          info->desc.info.file.password);
    case AVS_NET_DATA_SOURCE_BUFFER:
        return load_private_key_from_buffer(*client_key,
                                            info->desc.info.buffer.buffer,
                                            info->desc.info.buffer.buffer_size,
                                            info->desc.info.buffer.password);
    default:
        assert(0 && "invalid data source");
        return -1;
    }
    return 0;
}

#ifdef AVS_UNIT_TESTING
#include "test/data_loader.c"
#endif
