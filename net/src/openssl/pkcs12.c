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

#define MODULE_NAME avs_net_pkcs12
#include <x_log_config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/pkcs12.h>

#include "common.h"
#include "pkcs12.h"

void _avs_net_openssl_pkcs12_free(pkcs12_unpacked_t *pkcs12) {
    if (!pkcs12) {
        return;
    }
    if (pkcs12->additional_ca_certs) {
        sk_X509_pop_free(pkcs12->additional_ca_certs, X509_free);
    }
    if (pkcs12->client_cert) {
        X509_free(pkcs12->client_cert);
    }
    if (pkcs12->private_key) {
        EVP_PKEY_free(pkcs12->private_key);
    }
    free(pkcs12);
}

static pkcs12_unpacked_t *
pkcs12_unpacked_new(const void *data,
                    size_t size,
                    const char *password) {
    if (!data) {
        LOG(ERROR, "cannot parse NULL pkcs12 data");
        return NULL;
    }
    if (!size) {
        LOG(ERROR, "cannot parse 0 sized pkcs12 data");
        return NULL;
    }
    long length = (long) (unsigned) size;
    PKCS12 *ctx = d2i_PKCS12(NULL, (const unsigned char **) &data, length);
    pkcs12_unpacked_t *result = NULL;
    if (!ctx) {
        goto cleanup;
    }

    result = (pkcs12_unpacked_t *) calloc(1, sizeof(pkcs12_unpacked_t));
    if (!result) {
        goto cleanup;
    }

    if (!PKCS12_parse(ctx, password, &result->private_key, &result->client_cert,
                      &result->additional_ca_certs)) {
        log_openssl_error();
        _avs_net_openssl_pkcs12_free(result);
        result = NULL;
        goto cleanup;
    }

cleanup:
    if (ctx) {
        PKCS12_free(ctx);
    }
    return result;
}

pkcs12_unpacked_t *
_avs_net_openssl_unpack_pkcs12_from_file(const char *filename,
                                         const char *password) {
    pkcs12_unpacked_t *result = NULL;
    void *data = NULL;
    FILE *f = fopen(filename, "rb");
    if (!f) {
        LOG(ERROR, "cannot open %s for parsing", filename);
        return NULL;
    }

    long len;
    if (fseek(f, 0L, SEEK_END)
            || (len = ftell(f)) < 0
            || fseek(f, 0L, SEEK_SET)) {
        goto finish;
    }

    if (!(data = malloc((size_t)len))) {
        LOG(ERROR, "could not allocate <%ld> bytes", len);
        goto finish;
    }
    if (fread(data, (size_t) len, 1, f) != 1) {
        LOG(ERROR, "could not read file <%s>: %s", filename, strerror(errno));
        goto finish;
    }
    result = pkcs12_unpacked_new(data, len, password);

finish:
    if (f) {
        fclose(f);
    }
    if (data) {
        free(data);
    }
    return result;
}

pkcs12_unpacked_t *
_avs_net_openssl_unpack_pkcs12_from_buffer(const void *buffer,
                                           size_t len,
                                           const char *password) {
    return pkcs12_unpacked_new(buffer, len, password);
}
