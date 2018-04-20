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
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <avsystem/commons/utils.h>

VISIBILITY_SOURCE_BEGIN

/**
 * mbedTLS provides an API that loads certificates / keys / whatever from files
 * and paths. However, this is something we do not have a direct control over -
 * i.e. we don't control what C API is used to load files, nor how they are
 * being loaded, how big is the overhead and so on.
 *
 * It thus makes sense to implement a single and consistent method for dealing
 * with the loading problem.
 */
static void *read_file(const char *name, size_t *out_size) {
    FILE *f = fopen(name, "rb");
    char *buffer = NULL;
    long len;
    if (!f) {
        LOG(ERROR, "could not open file <%s>: %s", name, strerror(errno));
        goto finish;
    }
    if (fseek(f, 0, SEEK_END) < 0
            || (len = ftell(f)) < 0
            || fseek(f, 0, SEEK_SET)) {
        LOG(ERROR, "could not seek in file <%s>: %s", name, strerror(errno));
        goto finish;
    }

    // Allocate buffer that is also able to store '\0' in case the contents are
    // PEM encoded.
    buffer = (char *)calloc(1, (size_t)len + 1);
    if (!buffer) {
        LOG(ERROR, "could not allocate buffer of size <%ld>", len + 1);
        goto finish;
    }
    if (fread(buffer, (size_t)len, 1, f) != 1) {
        free(buffer);
        buffer = NULL;
        LOG(ERROR, "could not read file <%s>: %s", name, strerror(errno));
        goto finish;
    }
    // Same as in mbedtls_pk_load_file()
    if (strstr(buffer, "-----BEGIN ") != NULL) {
        len++;
    }
    *out_size = (size_t)len;
finish:
    if (f) {
        fclose(f);
    }
    return buffer;
}

typedef void entry_callback_t(void *context, const char *filename);

// Arbitrary size of the statically allocated path processed by
// iterate_directory().
#define MAX_PATH_LENGTH 1024

static int
iterate_directory(const char *directory, entry_callback_t *clb, void *context) {
    DIR *dir = opendir(directory);
    if (!dir) {
        LOG(ERROR, "could not open directory <%s>: %s", directory,
            strerror(errno));
        return -1;
    }
    int retval = 0;
    char name[MAX_PATH_LENGTH];
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (avs_simple_snprintf(name, sizeof(name), "%s/%s", directory,
                                entry->d_name)
            < 0) {
            LOG(ERROR,
                "could not generate file name (%s/%s) - filename or directory "
                "too long (maximum total length supported is %" PRIu32 ")",
                directory, entry->d_name, (uint32_t) MAX_PATH_LENGTH);
            // continue anyway, hoping to load something
            retval = -1;
            continue;
        }

        struct stat statbuf;
        if (stat(name, &statbuf) < 0) {
            LOG(ERROR, "could not stat %s: %s", name, strerror(errno));
            // continue anyway, hoping to load something
            retval = -1;
            continue;
        }

        if (S_ISREG(statbuf.st_mode)) {
            clb(context, name);
        }
    }
    closedir(dir);
    return retval;
}

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

    size_t len;
    void *buf = read_file(name, &len);
    if (!buf) {
        return -1;
    }
    int retval = append_cert_from_buffer(chain, buf, len);
    free(buf);
    if (retval) {
        LOG(DEBUG, "certificate <%s>: failed", name);
    } else {
        LOG(DEBUG, "certificate <%s>: loaded", name);
    }
    return retval;
}

typedef struct {
    mbedtls_x509_crt *chain;
    int num_loaded;
} load_entry_state_t;

static void try_load_cert(void *context, const char *filename) {
    load_entry_state_t *state = (load_entry_state_t *) context;
    if (!load_cert_from_file(state->chain, filename)) {
        ++state->num_loaded;
    }
}

static int load_ca_from_path(mbedtls_x509_crt *chain, const char *path) {
    load_entry_state_t state = {
        .chain = chain,
        .num_loaded = 0
    };
    // NOTE: We call it a day, if at least one certificate could be loaded.
    (void) iterate_directory(path, try_load_cert, &state);
    if (!state.num_loaded) {
        LOG(ERROR, "could not load any CA from path <%s>", path);
        return -1;
    }
    return 0;
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
    size_t len;
    void *buf = read_file(filename, &len);
    if (!buf) {
        return -1;
    }
    const int retval =
            load_private_key_from_buffer(client_key, buf, len, password);
    free(buf);
    if (retval) {
        LOG(DEBUG, "private key <%s>: failed", filename);
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
