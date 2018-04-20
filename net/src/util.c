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

#define MODULE_NAME avs_net_util
#include <x_log_config.h>

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "util.h"

#include <avsystem/commons/log.h>

VISIBILITY_SOURCE_BEGIN

char *_avs_read_file(const char *name, size_t *out_size) {
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

// Arbitrary size of the statically allocated path processed by
// iterate_directory().
#define MAX_PATH_LENGTH 1024

int _avs_iterate_directory(const char *directory,
                           entry_callback_t *clb,
                           void *context) {
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

