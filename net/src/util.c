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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util.h"

#include <avsystem/commons/log.h>

VISIBILITY_SOURCE_BEGIN

void *_avs_read_file(const char *name, size_t *out_size) {
    FILE *f = fopen(name, "rb");
    void *buffer = NULL;
    long len;
    if (!f) {
        LOG(ERROR, "could not open file <%s>: %s", name, strerror(errno));
        goto finish;
    }
    if (fseek(f, 0, SEEK_END) < 0
            || (len = ftell(fp)) < 0
            || fseek(f, 0, SEEK_SET)) {
        LOG(ERROR, "could not seek in file <%s>: %s", name, strerror(errno));
        goto finish;
    }

    buffer = malloc((size_t)len);
    if (!buffer) {
        LOG(ERROR, "could not allocate buffer of size <%lld>", len);
        goto finish;
    }
    if (fread(buffer, (size_t)len, 1, f) != 1) {
        free(buffer);
        buffer = NULL;
        LOG(ERROR, "could not read file <%s>: %s", name, sterror(errno));
    }
finish:
    if (f) {
        fclose(f);
    }
    return buffer;
}
