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

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_STREAM) && defined(AVS_COMMONS_WITH_OPENSSL)

#    include <stdlib.h>

#    include <openssl/md5.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_md5.h>

#    include "avs_md5_common.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    avs_stream_md5_common_t common;
    MD5_CTX ctx;
} openssl_md5_stream_t;

static avs_error_t avs_md5_finish(avs_stream_t *stream) {
    openssl_md5_stream_t *str = (openssl_md5_stream_t *) stream;

    // MD5_Final() returns 1 on success.
    int retval = !MD5_Final(str->common.result, &str->ctx);
    _avs_stream_md5_common_finalize(&str->common);

    return avs_errno(retval ? AVS_EIO : AVS_NO_ERROR);
}

static avs_error_t avs_md5_reset(avs_stream_t *stream) {
    openssl_md5_stream_t *str = (openssl_md5_stream_t *) stream;

    if (_avs_stream_md5_common_is_finalized(&str->common)) {
        avs_md5_finish(stream);
    }
    MD5_Init(&str->ctx);
    _avs_stream_md5_common_reset(&str->common);
    return AVS_OK;
}

static avs_error_t
avs_md5_update(avs_stream_t *stream, const void *buf, size_t *len) {
    openssl_md5_stream_t *str = (openssl_md5_stream_t *) stream;

    if (_avs_stream_md5_common_is_finalized(&str->common)) {
        return avs_errno(AVS_EBADF);
    }
    MD5_Update(&str->ctx, buf, *len);
    return AVS_OK;
}

static const avs_stream_v_table_t md5_vtable = {
    .write_some = avs_md5_update,
    .finish_message = avs_md5_finish,
    .read = _avs_stream_md5_common_read,
    .reset = avs_md5_reset,
    .close = avs_md5_finish,
    AVS_STREAM_V_TABLE_NO_EXTENSIONS
};

avs_stream_t *avs_stream_md5_create(void) {
    openssl_md5_stream_t *retval =
            (openssl_md5_stream_t *) avs_malloc(sizeof(openssl_md5_stream_t));
    if (retval) {
        _avs_stream_md5_common_init(&retval->common, &md5_vtable);
        MD5_Init(&retval->ctx);
    }
    return (avs_stream_t *) retval;
}

#endif // defined(AVS_COMMONS_WITH_AVS_STREAM) &&
       // defined(AVS_COMMONS_WITH_OPENSSL)
