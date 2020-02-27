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

#if defined(AVS_COMMONS_WITH_AVS_STREAM) && defined(AVS_COMMONS_WITH_MBEDTLS)

#    include <stdlib.h>

#    include <mbedtls/md5.h>
#    include <mbedtls/version.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_md5.h>

#    include "avs_md5_common.h"

VISIBILITY_SOURCE_BEGIN

#    if MBEDTLS_VERSION_NUMBER < 0x02070000
// the _ret variants were introduced in mbed TLS 2.7.0,
// emulate them on older versions

static inline int mbedtls_md5_starts_ret(mbedtls_md5_context *ctx) {
    mbedtls_md5_starts(ctx);
    return 0;
}

static inline int mbedtls_md5_update_ret(mbedtls_md5_context *ctx,
                                         const unsigned char *input,
                                         size_t ilen) {
    mbedtls_md5_update(ctx, input, ilen);
    return 0;
}

static inline int mbedtls_md5_finish_ret(mbedtls_md5_context *ctx,
                                         unsigned char *output) {
    mbedtls_md5_finish(ctx, output);
    return 0;
}
#    endif

typedef struct {
    avs_stream_md5_common_t common;
    mbedtls_md5_context ctx;
} mbedtls_md5_stream_t;

static avs_error_t avs_md5_finish(avs_stream_t *stream) {
    mbedtls_md5_stream_t *str = (mbedtls_md5_stream_t *) stream;

    int result = mbedtls_md5_finish_ret(&str->ctx, str->common.result);
    _avs_stream_md5_common_finalize(&str->common);

    return avs_errno(result ? AVS_ENOBUFS : AVS_NO_ERROR);
}

static avs_error_t avs_md5_reset(avs_stream_t *stream) {
    mbedtls_md5_stream_t *str = (mbedtls_md5_stream_t *) stream;

    if (!_avs_stream_md5_common_is_finalized(&str->common)) {
        avs_md5_finish(stream);
    }
    int result = mbedtls_md5_starts_ret(&str->ctx);
    _avs_stream_md5_common_reset(&str->common);
    return avs_errno(result ? AVS_ENOBUFS : AVS_NO_ERROR);
}

static avs_error_t
avs_md5_update(avs_stream_t *stream, const void *buf, size_t *len) {
    mbedtls_md5_stream_t *str = (mbedtls_md5_stream_t *) stream;

    if (_avs_stream_md5_common_is_finalized(&str->common)) {
        return avs_errno(AVS_EBADF);
    }

    return avs_errno(
            mbedtls_md5_update_ret(&str->ctx, (const unsigned char *) buf, *len)
                    ? AVS_ENOBUFS
                    : AVS_NO_ERROR);
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
    mbedtls_md5_stream_t *retval =
            (mbedtls_md5_stream_t *) avs_malloc(sizeof(mbedtls_md5_stream_t));
    if (retval) {
        _avs_stream_md5_common_init(&retval->common, &md5_vtable);
        mbedtls_md5_init(&retval->ctx);
        if (mbedtls_md5_starts_ret(&retval->ctx)) {
            avs_free(retval);
            retval = NULL;
        }
    }
    return (avs_stream_t *) retval;
}

#endif // defined(AVS_COMMONS_WITH_AVS_STREAM) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
