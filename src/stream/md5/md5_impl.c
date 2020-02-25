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

#if defined(AVS_COMMONS_WITH_AVS_STREAM) && !defined(AVS_COMMONS_WITH_OPENSSL) \
        && !defined(AVS_COMMONS_WITH_MBEDTLS)

#    include <stdlib.h>
#    include <string.h>

#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_stream_md5.h>

#    include "avs_md5_common.h"

VISIBILITY_SOURCE_BEGIN

typedef struct {
    avs_stream_md5_common_t common;
    uint32_t bits[2];
    unsigned char in[64];
} md5_stream_t;

static uint32_t getu32(const unsigned char *addr) {
    return (((((uint32_t) addr[3] << 8) | addr[2]) << 8) | addr[1]) << 8
           | addr[0];
}

static void putu32(uint32_t data, unsigned char *addr) {
    addr[0] = (unsigned char) data;
    addr[1] = (unsigned char) (data >> 8);
    addr[2] = (unsigned char) (data >> 16);
    addr[3] = (unsigned char) (data >> 24);
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#    define F1(x, y, z) (z ^ (x & (y ^ z)))
#    define F2(x, y, z) F1(z, x, y)
#    define F3(x, y, z) (x ^ y ^ z)
#    define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#    define MD5STEP(f, w, x, y, z, data, s) \
        (w += f(x, y, z) + data,            \
         w &= 0xffffffff,                   \
         w = w << s | w >> (32 - s),        \
         w += x)

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void avs_md5_transform(unsigned char buf[MD5_LENGTH],
                              const unsigned char inraw[64]) {
    register uint32_t old_a, old_b, old_c, old_d, a, b, c, d;
    uint32_t in[16];
    int i;

    for (i = 0; i < 16; ++i)
        in[i] = getu32(inraw + 4 * i);

    a = old_a = getu32(buf);
    b = old_b = getu32(buf + 4);
    c = old_c = getu32(buf + 8);
    d = old_d = getu32(buf + 12);

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    putu32(a + old_a, buf);
    putu32(b + old_b, buf + 4);
    putu32(c + old_c, buf + 8);
    putu32(d + old_d, buf + 12);
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static avs_error_t avs_md5_reset(avs_stream_t *stream) {
    static const unsigned char INITIAL_DATA[] = { 0x01, 0x23, 0x45, 0x67,
                                                  0x89, 0xAB, 0xCD, 0xEF,
                                                  0xFE, 0xDC, 0xBA, 0x98,
                                                  0x76, 0x54, 0x32, 0x10 };

    md5_stream_t *ctx = (md5_stream_t *) stream;

    memset(ctx->in, 0, sizeof(ctx->in));
    memcpy(ctx->common.result, INITIAL_DATA, sizeof(ctx->common.result));
    memset(ctx->bits, 0, sizeof(ctx->bits));

    _avs_stream_md5_common_reset(&ctx->common);
    return AVS_OK;
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static avs_error_t avs_md5_finish(avs_stream_t *stream) {
    md5_stream_t *ctx = (md5_stream_t *) stream;
    unsigned count;
    unsigned char *p = NULL;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
     always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
        /* Two lots of padding:  Pad the first block to 64 bytes */
        memset(p, 0, count);
        avs_md5_transform(ctx->common.result, ctx->in);

        /* Now fill the next block with 56 bytes */
        memset(ctx->in, 0, 56);
    } else {
        /* Pad block to 56 bytes */
        memset(p, 0, count - 8);
    }

    /* Append length in bits and transform */
    putu32(ctx->bits[0], ctx->in + 56);
    putu32(ctx->bits[1], ctx->in + 60);

    avs_md5_transform(ctx->common.result, ctx->in);
    _avs_stream_md5_common_finalize(&ctx->common);

    /* In case it's sensitive */
    memset(ctx->bits, 0, sizeof(ctx->bits));
    return AVS_OK;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static avs_error_t
avs_md5_update(avs_stream_t *stream, const void *buf_, size_t *len) {
    const char *buf = (const char *) buf_;
    md5_stream_t *ctx = (md5_stream_t *) stream;
    size_t remaining = *len;
    uint32_t t;

    if (_avs_stream_md5_common_is_finalized(&ctx->common)) {
        return avs_errno(AVS_EBADF);
    }

    /* Update bitcount */

    t = ctx->bits[0];
    if ((ctx->bits[0] = (t + ((uint32_t) remaining << 3)) & 0xffffffff) < t)
        ctx->bits[1]++; /* Carry from low to high */
    ctx->bits[1] += (uint32_t) (remaining >> 29);

    t = (t >> 3) & 0x3f; /* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */

    if (t) {
        unsigned char *p = ctx->in + t;

        t = 64 - t;
        if (remaining < t) {
            memcpy(p, buf, remaining);
            return AVS_OK;
        }
        memcpy(p, buf, t);
        avs_md5_transform(ctx->common.result, ctx->in);
        buf += t;
        remaining -= t;
    }

    /* Process data in 64-byte chunks */

    while (remaining >= 64) {
        memcpy(ctx->in, buf, 64);
        avs_md5_transform(ctx->common.result, ctx->in);
        buf += 64;
        remaining -= 64;
    }

    /* Handle any remaining bytes of data. */

    memcpy(ctx->in, buf, remaining);
    return AVS_OK;
}

static const avs_stream_v_table_t md5_vtable = {
    .write_some = avs_md5_update,
    .finish_message = avs_md5_finish,
    .read = _avs_stream_md5_common_read,
    .reset = avs_md5_reset,
    .close = avs_md5_reset,
    AVS_STREAM_V_TABLE_NO_EXTENSIONS
};

avs_stream_t *avs_stream_md5_create(void) {
    md5_stream_t *retval = (md5_stream_t *) avs_malloc(sizeof(md5_stream_t));
    if (retval) {
        _avs_stream_md5_common_init(&retval->common, &md5_vtable);
        avs_md5_reset((avs_stream_t *) retval);
    }
    return (avs_stream_t *) retval;
}

#endif // defined(AVS_COMMONS_WITH_AVS_STREAM) &&
       // !defined(AVS_COMMONS_WITH_OPENSSL) &&
       // !defined(AVS_COMMONS_WITH_MBEDTLS)
