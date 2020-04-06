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

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <avsystem/commons/avs_unit_test.h>

AVS_UNIT_TEST(base64, padding) {
    char result[5];

    AVS_UNIT_ASSERT_SUCCESS(
            avs_base64_encode(result, sizeof(result), (const uint8_t *) "", 0));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode(result, sizeof(result),
                                              (const uint8_t *) "a", 1));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YQ==");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode(result, sizeof(result),
                                              (const uint8_t *) "aa", 2));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YWE=");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode(result, sizeof(result),
                                              (const uint8_t *) "aaa", 3));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YWFh");
}

AVS_UNIT_TEST(base64, encode) {
    char result[5];

    /* also encode terminating NULL byte */
    AVS_UNIT_ASSERT_SUCCESS(
            avs_base64_encode(result, sizeof(result), (const uint8_t *) "", 1));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "AA==");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode(result, sizeof(result),
                                              (const uint8_t *) "a", 2));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YQA=");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode(result, sizeof(result),
                                              (const uint8_t *) "aa", 3));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YWEA");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode(
            result, sizeof(result), (const uint8_t *) "\x0C\x40\x03", 3));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "DEAD");
    /* output buffer too short */
    AVS_UNIT_ASSERT_FAILED(avs_base64_encode(
            result, sizeof(result), (const uint8_t *) "\x0C\x40\x03\xAA", 4));
}

AVS_UNIT_TEST(base64, decode) {
    char result[5];
    size_t result_length;
    char buf[5] = "AX==";
    const char *ch;
    for (ch = AVS_BASE64_CHARS; *ch; ++ch) {
        buf[1] = *ch;
        AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(
                &result_length, (uint8_t *) result, sizeof(result), buf));
        AVS_UNIT_ASSERT_EQUAL(result_length, 1);
        AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode_strict(
                &result_length, (uint8_t *) result, sizeof(result), buf));
        AVS_UNIT_ASSERT_EQUAL(result_length, 1);
    }
    /* terminating NULL byte is Base64 encoded */
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(
            &result_length, (uint8_t *) result, sizeof(result), "AA=="));
    AVS_UNIT_ASSERT_EQUAL(result_length, 1);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(
            &result_length, (uint8_t *) result, sizeof(result), "YQA="));
    AVS_UNIT_ASSERT_EQUAL(result_length, 2);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "a");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(
            &result_length, (uint8_t *) result, sizeof(result), "YWEA"));
    AVS_UNIT_ASSERT_EQUAL(result_length, 3);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "aa");

    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(
            &result_length, (uint8_t *) result, sizeof(result), ""));
    AVS_UNIT_ASSERT_EQUAL(result_length, 0);

    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(
            &result_length, (uint8_t *) result, sizeof(result), "A+=="));
    AVS_UNIT_ASSERT_EQUAL(result_length, 1);

    AVS_UNIT_ASSERT_FAILED(avs_base64_decode(&result_length, (uint8_t *) result,
                                             sizeof(result), "\x01"));

    /* avs_base64_decode is not strict */
    AVS_UNIT_ASSERT_SUCCESS(
            avs_base64_decode(&result_length, (uint8_t *) result,
                              sizeof(result), "Y== ==\n\n\t\vWEA"));
    AVS_UNIT_ASSERT_EQUAL(result_length, 3);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "aa");

    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(
            &result_length, (uint8_t *) result, sizeof(result), "YQA"));
    AVS_UNIT_ASSERT_EQUAL(result_length, 2);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "a");

    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(
            &result_length, (uint8_t *) result, sizeof(result), "YQA=="));
    AVS_UNIT_ASSERT_EQUAL(result_length, 2);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "a");
}

AVS_UNIT_TEST(base64, decode_fail) {
    char result[5];
    char buf[5] = "AX==";
    char ch;
    AVS_UNIT_ASSERT_FAILED(
            avs_base64_decode(NULL, (uint8_t *) result, 1, "AA=="));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode(NULL, (uint8_t *) result, 5, ","));

    for (ch = 1; ch < CHAR_MAX; ++ch) {
        buf[1] = ch;
        if (!strchr(AVS_BASE64_CHARS, ch) && !isspace(ch) && ch != '=') {
            AVS_UNIT_ASSERT_FAILED(
                    avs_base64_decode(NULL, (uint8_t *) result, 5, buf));
        }
        if (!strchr(AVS_BASE64_CHARS, ch)) {
            AVS_UNIT_ASSERT_FAILED(
                    avs_base64_decode_strict(NULL, (uint8_t *) result, 5, buf));
        }
    }
}

AVS_UNIT_TEST(base64, decode_strict) {
    char result[16];
    /* no data - no problem */
    size_t result_length;
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode_strict(
            &result_length, (uint8_t *) result, sizeof(result), ""));
    AVS_UNIT_ASSERT_EQUAL(result_length, 0);

    /* not a multiple of 4 */
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "=="));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "="));

    /* invalid characters in the middle */
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9=v"));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9 v"));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9\0v"));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(
            NULL, (uint8_t *) result, sizeof(result), "Y== ==\n\n\t\vWEA"));

    /* invalid characters at the end */
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9v "));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(
            NULL, (uint8_t *) result, sizeof(result), "Zm9vYg== "));

    /* =-padded, invalid characters in the middle */
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(
            NULL, (uint8_t *) result, sizeof(result), "Zm9=Yg=="));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(
            NULL, (uint8_t *) result, sizeof(result), "Zm9 Yg=="));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(
            NULL, (uint8_t *) result, sizeof(result), "Zm9\0Yg=="));

    /* not a multiple of 4 (missing padding) */
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9vYg="));

    /* too much padding */
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(
            NULL, (uint8_t *) result, sizeof(result), "Zm9vY==="));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(
            NULL, (uint8_t *) result, sizeof(result), "Zm9v===="));

    /* too much padding + not a multiple of 4 */
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9vY=="));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9vY="));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9v=="));
    AVS_UNIT_ASSERT_FAILED(avs_base64_decode_strict(NULL, (uint8_t *) result,
                                                    sizeof(result), "Zm9v="));

    /* valid, with single padding byte */
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode_strict(
            &result_length, (uint8_t *) result, sizeof(result), "YQA="));
    AVS_UNIT_ASSERT_EQUAL(result_length, 2);
}

AVS_UNIT_TEST(base64, encoded_and_decoded_size) {
    char result[1024];
    uint8_t bytes[256];
    size_t i;
    size_t length;
    for (i = 0; i < sizeof(bytes); ++i) {
        bytes[i] = (uint8_t) (rand() % 256);
    }
    for (i = 0; i < sizeof(bytes); ++i) {
        AVS_UNIT_ASSERT_SUCCESS(
                avs_base64_encode(result, sizeof(result), bytes, i));
        length = strlen(result);
        AVS_UNIT_ASSERT_EQUAL(length + 1, avs_base64_encoded_size(i));
        /* avs_base64_estimate_decoded_size should be an upper bound */
        AVS_UNIT_ASSERT_TRUE(avs_base64_estimate_decoded_size(length + 1) >= i);
    }
    AVS_UNIT_ASSERT_EQUAL(avs_base64_estimate_decoded_size(0), 0);
    for (i = 1; i < 4; ++i) {
        AVS_UNIT_ASSERT_EQUAL(avs_base64_estimate_decoded_size(i), 3);
    }
}
