/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <avsystem/commons/unit/test.h>

AVS_UNIT_TEST(base64, padding) {
    char result[5];

    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode("", 0, result, sizeof(result)));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode("a", 1, result, sizeof(result)));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YQ==");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode("aa", 2, result, sizeof(result)));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YWE=");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode("aaa", 3, result, sizeof(result)));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YWFh");
}

AVS_UNIT_TEST(base64, encode) {
    char result[5];

    /* also encode terminating NULL byte */
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode("", 1, result, sizeof(result)));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "AA==");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode("a", 2, result, sizeof(result)));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YQA=");
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_encode("aa", 3, result, sizeof(result)));
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "YWEA");
}

AVS_UNIT_TEST(base64, decode) {
    char result[5];

    /* terminating NULL byte is Base64 encoded */
    AVS_UNIT_ASSERT_EQUAL(
            avs_base64_decode("AA==", (uint8_t *) result, sizeof(result)), 1);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "");
    AVS_UNIT_ASSERT_EQUAL(
            avs_base64_decode("YQA=", (uint8_t *) result, sizeof(result)), 2);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "a");
    AVS_UNIT_ASSERT_EQUAL(
            avs_base64_decode("YWEA", (uint8_t *) result, sizeof(result)), 3);
    AVS_UNIT_ASSERT_EQUAL_STRING(result, "aa");
}

AVS_UNIT_TEST(base64, decode_fail) {
    char result[5];

    AVS_UNIT_ASSERT_FAILED(
            (int) avs_base64_decode("AA==", (uint8_t *) result, 1));
    AVS_UNIT_ASSERT_FAILED((int) avs_base64_decode(",", (uint8_t *) result, 5));
}
