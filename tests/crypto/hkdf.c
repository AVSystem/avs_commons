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

#define AVS_UNIT_ENABLE_SHORT_ASSERTS
#include <avsystem/commons/avs_unit_test.h>

#include <avsystem/commons/avs_hkdf.h>

#include <string.h>

static void test_impl(const unsigned char *salt,
                      size_t salt_len,
                      const unsigned char *ikm,
                      size_t ikm_len,
                      const unsigned char *info,
                      size_t info_len,
                      const unsigned char *expected_output,
                      size_t expected_output_size) {
    unsigned char output[16];
    size_t output_size = expected_output_size;
    memset(output, 0, sizeof(output));

    ASSERT_OK(avs_crypto_hkdf_sha_256(salt, salt_len, ikm, ikm_len, info,
                                      info_len, output, &output_size));
    ASSERT_EQ(output_size, expected_output_size);
    ASSERT_EQ_BYTES_SIZED(output, expected_output, output_size);
}

// Test vectors from draft-ietf-core-object-security-16
// https://tools.ietf.org/html/draft-ietf-core-object-security-16#appendix-C.1

const unsigned char MASTER_SECRET[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                        0x0d, 0x0e, 0x0f, 0x10 };

AVS_UNIT_TEST(avs_crypto_hkdf, test_vector_1_client) {
    const unsigned char master_salt[] = { 0x9e, 0x7c, 0xa9, 0x22,
                                          0x23, 0x78, 0x63, 0x40 };

    const unsigned char sender_key_info[] = { 0x85, 0x40, 0xf6, 0x0a, 0x63,
                                              0x4b, 0x65, 0x79, 0x10 };
    const unsigned char sender_key[] = { 0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e,
                                         0x6a, 0xd4, 0xb5, 0x4f, 0xc7, 0x93,
                                         0x15, 0x43, 0x02, 0xff };

    test_impl(master_salt, sizeof(master_salt), MASTER_SECRET,
              sizeof(MASTER_SECRET), sender_key_info, sizeof(sender_key_info),
              sender_key, sizeof(sender_key));

    const unsigned char recipient_key_info[] = { 0x85, 0x41, 0x01, 0xf6, 0x0a,
                                                 0x63, 0x4b, 0x65, 0x79, 0x10 };
    const unsigned char recipient_key[] = { 0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94,
                                            0xc9, 0xca, 0xc9, 0x47, 0x16, 0x48,
                                            0xb4, 0xf9, 0x87, 0x10 };

    test_impl(master_salt, sizeof(master_salt), MASTER_SECRET,
              sizeof(MASTER_SECRET), recipient_key_info,
              sizeof(recipient_key_info), recipient_key, sizeof(recipient_key));

    const unsigned char common_iv_info[] = { 0x85, 0x40, 0xf6, 0x0a,
                                             0x62, 0x49, 0x56, 0x0d };
    const unsigned char common_iv[] = { 0x46, 0x22, 0xd4, 0xdd, 0x6d,
                                        0x94, 0x41, 0x68, 0xee, 0xfb,
                                        0x54, 0x98, 0x7c };

    test_impl(master_salt, sizeof(master_salt), MASTER_SECRET,
              sizeof(MASTER_SECRET), common_iv_info, sizeof(common_iv_info),
              common_iv, sizeof(common_iv));
}

AVS_UNIT_TEST(avs_crypto_hkdf, test_vector_1_server) {
    const unsigned char master_salt[] = { 0x9e, 0x7c, 0xa9, 0x22,
                                          0x23, 0x78, 0x63, 0x40 };

    const unsigned char sender_key_info[] = { 0x85, 0x41, 0x01, 0xf6, 0x0a,
                                              0x63, 0x4b, 0x65, 0x79, 0x10 };
    const unsigned char sender_key[] = { 0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94,
                                         0xc9, 0xca, 0xc9, 0x47, 0x16, 0x48,
                                         0xb4, 0xf9, 0x87, 0x10 };

    test_impl(master_salt, sizeof(master_salt), MASTER_SECRET,
              sizeof(MASTER_SECRET), sender_key_info, sizeof(sender_key_info),
              sender_key, sizeof(sender_key));

    const unsigned char recipient_key_info[] = { 0x85, 0x40, 0xf6, 0x0a, 0x63,
                                                 0x4b, 0x65, 0x79, 0x10 };
    const unsigned char recipient_key[] = { 0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e,
                                            0x6a, 0xd4, 0xb5, 0x4f, 0xc7, 0x93,
                                            0x15, 0x43, 0x02, 0xff };

    test_impl(master_salt, sizeof(master_salt), MASTER_SECRET,
              sizeof(MASTER_SECRET), recipient_key_info,
              sizeof(recipient_key_info), recipient_key, sizeof(recipient_key));

    const unsigned char common_iv_info[] = { 0x85, 0x40, 0xf6, 0x0a,
                                             0x62, 0x49, 0x56, 0x0d };
    const unsigned char common_iv[] = { 0x46, 0x22, 0xd4, 0xdd, 0x6d,
                                        0x94, 0x41, 0x68, 0xee, 0xfb,
                                        0x54, 0x98, 0x7c };

    test_impl(master_salt, sizeof(master_salt), MASTER_SECRET,
              sizeof(MASTER_SECRET), common_iv_info, sizeof(common_iv_info),
              common_iv, sizeof(common_iv));
}

AVS_UNIT_TEST(avs_crypto_hkdf, test_vector_2_client) {
    const unsigned char sender_key_info[] = { 0x85, 0x41, 0x00, 0xf6, 0x0a,
                                              0x63, 0x4b, 0x65, 0x79, 0x10 };
    const unsigned char sender_key[] = { 0x32, 0x1b, 0x26, 0x94, 0x32, 0x53,
                                         0xc7, 0xff, 0xb6, 0x00, 0x3b, 0x0b,
                                         0x64, 0xd7, 0x40, 0x41 };

    test_impl(NULL, 0, MASTER_SECRET, sizeof(MASTER_SECRET), sender_key_info,
              sizeof(sender_key_info), sender_key, sizeof(sender_key));

    const unsigned char recipient_key_info[] = { 0x85, 0x41, 0x01, 0xf6, 0x0a,
                                                 0x63, 0x4b, 0x65, 0x79, 0x10 };
    const unsigned char recipient_key[] = { 0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51,
                                            0x77, 0xcd, 0x67, 0x9a, 0xb4, 0xbc,
                                            0xec, 0x9d, 0x7d, 0xda };

    test_impl(NULL, 0, MASTER_SECRET, sizeof(MASTER_SECRET), recipient_key_info,
              sizeof(recipient_key_info), recipient_key, sizeof(recipient_key));

    const unsigned char common_iv_info[] = { 0x85, 0x40, 0xf6, 0x0a,
                                             0x62, 0x49, 0x56, 0x0d };
    const unsigned char common_iv[] = { 0xbe, 0x35, 0xae, 0x29, 0x7d,
                                        0x2d, 0xac, 0xe9, 0x10, 0xc5,
                                        0x2e, 0x99, 0xf9 };

    test_impl(NULL, 0, MASTER_SECRET, sizeof(MASTER_SECRET), common_iv_info,
              sizeof(common_iv_info), common_iv, sizeof(common_iv));
}

AVS_UNIT_TEST(avs_crypto_hkdf, test_vector_2_server) {
    const unsigned char sender_key_info[] = { 0x85, 0x41, 0x01, 0xf6, 0x0a,
                                              0x63, 0x4b, 0x65, 0x79, 0x10 };
    const unsigned char sender_key[] = { 0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51,
                                         0x77, 0xcd, 0x67, 0x9a, 0xb4, 0xbc,
                                         0xec, 0x9d, 0x7d, 0xda };

    test_impl(NULL, 0, MASTER_SECRET, sizeof(MASTER_SECRET), sender_key_info,
              sizeof(sender_key_info), sender_key, sizeof(sender_key));

    const unsigned char recipient_key_info[] = { 0x85, 0x41, 0x00, 0xf6, 0x0a,
                                                 0x63, 0x4b, 0x65, 0x79, 0x10 };
    const unsigned char recipient_key[] = { 0x32, 0x1b, 0x26, 0x94, 0x32, 0x53,
                                            0xc7, 0xff, 0xb6, 0x00, 0x3b, 0x0b,
                                            0x64, 0xd7, 0x40, 0x41 };

    test_impl(NULL, 0, MASTER_SECRET, sizeof(MASTER_SECRET), recipient_key_info,
              sizeof(recipient_key_info), recipient_key, sizeof(recipient_key));

    const unsigned char common_iv_info[] = { 0x85, 0x40, 0xf6, 0x0a,
                                             0x62, 0x49, 0x56, 0x0d };
    const unsigned char common_iv[] = { 0xbe, 0x35, 0xae, 0x29, 0x7d,
                                        0x2d, 0xac, 0xe9, 0x10, 0xc5,
                                        0x2e, 0x99, 0xf9 };

    test_impl(NULL, 0, MASTER_SECRET, sizeof(MASTER_SECRET), common_iv_info,
              sizeof(common_iv_info), common_iv, sizeof(common_iv));
}
