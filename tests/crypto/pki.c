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

#include <avs_commons_posix_init.h> // for struct stat::st_mtim

#include <inttypes.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <avsystem/commons/avs_base64.h>
#include <avsystem/commons/avs_crypto_pki.h>
#include <avsystem/commons/avs_http.h>
#include <avsystem/commons/avs_stream_membuf.h>
#include <avsystem/commons/avs_unit_test.h>
#include <avsystem/commons/avs_utils.h>

#include "pki.h"

#include "src/crypto/avs_crypto_utils.h"

AVS_UNIT_TEST(avs_crypto_pki_ec, test_ec_gen) {
    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    uint8_t secret_key[256];
    size_t secret_key_size = sizeof(secret_key);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_pki_ec_gen(prng_ctx, AVS_CRYPTO_PKI_ECP_GROUP_SECP256R1,
                                  secret_key, &secret_key_size));

    avs_crypto_prng_free(&prng_ctx);

    // The resulting data shall look like this:
    //
    // SEQUENCE (4 elem)                                     30 77
    //   INTEGER 1                                           02 01 01
    //   OCTET STRING (32 byte) [EC parameters]              04 20 [32bytesData]
    //   [0] (1 elem)                                        A0 0A
    //     OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1  06 08 2A 86 48 CE
    //                                                             3D 03 01 07
    //   [1] (1 elem)                                        A1 44
    //     BIT STRING (520 bit) [private key]                03 42 [66bytesData]
    //
    // (121 bytes total)

    AVS_UNIT_ASSERT_EQUAL(secret_key_size, 121);
    AVS_UNIT_ASSERT_EQUAL_BYTES(secret_key, "\x30\x77\x02\x01\x01\x04\x20");
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &secret_key[39],
            "\xA0\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\xA1\x44\x03\x42");
}

AVS_UNIT_TEST(avs_crypto_pki_ec, test_csr_create) {
#define TEST_CN "avs_crypto_pki_ec_test_csr_create"
    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    uint8_t secret_key[256];
    size_t secret_key_size = sizeof(secret_key);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_pki_ec_gen(prng_ctx, AVS_CRYPTO_PKI_ECP_GROUP_SECP256R1,
                                  secret_key, &secret_key_size));

    uint8_t csr[512];
    size_t csr_size = sizeof(csr);

    avs_crypto_client_key_info_t key_info =
            avs_crypto_client_key_info_from_buffer(secret_key, secret_key_size,
                                                   NULL);
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_pki_csr_create(
            prng_ctx, &key_info, "SHA256",
            AVS_CRYPTO_PKI_X509_NAME({ AVS_CRYPTO_PKI_X509_NAME_CN, TEST_CN }),
            csr, &csr_size));

    avs_crypto_prng_free(&prng_ctx);

    // The resulting data shall look like this:
    //
    // SEQUENCE (3 elem)                                         30 81 ??
    //   SEQUENCE (4 elem)                                       30 81 8E
    //     INTEGER 0                                             02 01 00
    //     SEQUENCE (1 elem)                                     30 2C
    //       SET (1 elem)                                        31 2A
    //         SEQUENCE (2 elem)                                 30 28
    //           OBJECT IDENTIFIER 2.5.4.3 commonName            06 03 55 04 03
    //           UTF8String avs_crypto_pki_ec_test_csr_create    0C 21 [string]
    //     SEQUENCE (2 elem)                                     30 59
    //       SEQUENCE (2 elem)                                   30 13
    //         OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey   06 07 2A 86 48
    //                                                           CE 3D 02 01
    //         OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1  06 08 2A 86 48
    //                                                           CE 3D 03 01 07
    //       BIT STRING (520 bit)                                03 42 [66bytes]
    //     [0] (0 elem)                                          A0 00
    //   SEQUENCE (1-2 elem)                                     30 (0A or 0C)
    //     OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 06 08 2A 86 48
    //                                                           CE 3D 04 03 02
    //     NULL                                                  05 00 (opt)
    //   BIT STRING (1 elem)                                     03 ?? 00
    //     SEQUENCE (2 elem)                                     30 ??
    //       INTEGER (max 256 bit)                               02 ??
    //       INTEGER (max 256 bit)                               02 ??

    AVS_UNIT_ASSERT_TRUE(csr_size > 169);
    AVS_UNIT_ASSERT_TRUE(csr_size <= 237);
    AVS_UNIT_ASSERT_EQUAL_BYTES(csr, "\x30\x81");
    AVS_UNIT_ASSERT_EQUAL(csr[2], csr_size - 3);
    AVS_UNIT_ASSERT_EQUAL_BYTES(
            &csr[3], "\x30\x81\x8E\x02\x01\x00\x30\x2C\x31\x2A\x30\x28\x06\x03"
                     "\x55\x04\x03\x0C\x21" TEST_CN
                     "\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06"
                     "\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42");
    AVS_UNIT_ASSERT_EQUAL_BYTES(&csr[146], "\xA0\x00\x30");
    AVS_UNIT_ASSERT_TRUE(csr[149] == 0x0A || csr[149] == 0x0C);
    bool has_additional_null_md = (csr[149] == 0x0C);
    AVS_UNIT_ASSERT_EQUAL_BYTES(&csr[150],
                                "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02");
    size_t signature_offset;
    if (has_additional_null_md) {
        AVS_UNIT_ASSERT_EQUAL_BYTES(&csr[160], "\x05\x00");
        signature_offset = 162;
    } else {
        signature_offset = 160;
    }
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset], 0x03);
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset + 1],
                          csr_size - signature_offset - 2);
    AVS_UNIT_ASSERT_EQUAL_BYTES(&csr[signature_offset + 2], "\x00\x30");
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset + 4],
                          csr_size - signature_offset - 5);
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset + 5], 0x02);
    AVS_UNIT_ASSERT_EQUAL(csr[signature_offset + 7 + csr[signature_offset + 6]],
                          0x02);
    AVS_UNIT_ASSERT_EQUAL(
            csr[signature_offset + 6]
                    + csr[signature_offset + 8 + csr[signature_offset + 6]],
            csr_size - signature_offset - 9);
#undef TEST_CN
}

AVS_UNIT_TEST(avs_crypto_pki, avs_crypto_client_cert_expiration_date) {
    static const char CERT_PATH[] = "../certs/client.crt";

    struct stat file_stat;
    AVS_UNIT_ASSERT_SUCCESS(stat(CERT_PATH, &file_stat));
    avs_time_real_t file_mtime = {
        .since_real_epoch = {
            .seconds = file_stat.st_mtim.tv_sec,
            .nanoseconds = (int32_t) file_stat.st_mtim.tv_nsec
        }
    };

    avs_crypto_client_cert_info_t cert_info =
            avs_crypto_client_cert_info_from_file(CERT_PATH);
    avs_time_real_t cert_validity =
            avs_crypto_client_cert_expiration_date(&cert_info);

    AVS_UNIT_ASSERT_TRUE(avs_time_real_valid(cert_validity));
    double cert_relative_validity = avs_time_duration_to_fscalar(
            avs_time_real_diff(cert_validity, file_mtime), AVS_TIME_S);

    // the cert is supposed to be valid for 9999 days since generation
    // test that it is, with up to 30 second difference allowed
    AVS_UNIT_ASSERT_TRUE(cert_relative_validity >= 9999.0 * 86400.0 - 30.0);
    AVS_UNIT_ASSERT_TRUE(cert_relative_validity <= 9999.0 * 86400.0 + 30.0);
}

static void
load_pem_from_url(const char *raw_url, uint8_t **out_buf, size_t *out_size) {
    assert(out_buf && !*out_buf && out_size);

    avs_url_t *url = avs_url_parse(raw_url);
    AVS_UNIT_ASSERT_NOT_NULL(url);

    avs_http_t *http = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    AVS_UNIT_ASSERT_NOT_NULL(http);

    avs_crypto_prng_ctx_t *prng_ctx = avs_crypto_prng_new(NULL, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(prng_ctx);

    const avs_net_ssl_configuration_t SSL_CONFIG = {
        .prng_ctx = prng_ctx
    };
    avs_http_ssl_configuration(http, &SSL_CONFIG);

    avs_stream_t *stream = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, http, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));

    avs_stream_t *membuf = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_NOT_NULL(membuf);

    char buf[128];
    bool finished = false;
    while (!finished) {
        AVS_UNIT_ASSERT_SUCCESS(
                avs_stream_getline(stream, NULL, &finished, buf, sizeof(buf)));
        // trim the line
        const char *begin = buf + strspn(buf, AVS_SPACES);
        size_t length = strcspn(begin, AVS_SPACES);
        // ignore PEM begin/end lines
        if (strncmp(begin, "-----", 5) != 0) {
            AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(membuf, begin, length));
        }
    }
    avs_stream_cleanup(&stream);
    avs_http_free(http);
    avs_crypto_prng_free(&prng_ctx);
    avs_url_free(url);

    // terminating nullbyte
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write(membuf, "", 1));
    void *data = NULL;
    size_t length;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_membuf_take_ownership(membuf, &data, &length));
    avs_stream_cleanup(&membuf);

    size_t estimate = avs_base64_estimate_decoded_size(length);
    *out_buf = (uint8_t *) avs_malloc(estimate);
    AVS_UNIT_ASSERT_NOT_NULL(*out_buf);
    AVS_UNIT_ASSERT_SUCCESS(avs_base64_decode(out_size, *out_buf, estimate,
                                              (const char *) data));
    avs_free(data);
}

AVS_UNIT_TEST(avs_crypto_pki_pkcs7, pkcs7_parse_success) {
    uint8_t *buf = NULL;
    size_t buf_size;
    load_pem_from_url("https://github.com/openssl/openssl/raw/"
                      "dd0164e7565bb14fac193aea4c2c37714bf66d56/test/pkcs7.pem",
                      &buf, &buf_size);

    AVS_LIST(avs_crypto_trusted_cert_info_t) certs = NULL;
    AVS_LIST(avs_crypto_cert_revocation_list_info_t) crls = NULL;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_parse_pkcs7_certs_only(&certs, &crls, buf, buf_size));
    avs_free(buf);

    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(certs), 2);

    avs_crypto_trusted_cert_info_t *cert1 = AVS_LIST_NTH(certs, 0);
    AVS_UNIT_ASSERT_EQUAL(cert1->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT);
    AVS_UNIT_ASSERT_EQUAL(cert1->desc.source, AVS_CRYPTO_DATA_SOURCE_BUFFER);
    AVS_UNIT_ASSERT_EQUAL(cert1->desc.info.buffer.buffer_size, 1276);

    avs_crypto_trusted_cert_info_t *cert2 = AVS_LIST_NTH(certs, 1);
    AVS_UNIT_ASSERT_EQUAL(cert2->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_TRUSTED_CERT);
    AVS_UNIT_ASSERT_EQUAL(cert2->desc.source, AVS_CRYPTO_DATA_SOURCE_BUFFER);
    AVS_UNIT_ASSERT_EQUAL(cert2->desc.info.buffer.buffer_size, 637);

    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(crls), 2);

    avs_crypto_cert_revocation_list_info_t *crl1 = AVS_LIST_NTH(crls, 0);
    AVS_UNIT_ASSERT_EQUAL(crl1->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
    AVS_UNIT_ASSERT_EQUAL(crl1->desc.source, AVS_CRYPTO_DATA_SOURCE_BUFFER);
    AVS_UNIT_ASSERT_EQUAL(crl1->desc.info.buffer.buffer_size, 299);

    avs_crypto_cert_revocation_list_info_t *crl2 = AVS_LIST_NTH(crls, 1);
    AVS_UNIT_ASSERT_EQUAL(crl2->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
    AVS_UNIT_ASSERT_EQUAL(crl2->desc.source, AVS_CRYPTO_DATA_SOURCE_BUFFER);
    AVS_UNIT_ASSERT_EQUAL(crl2->desc.info.buffer.buffer_size, 296);

    // Now let's check if it's loadable
    avs_crypto_trusted_cert_info_t cert_info =
            avs_crypto_trusted_cert_info_from_list(certs);
    avs_crypto_cert_revocation_list_info_t crl_info =
            avs_crypto_cert_revocation_list_info_from_list(crls);
    assert_trust_store_loadable(&cert_info, &crl_info);

    AVS_LIST_CLEAR(&certs);
    AVS_LIST_CLEAR(&crls);
}

AVS_UNIT_TEST(avs_crypto_pki_pkcs7, pkcs7_parse_failure) {
    uint8_t *buf = NULL;
    size_t buf_size;
    // This file contains encapsulated data and signerInfos
    load_pem_from_url(
            "https://github.com/openssl/openssl/raw/"
            "dd0164e7565bb14fac193aea4c2c37714bf66d56/test/pkcs7-1.pem",
            &buf, &buf_size);
    AVS_UNIT_ASSERT_EQUAL(buf_size, 597);

    AVS_LIST(avs_crypto_trusted_cert_info_t) certs = NULL;
    AVS_LIST(avs_crypto_cert_revocation_list_info_t) crls = NULL;
    // this file has a superfluous byte in it
    AVS_UNIT_ASSERT_FAILED(
            avs_crypto_parse_pkcs7_certs_only(&certs, &crls, buf, buf_size));
    // but also contains encapsulated data and signerInfos
    AVS_UNIT_ASSERT_FAILED(avs_crypto_parse_pkcs7_certs_only(&certs, &crls, buf,
                                                             buf_size - 1));

    avs_free(buf);
}
