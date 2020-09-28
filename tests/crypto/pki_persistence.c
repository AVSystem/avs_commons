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

#include <avsystem/commons/avs_crypto_pki.h>
#include <avsystem/commons/avs_stream_inbuf.h>
#include <avsystem/commons/avs_stream_membuf.h>
#include <avsystem/commons/avs_unit_test.h>

const char CERTIFICATE_CHAIN_DATA[] =
        "\x00\x00\x00\x03" // number of entries
        // entry 1:
        "F"                // file source
        "\x00"             // version 0
        "\x00\x00\x00\x0a" // buffer size
        "cert1.der\0"      // buffer
        "\x00\x00\x00\x09" // file path length
        "\xff\xff\xff\xff" // password length (-1 => NULL)
        // entry 2:
        "P"                // path source
        "\x00"             // version 0
        "\x00\x00\x00\x0b" // buffer size
        "/etc/certs\0"     // buffer
        "\x00\x00\x00\x0a" // path length
                           // (note: path source does not have password field)
        // entry 3:
        "B"                // buffer source
        "\x00"             // version 0
        "\x00\x00\x00\x0a" // buffer size
        "dummy_cert"
        "\x00\x00\x00\x0a"  // data length
        "\xff\xff\xff\xff"; // password length (-1 => NULL)

AVS_UNIT_TEST(avs_crypto_pki_persistence, certificate_chain_persist) {
    avs_crypto_certificate_chain_info_t entry1 =
            avs_crypto_certificate_chain_info_from_file("cert1.der");
    avs_crypto_certificate_chain_info_t entry2 =
            avs_crypto_certificate_chain_info_from_path("/etc/certs");
    avs_crypto_certificate_chain_info_t entry3 =
            avs_crypto_certificate_chain_info_from_buffer("dummy_cert", 10);
    avs_crypto_certificate_chain_info_t entries12 =
            avs_crypto_certificate_chain_info_from_array(
                    &(const avs_crypto_certificate_chain_info_t[]) {
                            entry1, entry2 }[0],
                    2);

    AVS_LIST(avs_crypto_certificate_chain_info_t) list123 = NULL;
    *AVS_LIST_APPEND_NEW(avs_crypto_certificate_chain_info_t, &list123) =
            entries12;
    *AVS_LIST_APPEND_NEW(avs_crypto_certificate_chain_info_t, &list123) =
            entry3;
    avs_crypto_certificate_chain_info_t entries123 =
            avs_crypto_certificate_chain_info_from_list(list123);

    avs_stream_t *membuf = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_NOT_NULL(membuf);
    avs_persistence_context_t ctx =
            avs_persistence_store_context_create(membuf);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_certificate_chain_info_persist(&ctx, entries123));

    void *buf = NULL;
    size_t buf_size;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_membuf_take_ownership(membuf, &buf, &buf_size));
    AVS_UNIT_ASSERT_NOT_NULL(buf);
    AVS_UNIT_ASSERT_EQUAL(buf_size, sizeof(CERTIFICATE_CHAIN_DATA) - 1);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buf, CERTIFICATE_CHAIN_DATA, buf_size);

    avs_free(buf);
    avs_stream_cleanup(&membuf);
    AVS_LIST_CLEAR(&list123);
}

AVS_UNIT_TEST(avs_crypto_pki_persistence, certificate_chain_array_persistence) {
    avs_stream_inbuf_t inbuf = AVS_STREAM_INBUF_STATIC_INITIALIZER;
    avs_stream_inbuf_set_buffer(
            &inbuf, CERTIFICATE_CHAIN_DATA, sizeof(CERTIFICATE_CHAIN_DATA) - 1);
    avs_persistence_context_t restore_ctx =
            avs_persistence_restore_context_create((avs_stream_t *) &inbuf);

    avs_crypto_certificate_chain_info_t *array = NULL;
    size_t element_count;
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_certificate_chain_info_array_persistence(
            &restore_ctx, &array, &element_count));
    AVS_UNIT_ASSERT_NOT_NULL(array);
    AVS_UNIT_ASSERT_EQUAL(element_count, 3);

    AVS_UNIT_ASSERT_EQUAL(array[0].desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
    AVS_UNIT_ASSERT_EQUAL(array[0].desc.source, AVS_CRYPTO_DATA_SOURCE_FILE);
    AVS_UNIT_ASSERT_EQUAL_STRING(array[0].desc.info.file.filename, "cert1.der");
    AVS_UNIT_ASSERT_NULL(array[0].desc.info.file.password);

    AVS_UNIT_ASSERT_EQUAL(array[1].desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
    AVS_UNIT_ASSERT_EQUAL(array[1].desc.source, AVS_CRYPTO_DATA_SOURCE_PATH);
    AVS_UNIT_ASSERT_EQUAL_STRING(array[1].desc.info.path.path, "/etc/certs");

    AVS_UNIT_ASSERT_EQUAL(array[2].desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
    AVS_UNIT_ASSERT_EQUAL(array[2].desc.source, AVS_CRYPTO_DATA_SOURCE_BUFFER);
    AVS_UNIT_ASSERT_EQUAL(array[2].desc.info.buffer.buffer_size, 10);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(
            array[2].desc.info.buffer.buffer, "dummy_cert", 10);
    AVS_UNIT_ASSERT_NULL(array[2].desc.info.buffer.password);

    avs_stream_t *membuf = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_NOT_NULL(membuf);
    avs_persistence_context_t persist_ctx =
            avs_persistence_store_context_create(membuf);
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_certificate_chain_info_array_persistence(
            &persist_ctx, &array, &element_count));

    void *buf = NULL;
    size_t buf_size;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_membuf_take_ownership(membuf, &buf, &buf_size));
    AVS_UNIT_ASSERT_NOT_NULL(buf);
    AVS_UNIT_ASSERT_EQUAL(buf_size, sizeof(CERTIFICATE_CHAIN_DATA) - 1);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buf, CERTIFICATE_CHAIN_DATA, buf_size);

    avs_free(buf);
    avs_stream_cleanup(&membuf);
    avs_free(array);
}

AVS_UNIT_TEST(avs_crypto_pki_persistence, certificate_chain_list_persistence) {
    avs_stream_inbuf_t inbuf = AVS_STREAM_INBUF_STATIC_INITIALIZER;
    avs_stream_inbuf_set_buffer(
            &inbuf, CERTIFICATE_CHAIN_DATA, sizeof(CERTIFICATE_CHAIN_DATA) - 1);
    avs_persistence_context_t restore_ctx =
            avs_persistence_restore_context_create((avs_stream_t *) &inbuf);

    AVS_LIST(avs_crypto_certificate_chain_info_t) list = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_certificate_chain_info_list_persistence(
            &restore_ctx, &list));
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(list), 3);

    AVS_LIST(avs_crypto_certificate_chain_info_t) entry = list;
    AVS_UNIT_ASSERT_EQUAL(entry->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.source, AVS_CRYPTO_DATA_SOURCE_FILE);
    AVS_UNIT_ASSERT_EQUAL_STRING(entry->desc.info.file.filename, "cert1.der");
    AVS_UNIT_ASSERT_NULL(entry->desc.info.file.password);

    AVS_LIST_ADVANCE(&entry);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.source, AVS_CRYPTO_DATA_SOURCE_PATH);
    AVS_UNIT_ASSERT_EQUAL_STRING(entry->desc.info.path.path, "/etc/certs");

    AVS_LIST_ADVANCE(&entry);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERTIFICATE_CHAIN);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.source, AVS_CRYPTO_DATA_SOURCE_BUFFER);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.info.buffer.buffer_size, 10);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(
            entry->desc.info.buffer.buffer, "dummy_cert", 10);
    AVS_UNIT_ASSERT_NULL(entry->desc.info.buffer.password);

    avs_stream_t *membuf = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_NOT_NULL(membuf);
    avs_persistence_context_t persist_ctx =
            avs_persistence_store_context_create(membuf);
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_certificate_chain_info_list_persistence(
            &persist_ctx, &list));

    void *buf = NULL;
    size_t buf_size;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_membuf_take_ownership(membuf, &buf, &buf_size));
    AVS_UNIT_ASSERT_NOT_NULL(buf);
    AVS_UNIT_ASSERT_EQUAL(buf_size, sizeof(CERTIFICATE_CHAIN_DATA) - 1);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buf, CERTIFICATE_CHAIN_DATA, buf_size);

    avs_free(buf);
    avs_stream_cleanup(&membuf);
    AVS_LIST_CLEAR(&list);
}

const char CERT_REVOCATION_LIST_DATA[] =
        "\x00\x00\x00\x02" // number of entries
        // entry 1:
        "F"                // file source
        "\x00"             // version 0
        "\x00\x00\x00\x09" // buffer size
        "crl1.pem\0"       // buffer
        "\x00\x00\x00\x08" // file path length
        "\xff\xff\xff\xff" // password length (-1 => NULL)
        // entry 2:
        "B"                // buffer source
        "\x00"             // version 0
        "\x00\x00\x00\x08" // buffer size
        "fake_crl"
        "\x00\x00\x00\x08"  // data length
        "\xff\xff\xff\xff"; // password length (-1 => NULL)

AVS_UNIT_TEST(avs_crypto_pki_persistence, cert_revocation_list_persist) {
    avs_crypto_cert_revocation_list_info_t entry1 =
            avs_crypto_cert_revocation_list_info_from_file("crl1.pem");
    avs_crypto_cert_revocation_list_info_t entry2 =
            avs_crypto_cert_revocation_list_info_from_buffer("fake_crl", 8);
    avs_crypto_cert_revocation_list_info_t entries12 =
            avs_crypto_cert_revocation_list_info_from_array(
                    &(const avs_crypto_cert_revocation_list_info_t[]) {
                            entry1, entry2 }[0],
                    2);

    avs_stream_t *membuf = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_NOT_NULL(membuf);
    avs_persistence_context_t ctx =
            avs_persistence_store_context_create(membuf);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_cert_revocation_list_info_persist(&ctx, entries12));

    void *buf = NULL;
    size_t buf_size;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_membuf_take_ownership(membuf, &buf, &buf_size));
    AVS_UNIT_ASSERT_NOT_NULL(buf);
    AVS_UNIT_ASSERT_EQUAL(buf_size, sizeof(CERT_REVOCATION_LIST_DATA) - 1);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buf, CERT_REVOCATION_LIST_DATA, buf_size);

    avs_free(buf);
    avs_stream_cleanup(&membuf);
}

AVS_UNIT_TEST(avs_crypto_pki_persistence,
              cert_revocation_list_array_persistence) {
    avs_stream_inbuf_t inbuf = AVS_STREAM_INBUF_STATIC_INITIALIZER;
    avs_stream_inbuf_set_buffer(&inbuf,
                                CERT_REVOCATION_LIST_DATA,
                                sizeof(CERT_REVOCATION_LIST_DATA) - 1);
    avs_persistence_context_t restore_ctx =
            avs_persistence_restore_context_create((avs_stream_t *) &inbuf);

    avs_crypto_cert_revocation_list_info_t *array = NULL;
    size_t element_count;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_cert_revocation_list_info_array_persistence(
                    &restore_ctx, &array, &element_count));
    AVS_UNIT_ASSERT_NOT_NULL(array);
    AVS_UNIT_ASSERT_EQUAL(element_count, 2);

    AVS_UNIT_ASSERT_EQUAL(array[0].desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
    AVS_UNIT_ASSERT_EQUAL(array[0].desc.source, AVS_CRYPTO_DATA_SOURCE_FILE);
    AVS_UNIT_ASSERT_EQUAL_STRING(array[0].desc.info.file.filename, "crl1.pem");
    AVS_UNIT_ASSERT_NULL(array[0].desc.info.file.password);

    AVS_UNIT_ASSERT_EQUAL(array[1].desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
    AVS_UNIT_ASSERT_EQUAL(array[1].desc.source, AVS_CRYPTO_DATA_SOURCE_BUFFER);
    AVS_UNIT_ASSERT_EQUAL(array[1].desc.info.buffer.buffer_size, 8);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(
            array[1].desc.info.buffer.buffer, "fake_crl", 8);
    AVS_UNIT_ASSERT_NULL(array[1].desc.info.buffer.password);

    avs_stream_t *membuf = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_NOT_NULL(membuf);
    avs_persistence_context_t persist_ctx =
            avs_persistence_store_context_create(membuf);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_cert_revocation_list_info_array_persistence(
                    &persist_ctx, &array, &element_count));

    void *buf = NULL;
    size_t buf_size;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_membuf_take_ownership(membuf, &buf, &buf_size));
    AVS_UNIT_ASSERT_NOT_NULL(buf);
    AVS_UNIT_ASSERT_EQUAL(buf_size, sizeof(CERT_REVOCATION_LIST_DATA) - 1);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buf, CERT_REVOCATION_LIST_DATA, buf_size);

    avs_free(buf);
    avs_stream_cleanup(&membuf);
    avs_free(array);
}

AVS_UNIT_TEST(avs_crypto_pki_persistence,
              cert_revocation_list_list_persistence) {
    avs_stream_inbuf_t inbuf = AVS_STREAM_INBUF_STATIC_INITIALIZER;
    avs_stream_inbuf_set_buffer(&inbuf,
                                CERT_REVOCATION_LIST_DATA,
                                sizeof(CERT_REVOCATION_LIST_DATA) - 1);
    avs_persistence_context_t restore_ctx =
            avs_persistence_restore_context_create((avs_stream_t *) &inbuf);

    AVS_LIST(avs_crypto_cert_revocation_list_info_t) list = NULL;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_cert_revocation_list_info_list_persistence(&restore_ctx,
                                                                  &list));
    AVS_UNIT_ASSERT_EQUAL(AVS_LIST_SIZE(list), 2);

    AVS_LIST(avs_crypto_cert_revocation_list_info_t) entry = list;
    AVS_UNIT_ASSERT_EQUAL(entry->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.source, AVS_CRYPTO_DATA_SOURCE_FILE);
    AVS_UNIT_ASSERT_EQUAL_STRING(entry->desc.info.file.filename, "crl1.pem");
    AVS_UNIT_ASSERT_NULL(entry->desc.info.file.password);

    AVS_LIST_ADVANCE(&entry);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.type,
                          AVS_CRYPTO_SECURITY_INFO_CERT_REVOCATION_LIST);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.source, AVS_CRYPTO_DATA_SOURCE_BUFFER);
    AVS_UNIT_ASSERT_EQUAL(entry->desc.info.buffer.buffer_size, 8);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(
            entry->desc.info.buffer.buffer, "fake_crl", 8);
    AVS_UNIT_ASSERT_NULL(entry->desc.info.buffer.password);

    avs_stream_t *membuf = avs_stream_membuf_create();
    AVS_UNIT_ASSERT_NOT_NULL(membuf);
    avs_persistence_context_t persist_ctx =
            avs_persistence_store_context_create(membuf);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_cert_revocation_list_info_list_persistence(&persist_ctx,
                                                                  &list));

    void *buf = NULL;
    size_t buf_size;
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_membuf_take_ownership(membuf, &buf, &buf_size));
    AVS_UNIT_ASSERT_NOT_NULL(buf);
    AVS_UNIT_ASSERT_EQUAL(buf_size, sizeof(CERT_REVOCATION_LIST_DATA) - 1);
    AVS_UNIT_ASSERT_EQUAL_BYTES_SIZED(buf, CERT_REVOCATION_LIST_DATA, buf_size);

    avs_free(buf);
    avs_stream_cleanup(&membuf);
    AVS_LIST_CLEAR(&list);
}
