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

#define AVS_STREAM_STREAM_FILE_C

#include <avs_commons_posix_init.h>

#include <avsystem/commons/avs_unit_test.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../pki.h"

#include "src/crypto/avs_global.h"
#include "src/crypto/openssl/avs_openssl_common.h"
#include "src/crypto/openssl/avs_openssl_data_loader.h"

void assert_trust_store_loadable(
        const avs_crypto_certificate_chain_info_t *certs,
        const avs_crypto_cert_revocation_list_info_t *crls) {
    X509_STORE *store = X509_STORE_new();
    AVS_UNIT_ASSERT_NOT_NULL(store);
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_ca_certs(store, certs));
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_crls(store, crls));
    X509_STORE_free(store);
}

AVS_UNIT_TEST(backend_openssl_engine, key_loading_from_pkcs11) {
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_ensure_global_state());

    // System preparation
    char soft_hsm_command[200];
    char pkcs11_command_1[200];
    char pkcs11_command_2[200];
    char token[] = "XXXXXX";
    char public_key_path[] = "/tmp/public_key_XXXXXX.der";

    const char *pin = "0001password";
    const char *label = "my_key";

    AVS_UNIT_ASSERT_NOT_EQUAL(mkstemps(public_key_path, 4), -1);
    memcpy(token, public_key_path + 16, 6);
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(soft_hsm_command, sizeof(soft_hsm_command),
                                "softhsm2-util --init-token --free --label %s "
                                "--pin %s --so-pin %s ",
                                token, pin, pin)
            > 0);
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(pkcs11_command_1, sizeof(pkcs11_command_1),
                                "pkcs11-tool --module "
                                "/usr/lib/softhsm/libsofthsm2.so --token %s "
                                "--login --pin %s --keypairgen "
                                "--key-type rsa:2048 --label %s",
                                token, pin, label)
            > 0);
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(pkcs11_command_2, sizeof(pkcs11_command_2),
                                "pkcs11-tool --module "
                                "/usr/lib/softhsm/libsofthsm2.so -r --type "
                                "pubkey --token %s --label %s -o %s",
                                token, label, public_key_path)
            > 0);

    AVS_UNIT_ASSERT_SUCCESS(system(soft_hsm_command));
    AVS_UNIT_ASSERT_SUCCESS(system(pkcs11_command_1));
    AVS_UNIT_ASSERT_SUCCESS(system(pkcs11_command_2));

    // Text preparation
    unsigned char original_text[256] = "Text to be encrypted.";
    int original_text_len = (int) strlen((const char *) original_text);
    memset((void *) (original_text + original_text_len), 'X',
           255 - original_text_len);
    original_text[255] = 0;
    original_text_len = 256;

    // Loading public key from file
    FILE *public_key_file = fopen(public_key_path, "rb");
    AVS_UNIT_ASSERT_NOT_NULL(public_key_file);
    EVP_PKEY *public_key = d2i_PUBKEY_fp(public_key_file, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(public_key);

    // Encryption
    EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(public_key, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(encrypt_ctx);
    AVS_UNIT_ASSERT_EQUAL(EVP_PKEY_encrypt_init(encrypt_ctx), 1);
    AVS_UNIT_ASSERT_EQUAL(
            EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx, RSA_NO_PADDING), 1);
    size_t encrypted_text_len;
    AVS_UNIT_ASSERT_EQUAL(EVP_PKEY_encrypt(encrypt_ctx, NULL,
                                           &encrypted_text_len, original_text,
                                           original_text_len),
                          1);
    unsigned char *encrypted_text =
            (unsigned char *) OPENSSL_malloc(encrypted_text_len);
    AVS_UNIT_ASSERT_EQUAL(EVP_PKEY_encrypt(encrypt_ctx, encrypted_text,
                                           &encrypted_text_len, original_text,
                                           original_text_len),
                          1);
    AVS_UNIT_ASSERT_SUCCESS(fclose(public_key_file));
    EVP_PKEY_CTX_free(encrypt_ctx);
    EVP_PKEY_free(public_key);

    const char *query_template = "pkcs11:token=%s;object=%s;pin-value=%s";
    size_t query_buffer_size = strlen(query_template) + strlen(label)
                               + strlen(pin) + strlen(token)
                               - (3 * strlen("%s")) + 1;
    char *query = (char *) avs_malloc(query_buffer_size);
    AVS_UNIT_ASSERT_NOT_NULL(query);

    AVS_UNIT_ASSERT_TRUE(avs_simple_snprintf(query, query_buffer_size,
                                             query_template, token, label, pin)
                         >= 0);

    const avs_crypto_private_key_info_t private_key_info =
            avs_crypto_private_key_info_from_engine(query);
    EVP_PKEY *private_key = NULL;
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_private_key(
            &private_key, &private_key_info));
    avs_free(query);

    AVS_UNIT_ASSERT_NOT_NULL(private_key);

    // Decryption with private key on HSM
    ENGINE *engine = ENGINE_by_id("pkcs11");
    AVS_UNIT_ASSERT_NOT_NULL(engine);
    // Without this, a memory leak is triggered in the pkcs11 engine's key URL
    // parsing function...
    AVS_UNIT_ASSERT_EQUAL(
            ENGINE_ctrl_cmd(engine, "FORCE_LOGIN", 0, NULL, NULL, 0), 1);
    AVS_UNIT_ASSERT_EQUAL(ENGINE_init(engine), 1);
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(private_key, engine);
    AVS_UNIT_ASSERT_NOT_NULL(decrypt_ctx);
    AVS_UNIT_ASSERT_EQUAL(EVP_PKEY_decrypt_init(decrypt_ctx), 1);
    AVS_UNIT_ASSERT_EQUAL(
            EVP_PKEY_CTX_set_rsa_padding(decrypt_ctx, RSA_NO_PADDING), 1);

    unsigned char decrypted_text[256];
    size_t decrypted_text_len = original_text_len;
    AVS_UNIT_ASSERT_EQUAL(EVP_PKEY_decrypt(decrypt_ctx, decrypted_text,
                                           &decrypted_text_len, encrypted_text,
                                           encrypted_text_len),
                          1);
    EVP_PKEY_CTX_free(decrypt_ctx);
    EVP_PKEY_free(private_key);
    AVS_UNIT_ASSERT_EQUAL(ENGINE_finish(engine), 1);

    AVS_UNIT_ASSERT_EQUAL(decrypted_text_len, original_text_len);

    AVS_UNIT_ASSERT_EQUAL(strncmp((const char *) original_text,
                                  (const char *) decrypted_text,
                                  original_text_len),
                          0);

    OPENSSL_free(encrypted_text);
    ENGINE_free(engine);

    // System cleanup
    char delete_token_command[50];
    AVS_UNIT_ASSERT_TRUE(
            snprintf(delete_token_command, sizeof(delete_token_command),
                     "softhsm2-util --delete-token --token %s", token)
            > 0);
    AVS_UNIT_ASSERT_SUCCESS(system(delete_token_command));
    AVS_UNIT_ASSERT_SUCCESS(unlink(public_key_path));
}
