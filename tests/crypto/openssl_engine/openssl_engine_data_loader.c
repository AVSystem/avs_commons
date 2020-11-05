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

#include <avs_commons_posix_init.h>

#include <avsystem/commons/avs_crypto_pki.h>
#include <avsystem/commons/avs_unit_test.h>
#include <avsystem/commons/avs_utils.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../pki.h"

#include "libp11.h"

#include "src/crypto/avs_crypto_global.h"
#include "src/crypto/openssl/avs_openssl_common.h"
#include "src/crypto/openssl/avs_openssl_data_loader.h"
#include "src/crypto/openssl/avs_openssl_engine.h"

#ifdef MODULE_NAME
#    undef MODULE_NAME
#endif // MODULE_NAME
#define MODULE_NAME openssl_engine_test
#include <avs_x_log_config.h>

static char TOKEN[] = "XXXXXX";
static char PIN[] = "0001password";
static char PUBLIC_KEY_PATH[] = "/tmp/public_key_XXXXXX.der";
static const char *KEY_PAIR_LABEL = "my_key";
static char OPENSSL_ENGINE_CONF_FILE[] = "/tmp/openssl_engine_XXXXXX.conf";
static char *PKCS11_MODULE_PATH = NULL;
static const char *OPENSSL_ENGINE_CONF_TEMPLATE =
        "openssl_conf = openssl_init\n"
        ".include /etc/ssl/openssl.cnf\n\n"
        "[openssl_init]\n"
        "engines=engine_section\n\n"
        "[engine_section]\n"
        "pkcs11 = pkcs11_section\n\n"
        "[pkcs11_section]\n"
        "engine_id = pkcs11\n"
        "MODULE_PATH = %s\n"
        "init = 0;\n";
static char OPENSSL_ENGINE_CONF_STR[300];

static void system_cleanup(void) {
    char delete_token_command[50];
    AVS_UNIT_ASSERT_TRUE(
            snprintf(delete_token_command, sizeof(delete_token_command),
                     "softhsm2-util --delete-token --token %s", TOKEN)
            > 0);
    AVS_UNIT_ASSERT_SUCCESS(system(delete_token_command));

    AVS_UNIT_ASSERT_SUCCESS(unlink(PUBLIC_KEY_PATH));
    AVS_UNIT_ASSERT_SUCCESS(unlink(OPENSSL_ENGINE_CONF_FILE));
}

AVS_UNIT_SUITE_INIT(backend_openssl_engine, verbose) {
    (void) verbose;

    PKCS11_MODULE_PATH = getenv("PKCS11_MODULE_PATH");
    AVS_UNIT_ASSERT_NOT_NULL(PKCS11_MODULE_PATH);

    AVS_UNIT_ASSERT_TRUE(
            snprintf(OPENSSL_ENGINE_CONF_STR, sizeof(OPENSSL_ENGINE_CONF_STR),
                     OPENSSL_ENGINE_CONF_TEMPLATE, PKCS11_MODULE_PATH)
            > 0);

    AVS_UNIT_ASSERT_NOT_EQUAL(mkstemps(OPENSSL_ENGINE_CONF_FILE, 5), -1);
    FILE *f = fopen(OPENSSL_ENGINE_CONF_FILE, "w");
    fwrite(OPENSSL_ENGINE_CONF_STR, sizeof(char),
           strlen(OPENSSL_ENGINE_CONF_STR), f);
    fclose(f);

    AVS_UNIT_ASSERT_NOT_EQUAL(mkstemps(PUBLIC_KEY_PATH, 4), -1);

    char soft_hsm_command[200];
    char pkcs11_command_1[200];
    char pkcs11_command_2[200];

    AVS_UNIT_ASSERT_TRUE(mkstemp(TOKEN) >= 0);
    unlink(TOKEN);

    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(soft_hsm_command, sizeof(soft_hsm_command),
                                "softhsm2-util --init-token --free --label %s "
                                "--pin %s --so-pin %s ",
                                TOKEN, PIN, PIN)
            > 0);
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(pkcs11_command_1, sizeof(pkcs11_command_1),
                                "pkcs11-tool --module %s --token %s "
                                "--login --pin %s --keypairgen "
                                "--key-type rsa:2048 --label %s",
                                PKCS11_MODULE_PATH, TOKEN, PIN, KEY_PAIR_LABEL)
            > 0);
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(pkcs11_command_2, sizeof(pkcs11_command_2),
                                "pkcs11-tool --module %s -r --type "
                                "pubkey --token %s --label %s -o %s",
                                PKCS11_MODULE_PATH, TOKEN, KEY_PAIR_LABEL,
                                PUBLIC_KEY_PATH)
            > 0);

    AVS_UNIT_ASSERT_SUCCESS(system(soft_hsm_command));
    AVS_UNIT_ASSERT_SUCCESS(system(pkcs11_command_1));
    AVS_UNIT_ASSERT_SUCCESS(system(pkcs11_command_2));

    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_ensure_global_state());

    AVS_UNIT_ASSERT_SUCCESS(atexit(system_cleanup));
}

void assert_trust_store_loadable(
        const avs_crypto_certificate_chain_info_t *certs,
        const avs_crypto_cert_revocation_list_info_t *crls) {
    X509_STORE *store = X509_STORE_new();
    AVS_UNIT_ASSERT_NOT_NULL(store);
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_ca_certs(store, certs));
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_crls(store, crls));
    X509_STORE_free(store);
}

static EVP_PKEY *load_pubkey() {
    FILE *public_key_file = fopen(PUBLIC_KEY_PATH, "rb");
    AVS_UNIT_ASSERT_NOT_NULL(public_key_file);
    EVP_PKEY *public_key = d2i_PUBKEY_fp(public_key_file, NULL);
    AVS_UNIT_ASSERT_NOT_NULL(public_key);
    AVS_UNIT_ASSERT_SUCCESS(fclose(public_key_file));
    return public_key;
}

static void test_engine_key_pair(EVP_PKEY *private_key, EVP_PKEY *public_key) {
    // Text preparation
    unsigned char original_text[256] = "Text to be encrypted.";
    int original_text_len = (int) strlen((const char *) original_text);
    memset((void *) (original_text + original_text_len), 'X',
           255 - original_text_len);
    original_text[255] = 0;
    original_text_len = 256;

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
    EVP_PKEY_CTX_free(encrypt_ctx);

    // Decryption
    //
    // Without this, a memory leak is triggered in the pkcs11 engine's key URL
    // parsing function...
    AVS_UNIT_ASSERT_EQUAL(
            ENGINE_ctrl_cmd(global_engine, "FORCE_LOGIN", 0, NULL, NULL, 0), 1);
    AVS_UNIT_ASSERT_EQUAL(ENGINE_init(global_engine), 1);
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(private_key, global_engine);
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
    OPENSSL_free(encrypted_text);
    AVS_UNIT_ASSERT_EQUAL(ENGINE_finish(global_engine), 1);

    // Check
    AVS_UNIT_ASSERT_EQUAL(decrypted_text_len, original_text_len);
    AVS_UNIT_ASSERT_EQUAL(strncmp((const char *) original_text,
                                  (const char *) decrypted_text,
                                  original_text_len),
                          0);
}

static char *
make_pkcs11_uri(const char *token, const char *label, const char *pin) {
    const char *uri_template = "pkcs11:token=%s;object=%s?pin-value=%s";
    size_t uri_buffer_size = strlen(uri_template) + strlen(label) + strlen(PIN)
                             + strlen(TOKEN) - (3 * strlen("%s")) + 1;
    char *uri = (char *) avs_malloc(uri_buffer_size);
    AVS_UNIT_ASSERT_NOT_NULL(uri);

    AVS_UNIT_ASSERT_TRUE(avs_simple_snprintf(uri, uri_buffer_size, uri_template,
                                             token, label, pin)
                         >= 0);

    return uri;
}

AVS_UNIT_TEST(backend_openssl_engine, key_loading_from_pkcs11) {
    // Load public key
    EVP_PKEY *public_key = load_pubkey();

    // Load private key from engine
    char *key_uri = make_pkcs11_uri(TOKEN, KEY_PAIR_LABEL, PIN);
    const avs_crypto_private_key_info_t private_key_info =
            avs_crypto_private_key_info_from_engine(key_uri);
    EVP_PKEY *private_key = NULL;
    AVS_UNIT_ASSERT_SUCCESS(_avs_crypto_openssl_load_private_key(
            &private_key, &private_key_info));
    avs_free(key_uri);

    // Check
    test_engine_key_pair(private_key, public_key);

    // Cleanup
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
}

AVS_UNIT_TEST(backend_openssl_engine, cert_loading_from_pkcs11) {
    // System preparation
    char openssl_cli_command[300];
    char pkcs11_command[200];

    char cert_path[] = "/tmp/cert_XXXXXX.der";
    const char *cert_label = "my_cert";

    AVS_UNIT_ASSERT_NOT_EQUAL(mkstemps(cert_path, 4), -1);

    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(
                    openssl_cli_command, sizeof(openssl_cli_command),
                    "OPENSSL_CONF=%s openssl req -new -x509 "
                    "-days 365 -subj '/CN=%s' -sha256 -engine pkcs11 "
                    "-keyform engine -key 'pkcs11:token=%s;object=%s"
                    "?pin-value=%s' -outform der -out %s",
                    OPENSSL_ENGINE_CONF_FILE, KEY_PAIR_LABEL, TOKEN,
                    KEY_PAIR_LABEL, PIN, cert_path)
            > 0);
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(
                    pkcs11_command, sizeof(pkcs11_command),
                    "pkcs11-tool --module %s "
                    "--pin %s -w %s --type cert --label %s --token %s",
                    PKCS11_MODULE_PATH, PIN, cert_path, cert_label, TOKEN)
            > 0);

    AVS_UNIT_ASSERT_SUCCESS(system(openssl_cli_command));
    AVS_UNIT_ASSERT_SUCCESS(system(pkcs11_command));

    // Loading certificate
    char *cert_uri = make_pkcs11_uri(TOKEN, cert_label, PIN);
    const avs_crypto_certificate_chain_info_t cert_info =
            avs_crypto_certificate_chain_info_from_engine(cert_uri);
    X509 *cert = NULL;
    AVS_UNIT_ASSERT_SUCCESS(
            _avs_crypto_openssl_load_first_client_cert(&cert, &cert_info));
    AVS_UNIT_ASSERT_NOT_NULL(cert);

    // Verifying certificate
    EVP_PKEY *public_key = load_pubkey();
    AVS_UNIT_ASSERT_TRUE(X509_verify(cert, public_key));

    // Memory cleanup
    X509_free(cert);
    EVP_PKEY_free(public_key);
    avs_free((char *) (intptr_t) cert_uri);

    // System cleanup
    AVS_UNIT_ASSERT_SUCCESS(unlink(cert_path));
}

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES
static int check_matching_pkcs11_objects_qty(const char *label) {
    char pkcs11_command[300];
    AVS_UNIT_ASSERT_TRUE(
            avs_simple_snprintf(
                    pkcs11_command, sizeof(pkcs11_command),
                    "pkcs11-tool --module %s --token %s "
                    "--login --pin %s --list-objects | grep %s | wc -l",
                    PKCS11_MODULE_PATH, TOKEN, PIN, label)
            > 0);
    FILE *result_pipe = popen(pkcs11_command, "r");
    AVS_UNIT_ASSERT_NOT_NULL(result_pipe);
    int result;
    AVS_UNIT_ASSERT_EQUAL(fscanf(result_pipe, "%d", &result), 1);
    AVS_UNIT_ASSERT_SUCCESS(pclose(result_pipe));

    return result;
}

AVS_UNIT_TEST(backend_openssl_engine, pkcs11_key_pair_generation_and_removal) {
    char *label = "label1";
    char *key_uri = make_pkcs11_uri(TOKEN, label, PIN);

    AVS_UNIT_ASSERT_EQUAL(check_matching_pkcs11_objects_qty(label), 0);
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_pki_engine_key_gen(key_uri));

    AVS_UNIT_ASSERT_EQUAL(check_matching_pkcs11_objects_qty(label), 2);

    // Load private key from engine
    AVS_UNIT_ASSERT_EQUAL(ENGINE_init(global_engine), 1);
    EVP_PKEY *private_key =
            ENGINE_load_private_key(global_engine, key_uri, NULL, NULL);
    ENGINE_finish(global_engine);

    // Load public key from engine
    AVS_UNIT_ASSERT_EQUAL(ENGINE_init(global_engine), 1);
    EVP_PKEY *public_key =
            ENGINE_load_public_key(global_engine, key_uri, NULL, NULL);
    ENGINE_finish(global_engine);

    test_engine_key_pair(private_key, public_key);

    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);

    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_pki_engine_key_rm(key_uri));

    AVS_UNIT_ASSERT_EQUAL(check_matching_pkcs11_objects_qty(label), 0);

    avs_free(key_uri);
}

AVS_UNIT_TEST(backend_openssl_engine, pkcs11_cert_storage_and_removal) {
    AVS_LIST(avs_crypto_certificate_chain_info_t) certs = NULL;
    AVS_LIST(avs_crypto_cert_revocation_list_info_t) crls = NULL;
    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_parse_pkcs7_certs_only(
            &certs, &crls, EXAMPLE_CORRECT_PKCS7_DATA,
            sizeof(EXAMPLE_CORRECT_PKCS7_DATA) - 1));
    AVS_UNIT_ASSERT_NOT_NULL(certs);
    AVS_UNIT_ASSERT_TRUE(
            avs_time_real_valid(avs_crypto_certificate_expiration_date(certs)));

    char *label = "label2";
    char *cert_uri = make_pkcs11_uri(TOKEN, label, PIN);

    AVS_UNIT_ASSERT_EQUAL(check_matching_pkcs11_objects_qty(label), 0);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_crypto_pki_engine_certificate_store(cert_uri, certs));

    AVS_UNIT_ASSERT_EQUAL(check_matching_pkcs11_objects_qty(label), 1);

    avs_crypto_certificate_chain_info_t engine_cert =
            avs_crypto_certificate_chain_info_from_engine(cert_uri);
    AVS_UNIT_ASSERT_TRUE(avs_time_real_equal(
            avs_crypto_certificate_expiration_date(certs),
            avs_crypto_certificate_expiration_date(&engine_cert)));

    AVS_UNIT_ASSERT_SUCCESS(avs_crypto_pki_engine_certificate_rm(cert_uri));

    AVS_UNIT_ASSERT_EQUAL(check_matching_pkcs11_objects_qty(label), 0);

    AVS_LIST_CLEAR(&certs);
    AVS_LIST_CLEAR(&crls);

    avs_free(cert_uri);
}
#endif // AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES
