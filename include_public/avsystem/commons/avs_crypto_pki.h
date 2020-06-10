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

#ifndef AVS_COMMONS_CRYPTO_PKI_H
#define AVS_COMMONS_CRYPTO_PKI_H

#include <stdint.h>

#include <avsystem/commons/avs_commons_config.h>
#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_prng.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This struct is for internal use only and should not be filled manually. One
 * should construct appropriate instances of:
 * - @ref avs_crypto_trusted_cert_info_t,
 * - @ref avs_crypto_client_cert_info_t,
 * - @ref avs_crypto_client_key_info_t
 * using methods declared below.
 */
typedef struct {
    int type;
    int source;
    union {
        struct {
            const char *filename;
            const char *password;
        } file;
        struct {
            const char *path;
        } path;
        struct {
            const void *buffer;
            const char *password;
            size_t buffer_size;
        } buffer;
    } info;
} avs_crypto_security_info_union_t;

typedef struct {
    avs_crypto_security_info_union_t desc;
} avs_crypto_trusted_cert_info_t;

/**
 * Creates CA chain descriptor used later on to load CA chain from file @p
 * filename.
 *
 * NOTE: File loading is conducted by using: fopen(), fread(), ftell() and
 * fclose(), thus the platform shall implement them. On embededd platforms it
 * may be preferable to use @ref avs_crypto_trusted_cert_info_from_buffer()
 * instead.
 *
 * @param filename  File from which the CA chain shall be loaded.
 */
avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_file(const char *filename);

/**
 * Creates CA chain descriptor used later on to load CA chain from specified @p
 * path. The loading procedure attempts to treat each file as CA certificate,
 * attempts to load, and fails only if no CA certificate could be loaded.
 *
 * NOTE: File loading and discovery is conducted by using: fopen(), fseek(),
 * fread(), ftell(), fclose(), opendir(), readdir(), closedir() and stat(), thus
 * the platform shall implement them. On embededd platforms it may be preferable
 * to use @ref avs_crypto_trusted_cert_info_from_buffer() instead.
 *
 * @param path  Path from which the CA chain shall be loaded.
 *
 * WARNING: accepted file formats are backend-specific.
 */
avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_path(const char *path);

/**
 * Creates CA chain descriptor used later on to load CA chain from memory
 * @p buffer.
 *
 * NOTE: Lifetime of the @p buffer must be as long as lifetime of any (D)TLS
 * sockets that used this descriptor to perform configuration.
 *
 * @param buffer        Buffer where loaded CA chain is stored.
 * @param buffer_size   Size in bytes of the buffer.
 */
avs_crypto_trusted_cert_info_t
avs_crypto_trusted_cert_info_from_buffer(const void *buffer,
                                         size_t buffer_size);

typedef struct {
    avs_crypto_security_info_union_t desc;
} avs_crypto_client_key_info_t;

/**
 * Creates private key descriptor used later on to load private key from
 * file @p filename.
 *
 * @param filename  Name of the file to be loaded.
 * @param password  Optional password if present, or NULL.
 */
avs_crypto_client_key_info_t
avs_crypto_client_key_info_from_file(const char *filename,
                                     const char *password);

/**
 * Creates private key descriptor used later on to load private key from
 * @p buffer.
 *
 * @param buffer      Buffer in which private key is stored.
 * @param buffer_size Size of the buffer contents in bytes.
 * @param password    Optional password if present, or NULL.
 */
avs_crypto_client_key_info_t avs_crypto_client_key_info_from_buffer(
        const void *buffer, size_t buffer_size, const char *password);

typedef struct {
    avs_crypto_security_info_union_t desc;
} avs_crypto_client_cert_info_t;

/**
 * Creates client certificate descriptor used later on to load client
 * certificate from file @p filename.
 *
 * @param filename  Name of the file to be loaded.
 */
avs_crypto_client_cert_info_t
avs_crypto_client_cert_info_from_file(const char *filename);

/**
 * Creates client certificate descriptor used later on to load client
 * certificate from buffer @p buffer.
 *
 * @param buffer      Buffer in which certificate is stored.
 * @param buffer_size Size of the buffer contents in bytes.
 */
avs_crypto_client_cert_info_t
avs_crypto_client_cert_info_from_buffer(const void *buffer, size_t buffer_size);

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES

/**
 * Opaque type that represents a DER-encoded ASN.1 OBJECT IDENTIFIER, including
 * the leading identifier and length octets (so it shall always start with
 * '\x06' followed by a single length octet.
 *
 * NOTE: This type is actually never defined. It is used as a marker to ensure
 * type safety when operating on ASN.1 OBJECT IDENTIFIERs. If you need to use
 * an OBJECT IDENTIFIER that is not defined as a constant within this file, you
 * shall just cast pointer to a binary buffer holding it into a pointer to this
 * type.
 */
typedef struct avs_crypto_asn1_oid_struct avs_crypto_asn1_oid_t;

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the secp192k1 curve group.
 *
 * IANA TLS group ID: 18
 * IANA TLS group name: secp192k1
 * ASN.1 OID: iso(1) identified-organization(3) certicom(132) curve(0)
 *            ansip192k1(31)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_SECP192K1 \
        ((const avs_crypto_asn1_oid_t *) "\x06\x05\x2B\x81\x04\x00\x1F")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the secp192r1 curve group.
 *
 * IANA TLS group ID: 19
 * IANA TLS group name: secp192r1
 * ASN.1 OID: iso(1) member-body(2) us(840) ansi-x962(10045) curves(3) prime(1)
 *            prime192v1(1)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_SECP192R1 \
        ((const avs_crypto_asn1_oid_t          \
                  *) "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the secp224k1 curve group.
 *
 * IANA TLS group ID: 20
 * IANA TLS group name: secp224k1
 * ASN.1 OID: iso(1) identified-organization(3) certicom(132) curve(0)
 *            ansip224k1(32)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_SECP224K1 \
        ((const avs_crypto_asn1_oid_t *) "\x06\x05\x2B\x81\x04\x00\x20")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the secp224r1 curve group.
 *
 * IANA TLS group ID: 21
 * IANA TLS group name: secp224r1
 * ASN.1 OID: iso(1) identified-organization(3) certicom(132) curve(0)
 *            ansip224r1(33)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_SECP224R1 \
        ((const avs_crypto_asn1_oid_t *) "\x06\x05\x2B\x81\x04\x00\x21")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the secp256k1 curve group.
 *
 * IANA TLS group ID: 22
 * IANA TLS group name: secp256k1
 * ASN.1 OID: iso(1) identified-organization(3) certicom(132) curve(0)
 *            ansip256k1(10)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_SECP256K1 \
        ((const avs_crypto_asn1_oid_t *) "\x06\x05\x2B\x81\x04\x00\x0A")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the secp256r1 curve group.
 *
 * IANA TLS group ID: 23
 * IANA TLS group name: secp256r1
 * ASN.1 OID: iso(1) member-body(2) us(840) ansi-x962(10045) curves(3) prime(1)
 *            prime256v1(7)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_SECP256R1 \
        ((const avs_crypto_asn1_oid_t          \
                  *) "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the secp384r1 curve group.
 *
 * IANA TLS group ID: 24
 * IANA TLS group name: secp384r1
 * ASN.1 OID: iso(1) identified-organization(3) certicom(132) curve(0)
 *            ansip384r1(34)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_SECP384R1 \
        ((const avs_crypto_asn1_oid_t *) "\x06\x05\x2B\x81\x04\x00\x22")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the secp521r1 curve group.
 *
 * IANA TLS group ID: 25
 * IANA TLS group name: secp521r1
 * ASN.1 OID: iso(1) identified-organization(3) certicom(132) curve(0)
 *            ansip521r1(35)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_SECP521R1 \
        ((const avs_crypto_asn1_oid_t *) "\x06\x05\x2B\x81\x04\x00\x23")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the brainpoolP256r1 curve group.
 *
 * IANA TLS group ID: 26
 * IANA TLS group name: brainpoolP256r1
 * ASN.1 OID: iso(1) identified-organization(3) teletrust(36) algorithm(3)
 *            signatureAlgorithm(3) ecSign(2) ecStdCurvesAndGeneration(8)
 *            ellipticCurve(1) versionOne(1) brainpoolP256r1(7)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_BRAINPOOLP256R1 \
        ((const avs_crypto_asn1_oid_t                \
                  *) "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the brainpoolP384r1 curve group.
 *
 * IANA TLS group ID: 27
 * IANA TLS group name: brainpoolP384r1
 * ASN.1 OID: iso(1) identified-organization(3) teletrust(36) algorithm(3)
 *            signatureAlgorithm(3) ecSign(2) ecStdCurvesAndGeneration(8)
 *            ellipticCurve(1) versionOne(1) brainpoolP384r1(11)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_BRAINPOOLP384R1 \
        ((const avs_crypto_asn1_oid_t                \
                  *) "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0B")

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER for the brainpoolP512r1 curve group.
 *
 * IANA TLS group ID: 28
 * IANA TLS group name: brainpoolP512r1
 * ASN.1 OID: iso(1) identified-organization(3) teletrust(36) algorithm(3)
 *            signatureAlgorithm(3) ecSign(2) ecStdCurvesAndGeneration(8)
 *            ellipticCurve(1) versionOne(1) brainpoolP512r1(13)
 */
#    define AVS_CRYPTO_PKI_ECP_GROUP_BRAINPOOLP512R1 \
        ((const avs_crypto_asn1_oid_t                \
                  *) "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0D")

/**
 * Generates a random private key (in a form that allows deriving the public key
 * from it) suitable for use with elliptic curve cryptography.
 *
 * @param prng_ctx                  PRNG context to use for random number
 *                                  generation.
 *
 * @param ecp_group_asn1_oid        Pointer to DER-encoded ASN.1 OBJECT
 *                                  IDENTIFIER (including the leading identifier
 *                                  and length octets) describing the ECP group
 *                                  to use.
 *
 *                                  Values identifying common curves supported
 *                                  by both OpenSSL and mbed TLS are defined as
 *                                  the @c AVS_CRYPTO_PKI_ECP_GROUP_* macros.
 *
 *                                  NOTE: There is no separate length argument,
 *                                  as it is derived from the length octet
 *                                  within the encoded data.
 *
 * @param out_der_secret_key        Pointer to a buffer, at the beginning of
 *                                  which the private key encoded as SEC1 DER
 *                                  will be stored.
 *
 * @param inout_der_secret_key_size Pointer to a variable which, on input, shall
 *                                  contain the number of bytes available in the
 *                                  @p out_der_secret_key buffer. On successful
 *                                  return, it will be set to the number of
 *                                  bytes actually written.
 */
avs_error_t avs_crypto_pki_ec_gen(avs_crypto_prng_ctx_t *prng_ctx,
                                  const avs_crypto_asn1_oid_t *ecp_group_oid,
                                  void *out_der_secret_key,
                                  size_t *inout_der_secret_key_size);

avs_error_t
avs_crypto_pki_csr_create(avs_crypto_prng_ctx_t *prng_ctx,
                          const avs_crypto_client_key_info_t *private_key_info,
                          const char *md_name,
                          const char *subject_name,
                          void *out_der_csr,
                          size_t *inout_der_csr_size);

#endif // AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // AVS_COMMONS_CRYPTO_PKI_H
