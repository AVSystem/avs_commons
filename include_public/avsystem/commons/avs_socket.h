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

/**
 * @file avs_socket.h
 */

#ifndef AVS_COMMONS_SOCKET_H
#define AVS_COMMONS_SOCKET_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <avsystem/commons/avs_commons_config.h>
#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_time.h>

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO
#    include <avsystem/commons/avs_crypto_pki.h>
#    include <avsystem/commons/avs_prng.h>
#endif // AVS_COMMONS_WITH_AVS_CRYPTO

#ifdef AVS_COMMONS_NET_WITH_X509
#    warning \
            "Your avs_commons_config.h defines AVS_COMMONS_NET_WITH_X509, which is deprecated since avs_commons 4.2. Auto-including avs_net_pki_compat.h to provide backwards compatibility for legacy avs_net PKI APIs."
#    include <avsystem/commons/avs_net_pki_compat.h>
#endif // AVS_COMMONS_NET_WITH_X509

#ifdef __cplusplus
extern "C" {
#endif

/* glibc's sockaddr_storage is 128 bytes long, we follow suit */
#define AVS_NET_SOCKET_RAW_RESOLVED_ENDPOINT_MAX_SIZE 128

/* 30 sec timeout */
extern const avs_time_duration_t AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT;

typedef struct {
    uint8_t size;
    union {
        avs_max_align_t align;
        char buf[AVS_NET_SOCKET_RAW_RESOLVED_ENDPOINT_MAX_SIZE];
    } data;
} avs_net_resolved_endpoint_t;

typedef enum {
    AVS_NET_TCP_SOCKET,
    AVS_NET_UDP_SOCKET,
    AVS_NET_SSL_SOCKET,
    AVS_NET_DTLS_SOCKET
} avs_net_socket_type_t;

/**
 * Alias for address family to avoid leaking POSIX socket API.
 */
typedef enum {
    AVS_NET_AF_UNSPEC,
    AVS_NET_AF_INET4,
    AVS_NET_AF_INET6
} avs_net_af_t;

/**
 * Type for socket abstraction object.
 */
struct avs_net_socket_struct;
typedef struct avs_net_socket_struct avs_net_socket_t;

/**
 * This is a type of data used for binding socket to a specific network
 * interface. For POSIX interfaces it is array of IF_NAMESIZE characters.
 */
typedef char avs_net_socket_interface_name_t[IF_NAMESIZE];

/**
 * Structure that contains additional configuration options for creating TCP and
 * UDP network sockets.
 *
 * A structure initialized with all zeroes (e.g. using <c>memset()</c>) is
 * a valid, default configuration - it is used when <c>NULL</c> is passed to
 * @ref avs_net_tcp_socket_create or @ref avs_net_udp_socket_create , and may
 * also be used as a starting point for customizations.
 */
typedef struct {
    /**
     * Specifies the Differentiated Services Code Point to send in the IP
     * packets when communicating on the created socket. Valid values are in the
     * range 0-64.
     *
     * It is configured using the <c>IP_TOS</c> option on the underlying system
     * socket - not done if left at the default value of 0.
     */
    uint8_t dscp;

    /**
     * Specifies the priority of packets sent when communicating on the created
     * socket. Valid values are in the range 0-7.
     *
     * It is configured using the <c>SO_PRIORITY</c> option on the underlying
     * system socket - not done if left at the default value of 0. It may or may
     * not affect the IP TOS field, depending on the system.
     *
     * Also please note that e.g. on Linux, setting priority to 7 requires root
     * privileges (specifically, the <c>CAP_NET_ADMIN</c> capability).
     */
    uint8_t priority;

    /**
     * Used to set <c>SO_REUSEADDR<c> on the underlying system socket. This is
     * a boolean flag that needs to be set to either 0 or 1, left as
     * <c>uint8_t</c> instead of <c>bool</c> for compatibility reasons.
     */
    uint8_t reuse_addr;

    /**
     * Used to set <c>IP_TRANSPARENT</c> or <c>IPV6_TRANSPARENT</c> on the
     * underlying system socket. This is a boolean flag that needs to be set to
     * either 0 or 1, left as <c>uint8_t</c> instead of <c>bool</c> for
     * compatibility reasons.
     *
     * Please note that e.g. on Linux, creating transparent sockets requires
     * root privileges (specifically, either the <c>CAP_NET_ADMIN</c> or the
     * <c>CAP_NET_RAW</c> capability).
     */
    uint8_t transparent;

    /**
     * Configures the interface to which the created socket shall be bound. It
     * can be left as an empty string to use the standard, default routing.
     *
     * It sets the <c>SO_BINDTODEVICE</c> option on the system socket
     * internally. Please note that e.g. on Linux, using it requires root
     * privileges (specifically, the <c>CAP_NET_RAW</c> capability). Also, some
     * Linux-based systems enable the <c>rp_filter</c> feature in kernel, which
     * may prevent this setting from working correctly. See
     * http://stackoverflow.com/a/24019586/403742 for details.
     */
    avs_net_socket_interface_name_t interface_name;

    /**
     * Specifies the memory location used for "preferred endpoint" storage.
     *
     * If set to non-NULL:
     * - When connecting to a host specified using a domain name, then if one of
     *   the endpoint addresses returned by DNS resolution is exactly the
     *   address stored at <c>preferred_endpoint</c>, it will be tried first.
     * - After successfully connecting to a host, its resolved endpoint address
     *   will be stored at <c>preferred_endpoint</c>.
     *
     * This behaviour allows to implement affinity to a specific host when
     * communicating with an address served by multiple physical hosts.
     */
    avs_net_resolved_endpoint_t *preferred_endpoint;

    /**
     * Sets the IP protocol version used for communication. Note that setting it
     * explicitly to <c>AVS_NET_AF_INET4</c> or <c>AVS_NET_AF_INET6</c> will
     * result in limiting the socket to support only addresses of that specific
     * family, while using <c>AVS_NET_UNSPEC</c> may, at the underlying system
     * level, result in creating an IPv6 socket connected or bound to a mapped
     * IPv4 address.
     */
    avs_net_af_t address_family;

    /**
     * Specifies a forced value for the MTU to use when communicating over the
     * socket.
     *
     * If set to a positive value, calls to @ref avs_net_socket_get_opt with
     * <c>AVS_NET_SOCKET_OPT_MTU</c> key will always return this forced value.
     * Likewise, <c>AVS_NET_SOCKET_OPT_INNER_MTU</c> will return this value
     * minus IP and UDP header sizes.
     */
    int forced_mtu;

    /**
     * Sets the IP protocol version preferred for communication. If
     * <c>address_family</c> is set to <c>AVS_NET_UNSPEC</c> and
     * <c>preferred_family</c> is set to some specific value
     * (<c>AVS_NET_AF_INET4</c> or <c>AVS_NET_AF_INET6</c>), the socket will
     * always attempt connection to an address of the preferred family first.
     * Domain name resolution will not be requested for other families. Only if
     * connection via the preferred family is not possible, connection via other
     * families will be attempted.
     *
     * This field is ignored if <c>address_family</c> is not
     * <c>AVS_NET_UNSPEC</c>.
     */
    avs_net_af_t preferred_family;
} avs_net_socket_configuration_t;

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO
/**
 * Function type for callbacks to be executed for additional SSL configuration.
 *
 * Note that the @ref library_ssl_context parameter is a pointer to a native
 * SSL context object of the SSL library in use. It shall be cast to
 * <c>SSL_CTX *</c> for OpenSSL or <c>ssl_context *</c> for XySSL-derivatives.
 *
 * @param library_ssl_context pointer to a native SSL context object of the
 *                            SSL library in use
 *
 * @return 0 on success, negative value on failure
 */
typedef int avs_ssl_additional_configuration_clb_t(void *library_ssl_context);

/**
 * Available SSL versions that can be used by SSL sockets.
 */
typedef enum {
    AVS_NET_SSL_VERSION_DEFAULT = 0,
    AVS_NET_SSL_VERSION_SSLv2_OR_3,
    AVS_NET_SSL_VERSION_SSLv2,
    AVS_NET_SSL_VERSION_SSLv3,
    AVS_NET_SSL_VERSION_TLSv1,
    AVS_NET_SSL_VERSION_TLSv1_1,
    AVS_NET_SSL_VERSION_TLSv1_2
} avs_net_ssl_version_t;

/**
 * Internal structure used to store password protected data.
 */
typedef struct {
    const void *data;
    size_t size;
    const char *password;
} avs_net_ssl_raw_data_t;

typedef enum {
    AVS_NET_SECURITY_DEFAULT = 0,
    AVS_NET_SECURITY_PSK, /**< Pre-Shared Key */
    AVS_NET_SECURITY_CERTIFICATE =
            AVS_NET_SECURITY_DEFAULT /**< X509 Certificate + private key */
} avs_net_security_mode_t;

/**
 * A PSK/identity pair with borrowed pointers. avs_commons will never attempt
 * to modify these values.
 */
typedef struct {
    const void *psk;
    size_t psk_size;
    const void *identity;
    size_t identity_size;
} avs_net_psk_info_t;

/**
 * Configuration for certificate-mode (D)TLS connection.
 */
typedef struct {
    /**
     * Enables validation of peer certificate chain. If disabled,
     * #ignore_system_trust_store and #trusted_certs are ignored.
     */
    bool server_cert_validation;

    /**
     * Setting this flag to true disables the usage of system-wide trust store
     * (e.g. <c>/etc/ssl/certs</c> on most Unix-like systems).
     *
     * NOTE: System-wide trust store is currently supported only by the OpenSSL
     * backend. This field is ignored by the Mbed TLS backend.
     */
    bool ignore_system_trust_store;

    /**
     * Enable use of DNS-based Authentication of Named Entities (DANE) if
     * possible.
     *
     * If this field is set to true, but #server_cert_validation is disabled,
     * "opportunistic DANE" is used.
     */
    bool dane;

    /**
     * Store of trust anchor certificates. This field is optional and can be
     * left zero-initialized. If used, it shall be initialized using one of the
     * <c>avs_crypto_certificate_chain_info_from_*</c> helper functions.
     */
    avs_crypto_certificate_chain_info_t trusted_certs;

    /**
     * Store of certificate revocation lists. This field is optional and can be
     * left zero-initialized. If used, it shall be initialized using one of the
     * <c>avs_crypto_cert_revocation_list_info_from_*</c> helper functions.
     */
    avs_crypto_cert_revocation_list_info_t cert_revocation_lists;

    /**
     * Local certificate chain to use for authenticating with the peer. This
     * field is optional and can be left zero-initialized. If used, it shall be
     * initialized using one of the
     * <c>avs_crypto_certificate_chain_info_from_*</c> helper functions.
     */
    avs_crypto_certificate_chain_info_t client_cert;

    /**
     * Private key matching #client_cert to use for authenticating with the
     * peer. This field is optional and can be left zero-initialized, unless
     * #client_cert is also specified. If used, it shall be initialized using
     * one of the <c>avs_crypto_private_key_info_from_*</c> helper functions.
     */
    avs_crypto_private_key_info_t client_key;

    /**
     * Enable rebuilding of client certificate chain based on certificates in
     * the trust store.
     *
     * If this field is set to <c>true</c>, and the last certificate in the
     * #client_cert chain is not self-signed, the library will attempt to find
     * its ancestors in #trusted_certs and append them to the chain presented
     * during handshake.
     */
    bool rebuild_client_cert_chain;
} avs_net_certificate_info_t;

typedef struct {
    avs_net_security_mode_t mode;
    union {
        avs_net_psk_info_t psk;
        avs_net_certificate_info_t cert;
    } data;
} avs_net_security_info_t;

avs_net_security_info_t avs_net_security_info_from_psk(avs_net_psk_info_t psk);

avs_net_security_info_t
avs_net_security_info_from_certificates(avs_net_certificate_info_t info);

typedef struct {
    avs_time_duration_t min;
    avs_time_duration_t max;
} avs_net_dtls_handshake_timeouts_t;
#endif // AVS_COMMONS_WITH_AVS_CRYPTO

/**
 * Category for @ref avs_error_t containing a (D)TLS Alert.
 *
 * The <c>code</c> field in errors of this type will contain a packed
 * representation of the TLS alert. @ref avs_net_ssl_alert_level and
 * @ref avs_net_ssl_alert_description may be used to unpack the alert fields.
 *
 * Errors of this type will be returned by socket operations (and may be
 * propagated by other code) when a (D)TLS Alert message is received during
 * some operation, likely a handshake (which is performed during
 * @ref avs_net_socket_connect and @ref avs_net_socket_decorate).
 */
#define AVS_NET_SSL_ALERT_CATEGORY 8572 // 'TLSA' on phone keypad

/**
 * Builds an avs_error_t value corresponding to an SSL alert. Meaning of the
 * arguments is as defined in https://tools.ietf.org/html/rfc5246#section-7.2
 */
static inline avs_error_t avs_net_ssl_alert(uint8_t level,
                                            uint8_t description) {
    avs_error_t result = { AVS_NET_SSL_ALERT_CATEGORY,
                           (uint16_t) ((level << 8) | description) };
    return result;
}

static inline uint8_t avs_net_ssl_alert_level(avs_error_t error) {
    assert(error.category == AVS_NET_SSL_ALERT_CATEGORY);
    return (uint8_t) (error.code >> 8);
}

static inline uint8_t avs_net_ssl_alert_description(avs_error_t error) {
    assert(error.category == AVS_NET_SSL_ALERT_CATEGORY);
    return (uint8_t) error.code;
}

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO
typedef struct {
    /** Array of ciphersuite IDs, or NULL to enable all ciphers */
    uint32_t *ids;
    /** Number of elements in @ref avs_net_socket_tls_ciphersuites_t#ids */
    size_t num_ids;
} avs_net_socket_tls_ciphersuites_t;

typedef struct {
    /**
     * SSL/TLS version to use for communication.
     */
    avs_net_ssl_version_t version;

    /**
     * Security configuration (either PSK key or certificate information) to use
     * for communication.
     */
    avs_net_security_info_t security;

    /**
     * If non-NULL, can be used to customize DTLS handshake timeout limits.
     */
    const avs_net_dtls_handshake_timeouts_t *dtls_handshake_timeouts;

    /**
     * Buffer to use for (D)TLS session resumption (used if
     * <c>session_resumption_buffer_size</c> is non-zero).
     *
     * During @ref avs_net_socket_connect, the library will attempt to load
     * session information from this buffer, and in case of success, will offer
     * that session to the server for resumption, allowing to maintain endpoint
     * association between connections.
     *
     * After a successful establishment, resumption or renegotiation of a
     * session, the buffer will be filled with the newly negotiated session
     * information.
     *
     * The buffer will also be always filled with zeroes in case of error, and
     * all the unused space will also be zeroed out after writing data, to allow
     * for e.g. size optimization when saving data to persistent storage.
     *
     * Session resumption support is currently only available through the mbed
     * TLS backend. Note that if support is added for other backends, the
     * session data format might not be compatible between backends. There is
     * rudimentary protection against attempting to read data in invalid format.
     */
    void *session_resumption_buffer;

    /**
     * Size of the buffer passed in <c>session_resumption_buffer</c>. Session
     * resumption support is enabled if nonzero. Must be zero if
     * <c>session_resumption_buffer</c> is NULL.
     *
     * Session data format used by the mbed TLS backend requires 112 bytes for
     * common data, and additional variable number of bytes for DER-formatted
     * X.509 peer certificate, if used.
     *
     * A buffer size of at least 1024 bytes is recommended to be able to store
     * most certificates.
     */
    size_t session_resumption_buffer_size;

    /**
     * An array of ciphersuite IDs, in big endian. For example,
     * TLS_PSK_WITH_AES_128_CCM_8 is represented as 0xC0A8.
     *
     * For a complete list of ciphersuites, see
     * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
     *
     * Note: cipher entries that are unsupported by the (D)TLS backend will be
     * silently ignored. An empty ciphersuite list (default) can be used to
     * enable all supported ciphersuites.
     *
     * A copy owned by the socket object is made, so it is not required for this
     * pointer to be valid after the call completes.
     */
    avs_net_socket_tls_ciphersuites_t ciphersuites;

    /**
     * Callback that is executed when initializing communication, that can be
     * used for additional configuration of the TLS backend.
     */
    avs_ssl_additional_configuration_clb_t *additional_configuration_clb;

    /**
     * Configuration used for the underlying raw TCP/UDP socket.
     */
    avs_net_socket_configuration_t backend_configuration;

    /**
     * Server Name Indication value to be used for certificate validation during
     * TLS handshake, or NULL if a default value shall be used (i.e. hostname to
     * which the connection is performed).
     *
     * The same value will also be used as DANE base domain if DANE is enabled.
     */
    const char *server_name_indication;

    /**
     * Enables / disables the use of DTLS connection_id extension (if
     * implemented by the backend). Note that it only works for DTLS sockets,
     * and has no effect on other socket types.
     */
    bool use_connection_id;

    /**
     * PRNG context to use. It must outlive the created socket. MUST NOT be
     * @c NULL .
     */
    avs_crypto_prng_ctx_t *prng_ctx;
} avs_net_ssl_configuration_t;
#endif // AVS_COMMONS_WITH_AVS_CRYPTO

typedef enum {
    /**
     * Used to set or get receive timeout of the socket. The value is passed in
     * the <c>recv_timeout</c> field of the @ref avs_net_socket_opt_value_t
     * union.
     */
    AVS_NET_SOCKET_OPT_RECV_TIMEOUT,

    /**
     * Used to get the current state of the socket. The value is passed in the
     * <c>state</c> field of the @ref avs_net_socket_opt_value_t union.
     */
    AVS_NET_SOCKET_OPT_STATE,

    /**
     * Used to get the family of the communication addresses used by the socket.
     * The value is passed in the <c>addr_family</c> field of the
     * @ref avs_net_socket_opt_value_t union.
     */
    AVS_NET_SOCKET_OPT_ADDR_FAMILY,

    /**
     * Used to get the maximum size of a network-layer packet that can be
     * transmitted by the socket. The value is passed as bytes in the <c>mtu</c>
     * field of the @ref avs_net_socket_opt_value_t union.
     */
    AVS_NET_SOCKET_OPT_MTU,

    /**
     * Used to get the maximum size of a buffer that can be passed to
     * @ref avs_net_socket_send or @ref avs_net_socket_send_to and transmitted
     * as a single packet. The value is passed as bytes in the <c>mtu</c> field
     * of the @ref avs_net_socket_opt_value_t union.
     */
    AVS_NET_SOCKET_OPT_INNER_MTU,

    /**
     * Used to check whether the last (D)TLS handshake was a successful session
     * resumption. The value is passed in the <c>flag</c> field of the
     * @ref avs_net_socket_opt_value_t union - <c>true</c> if the session was
     * resumed, or <c>false</c> if it was a full handshake. If the socket is in
     * any other state than @ref AVS_NET_SOCKET_STATE_CONNECTED, the behaviour
     * is undefined.
     *
     * If <c>session_resumption_buffer_size</c> field in
     * @ref avs_net_ssl_configuration_t is nonzero,
     * @ref avs_net_socket_connect will attempt to resume the session that was
     * previously used before calling @ref avs_net_socket_close. However, if it
     * is not possible, a normal handshake will be used instead and the whole
     * call will still be successful. This option makes it possible to check
     * whether the session has been resumed, or is a new unrelated one.
     */
    AVS_NET_SOCKET_OPT_SESSION_RESUMED,

    /**
     * Used to get the number of bytes sent. Does not include protocol overhead.
     */
    AVS_NET_SOCKET_OPT_BYTES_SENT,

    /**
     * Used to get the number of bytes received. Does not include protocol
     * overhead.
     */
    AVS_NET_SOCKET_OPT_BYTES_RECEIVED,

    /**
     * Used to set an array of DANE TLSA records. The value is write-only and
     * passed in the <c>dane_tlsa_array</c> field of the
     * @ref avs_net_socket_opt_value_t union.
     *
     * The data is copied into the socket, and the value passed by the user may
     * be freed after a successful call.
     *
     * NOTE: Attempting to set this option on a socket that is not a (D)TLS
     * socket or is not configured to use DANE, will yield an error.
     */
    AVS_NET_SOCKET_OPT_DANE_TLSA_ARRAY,
} avs_net_socket_opt_key_t;

typedef enum {
    /**
     * Socket is either newly constructed, or it has been closed by calling
     * @ref avs_net_socket_close.
     */
    AVS_NET_SOCKET_STATE_CLOSED,

    /**
     * Socket was previously in either BOUND, ACCEPTED or CONNECTED state, but
     * @ref avs_net_socket_shutdown was called.
     */
    AVS_NET_SOCKET_STATE_SHUTDOWN,

    /**
     * @ref avs_net_socket_bind has been called:
     * - In case of a datagram socket (@ref AVS_NET_UDP_SOCKET or
     *   @ref AVS_NET_DTLS_SOCKET), it is ready for @ref avs_net_socket_send_to
     *   and @ref avs_net_socket_receive_from operations.
     * - In case of a stream socket (@ref AVS_NET_TCP_SOCKET or
     *   @ref AVS_NET_SSL_SOCKET), it is ready for @ref avs_net_socket_accept
     *   operation.
     */
    AVS_NET_SOCKET_STATE_BOUND,

    /**
     * This is a server-side stream socket, serving a connection from one
     * concrete client brought up using @ref avs_net_socket_accept. It is ready
     * for @ref avs_net_socket_send and @ref avs_net_socket_receive operations.
     */
    AVS_NET_SOCKET_STATE_ACCEPTED,

    /**
     * @ref avs_net_socket_connect has been called. The socket is connected to
     * some concrete server. In case of a stream socket (@ref AVS_NET_TCP_SOCKET
     * or @ref AVS_NET_SSL_SOCKET), it is strictly the client end of the
     * connection. It is ready for @ref avs_net_socket_send and
     * @ref avs_net_socket_receive operations.
     */
    AVS_NET_SOCKET_STATE_CONNECTED
} avs_net_socket_state_t;

typedef enum {
    AVS_NET_SOCKET_DANE_CA_CONSTRAINT = 0,
    AVS_NET_SOCKET_DANE_SERVICE_CERTIFICATE_CONSTRAINT = 1,
    AVS_NET_SOCKET_DANE_TRUST_ANCHOR_ASSERTION = 2,
    AVS_NET_SOCKET_DANE_DOMAIN_ISSUED_CERTIFICATE = 3
} avs_net_socket_dane_certificate_usage_t;

typedef enum {
    AVS_NET_SOCKET_DANE_CERTIFICATE = 0,
    AVS_NET_SOCKET_DANE_PUBLIC_KEY = 1
} avs_net_socket_dane_selector_t;

typedef enum {
    AVS_NET_SOCKET_DANE_MATCH_FULL = 0,
    AVS_NET_SOCKET_DANE_MATCH_SHA256 = 1,
    AVS_NET_SOCKET_DANE_MATCH_SHA512 = 2
} avs_net_socket_dane_matching_type_t;

typedef struct {
    avs_net_socket_dane_certificate_usage_t certificate_usage;
    avs_net_socket_dane_selector_t selector;
    avs_net_socket_dane_matching_type_t matching_type;
    const void *association_data;
    size_t association_data_size;
} avs_net_socket_dane_tlsa_record_t;

typedef struct {
    const avs_net_socket_dane_tlsa_record_t *array_ptr;
    size_t array_element_count;
} avs_net_socket_dane_tlsa_array_t;

/**
 * Copies a DANE TLSA record array.
 *
 * Association data buffers are copied as well, so the original entries can be
 * freed.
 *
 * The resulting array is allocated in such a way that a single @ref avs_free
 * call is sufficient to free the whole array and all associated resources.
 *
 * The element count is not returned, as it will always be equal to
 * <c>input.array_element_count</c>.
 *
 * @param in_array DANE TLSA record array to copy.
 *
 * @returns Pointer to the copied array for success, or <c>NULL</c> if the input
 *          array has zero elements (NOTE: this is not an error) or if an
 *          out-of-memory condition occurred.
 */
avs_net_socket_dane_tlsa_record_t *
avs_net_socket_dane_tlsa_array_copy(avs_net_socket_dane_tlsa_array_t in_array);

typedef union {
    avs_time_duration_t recv_timeout;
    avs_net_socket_state_t state;
    avs_net_af_t addr_family;
    int mtu;
    bool flag;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    avs_net_socket_dane_tlsa_array_t dane_tlsa_array;
} avs_net_socket_opt_value_t;

int avs_net_socket_debug(int value);

/**
 * @name Sockets constructors
 * Creates a new socket of a specified type.
 *
 * @param socket A variable to hold the newly created socket in. If it already
 *               is initialized to any socket, the existing socket will be
 *               destroyed and freed. This also means that at first use, the
 *               variable <strong>MUST</strong> be initialized to <c>NULL</c>.
 *
 * @param config Pointer to additional configuration for the socket to create.
 *               The type of configuration data is dependent on the type of the
 *               socket: @ref avs_net_socket_configuration_t for a TCP or UDP
 *               socket (in which case it may also be <c>NULL</c> for defaults)
 *               or @ref avs_net_ssl_configuration_t for an SSL or DTLS socket.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 *
 * @{
 */

avs_error_t
avs_net_udp_socket_create(avs_net_socket_t **socket,
                          const avs_net_socket_configuration_t *config);

avs_error_t
avs_net_tcp_socket_create(avs_net_socket_t **socket,
                          const avs_net_socket_configuration_t *config);

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO
avs_error_t
avs_net_dtls_socket_create(avs_net_socket_t **socket,
                           const avs_net_ssl_configuration_t *config);

avs_error_t
avs_net_ssl_socket_create(avs_net_socket_t **socket,
                          const avs_net_ssl_configuration_t *config);
#endif // AVS_COMMONS_WITH_AVS_CRYPTO
/**@}*/

/**
 * Shuts down @p socket , cleans up any allocated resources and sets
 * <c>*socket</c> to NULL. When called on a socket decorator, also cleans up all
 * lower-layer sockets.
 *
 * @param[inout] socket Socket to clean up.
 *
 * @returns @li @ref AVS_OK for success
 *          @li an error condition for which the operation failed. Note that
 *              regardless of the return value, all resources associated with
 *              @p socket are cleaned up and <c>*socket</c> is set to NULL.
 */
avs_error_t avs_net_socket_cleanup(avs_net_socket_t **socket);

/**
 * Sets the remote endpoint of @p socket to given @p host : @p port pair.
 * If applicable for given socket type, performs handshakes necessary for
 * setting up communication.
 *
 * @param socket Socket to operate on.
 * @param host   Remote hostname or IP address to connect to.
 * @param port   Remote port to connect to.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed; in particular, if DNS resolution fails,
 *          <c>avs_errno(AVS_EADDRNOTAVAIL)</c> is returned.
 */
avs_error_t avs_net_socket_connect(avs_net_socket_t *socket,
                                   const char *host,
                                   const char *port);

/**
 * Makes @p socket use @p backend_socket as a lower-level socket interface.
 * Used e.g. for decorating a TCP socket with an SSL/TLS one, or for creating
 * a debug proxy.
 *
 * Decoration may take place while the lower-layer socket is in a closed state
 * (which allows to create e.g. a TLS socket with non-standard - possibly
 * non-IP - backend), or when it is ready for communication (which allows to
 * implement mechanisms such as STARTTLS). Note that not all types of sockets
 * will support decoration at every stage, or decoration at all.
 *
 * The default SSL/TLS/DTLS socket implementation can decorate either a stream
 * or a datagram socket, in both closed or ready state.
 *
 * @param socket         Wrapper socket. It must be a newly-created socket
 *                       object (in @ref AVS_NET_SOCKET_STATE_CLOSED state).
 * @param backend_socket Lower-layer socket to wrap.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_net_socket_decorate(avs_net_socket_t *socket,
                                    avs_net_socket_t *backend_socket);

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO
/**
 * @name Sockets decorators
 *
 * Creates DTLS or SSL socket with given @p config , then performs
 * @ref avs_net_socket_decorate with <c>*socket</c> as the backend socket and
 * replaces <c>*socket</c> with newly-created socket.
 *
 * @param[inout] socket Pointer to a socket object to use as backend. On
 *                      success, <c>*socket</c> is replaced with a newly-created
 *                      socket of given @p new_type .
 * @param[in]    config Pointer to additional socket configuration to pass to
 *                      @ref avs_net_ssl_socket_create or
 *                      @ref avs_net_dtls_socket_create .
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed. On failure, <c>*socket</c> value is guaranteed to
 *          be left untouched.
 *
 * @{
 */

avs_error_t avs_net_dtls_socket_decorate_in_place(
        avs_net_socket_t **socket, const avs_net_ssl_configuration_t *config);

avs_error_t
avs_net_ssl_socket_decorate_in_place(avs_net_socket_t **socket,
                                     const avs_net_ssl_configuration_t *config);

/**@}*/
#endif // AVS_COMMONS_WITH_AVS_CRYPTO

/**
 * Sends exactly @p buffer_length bytes from @p buffer to @p socket.
 *
 * @li For TCP sockets: the call may block for an indeterminate amount of time,
 *     until all passed data is successfully sent.
 * @li For UDP sockets: @p buffer is handled as a single datagram. If there is
 *     too much data to fit into a single datagram, the function fails.
 *
 * @param socket        Socket object to send data to.
 * @param buffer        Data to send.
 * @param buffer_length Number of bytes to send.
 *
 * @returns @li @ref AVS_OK if exactly @p buffer_length bytes were written,
 *          @li an error condition for which the operation failed.
 */
avs_error_t avs_net_socket_send(avs_net_socket_t *socket,
                                const void *buffer,
                                size_t buffer_length);

/**
 * Sends exactly @p buffer_length bytes from @p buffer to @p host / @p port,
 * using @p socket.
 *
 * @li For TCP sockets: @p host and @p are ignored if @p socket is already
 *     connected.
 * @li For UDP sockets: @p buffer is handled as a single datagram. If there is
 *     too much data to fit into a single datagram, the function fails.
 *
 * @param[in]  socket         Socket object to send data to.
 * @param[in]  buffer         Data to send.
 * @param[in]  buffer_length  Number of bytes to send.
 * @param[in]  host           Remote host to send data to. May be an IP address
 *                            as a string, or a domain name.
 * @param[in]  port           Remote port to send data to: an integer as string.
 *
 * @returns @li @ref AVS_OK if exactly @p buffer_length bytes were written,
 *          @li an error condition for which the operation failed; in
 *          particular, if DNS resolution fails,
 *          <c>avs_errno(AVS_EADDRNOTAVAIL)</c> is returned.
 */
avs_error_t avs_net_socket_send_to(avs_net_socket_t *socket,
                                   const void *buffer,
                                   size_t buffer_length,
                                   const char *host,
                                   const char *port);
/**
 * Receives up to @p buffer_length bytes of data from @p socket into @p buffer .
 *
 * For UDP datagrams whose length exceeds @p buffer_length :
 * - @p buffer is filled with @p buffer_length initial bytes of data,
 * - @p buffer_length is returned via @p out_bytes_received ,
 * - the function returns <c>avs_errno(AVS_EMSGSIZE)</c>.
 * That means, one can still access the truncated message if required. Note
 * that the actual length of received datagram is lost.
 *
 * WARNING: If recvmsg() is not available, this function will report the
 * UDP datagram as truncated if it is exactly @p buffer_length bytes long.
 *
 * @param[in]  socket             Socket object to read data from.
 *                                The socket must be connected.
 * @param[out] out_bytes_received Number of bytes successfully read into
 *                                @p buffer after a call to this function.
 * @param[out] buffer             Buffer to write read bytes to.
 * @param[in]  buffer_length      Number of bytes available in @p buffer .
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_net_socket_receive(avs_net_socket_t *socket,
                                   size_t *out_bytes_received,
                                   void *buffer,
                                   size_t buffer_length);

/**
 * Receives up to @p buffer_length bytes of data from @p socket into @p buffer .
 * Fills @p host and @p port with information about the sender.
 *
 * For UDP datagrams whose length exceeds @p buffer_length :
 * - @p buffer is filled with @p buffer_length initial bytes of data,
 * - @p buffer_length is returned via @p out_bytes_received ,
 * - the function returns <c>avs_errno(AVS_EMSGSIZE)</c>.
 * That means, one can still access the truncated message if required. Note
 * that the actual length of received datagram is lost.
 *
 * WARNING: If recvmsg() is not available, this function will report the
 * UDP datagram as truncated if it is exactly @p buffer_length bytes long.
 *
 * @param[in]  socket             Socket object to read data from.
 * @param[out] out_bytes_received Number of bytes successfully read into
 *                                @p buffer after a call to this function.
 * @param[out] buffer             Buffer to write received bytes to.
 * @param[in]  buffer_length      Number of bytes available in @p buffer .
 * @param[out] host               Buffer to store sender hostname. If possible,
 *                                @p host is set to sender domain name,
 *                                otherwise it is the sender IP address
 *                                converted to a string.
 * @param[in]  host_size          Number of bytes available in @p host .
 * @param[out] port               Buffer to store the port a message was sent
 *                                from, converted to a string.
 * @param[in]  port_size          Number of bytes available in @p port .
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_net_socket_receive_from(avs_net_socket_t *socket,
                                        size_t *out_bytes_received,
                                        void *buffer,
                                        size_t buffer_length,
                                        char *host,
                                        size_t host_size,
                                        char *port,
                                        size_t port_size);

/**
 * Binds @p socket to specified local @p address and @p port .
 *
 * @param socket  Socket object to operate on.
 * @param address Local IP address to bind to.
 * @param port    Local port to bind to.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_net_socket_bind(avs_net_socket_t *socket,
                                const char *address,
                                const char *port);

/**
 * Accepts an incoming connection targeted at @p server_socket and prepares
 * @p client_socket for communication with connecting host.
 *
 * @param server_socket Listening socket.
 * @param client_socket Socket that will be later used for the accepted
 *                      connection. This shall be a newly created (not bound or
 *                      connected) socket of the same type as
 *                      <c>server_socket</c>. An error will be returned
 *                      otherwise.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 *
 * NOTE: this function fails for connectionless sockets (e.g. UDP).
 */
avs_error_t avs_net_socket_accept(avs_net_socket_t *server_socket,
                                  avs_net_socket_t *client_socket);

/**
 * Shuts down the @p socket , so that further communication is not allowed.
 * Discards any buffered, but not yet processed data.
 *
 * @p socket may later be reused by calling @ref avs_net_socket_connect
 * or @ref avs_net_socket_bind .
 *
 * @param socket Socket to close.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed. Regardless of the return value, the socket is left
 *          in @ref AVS_NET_SOCKET_STATE_CLOSED state and needs to be connected
 *          or bound before using again.
 */
avs_error_t avs_net_socket_close(avs_net_socket_t *socket);

/**
 * Shuts down the @p socket , so that further communication is not allowed.
 * Any buffered, but not yet processed data will still be delivered. Performs
 * the termination handshake if @p socket protocol requires one.
 *
 * Already-received data can still be read using @ref avs_net_socket_receive.
 * @p socket needs to be closed (@ref avs_net_socket_close) before reusing it
 * for further communication.
 *
 * @param socket Socket to shut down.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed. Regardless of the return value, the socket is left
 *          in @ref AVS_NET_SOCKET_STATE_SHUTDOWN state and needs to be
 *          connected or bound before using again.
 */
avs_error_t avs_net_socket_shutdown(avs_net_socket_t *socket);

/**
 * Returns the name of an interface @p socket is currently bound to.
 *
 * @param[in]  socket  Bound socket to retrieve interface name for.
 * @param[out] if_name Retrieved interface name.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t
avs_net_socket_interface_name(avs_net_socket_t *socket,
                              avs_net_socket_interface_name_t *if_name);

/**
 * Returns the IP address of the remote endpoint @p socket is connected to.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store remote endpoint IP address in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li @ref AVS_OK for success, in which case @p out_buffer is
 *              guaranteed to be null-terminated,
 *          @li an error condition for which the operation failed.
 */
avs_error_t avs_net_socket_get_remote_host(avs_net_socket_t *socket,
                                           char *out_buffer,
                                           size_t out_buffer_size);

/**
 * Returns the hostname of the remote endpoint that was used when connecting
 * @p socket. If the socket was connected using the IP address and not
 * a hostname, a stringified IP address is returned.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store remote endpoint hostname in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li @ref AVS_OK for success, in which case @p out_buffer is
 *              guaranteed to be null-terminated,
 *          @li an error condition for which the operation failed.
 */
avs_error_t avs_net_socket_get_remote_hostname(avs_net_socket_t *socket,
                                               char *out_buffer,
                                               size_t out_buffer_size);

/**
 * Returns the remote port @p socket is connected to.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store the port (converted
 *                             to a string) in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li @ref AVS_OK for success, in which case @p out_buffer is
 *              guaranteed to be null-terminated,
 *          @li an error condition for which the operation failed.
 */
avs_error_t avs_net_socket_get_remote_port(avs_net_socket_t *socket,
                                           char *out_buffer,
                                           size_t out_buffer_size);

/**
 * Returns the IP address @p socket is bound to.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store bound-to IP address in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li @ref AVS_OK for success, in which case @p out_buffer is
 *              guaranteed to be null-terminated,
 *          @li an error condition for which the operation failed.
 */
avs_error_t avs_net_socket_get_local_host(avs_net_socket_t *socket,
                                          char *out_buffer,
                                          size_t out_buffer_size);

/**
 * Returns the local port @p socket is bound to.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store the port (converted
 *                             to a string) in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li @ref AVS_OK for success, in which case @p out_buffer is
 *              guaranteed to be null-terminated,
 *          @li an error condition for which the operation failed.
 */
avs_error_t avs_net_socket_get_local_port(avs_net_socket_t *socket,
                                          char *out_buffer,
                                          size_t out_buffer_size);

/**
 * Returns a socket option value. See @ref avs_net_socket_opt_key_t for
 * a list of available socket options.
 *
 * @param[in]  socket           Socket to operate on.
 * @param[in]  option_key       Socket option to retrieve.
 * @param[out] out_option_value Buffer to store retrieved option value in.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t
avs_net_socket_get_opt(avs_net_socket_t *socket,
                       avs_net_socket_opt_key_t option_key,
                       avs_net_socket_opt_value_t *out_option_value);

/**
 * Sets a socket option value. See @ref avs_net_socket_opt_key_t for a list
 * of available socket options.
 *
 * @param socket       Socket to operate on.
 * @param option_key   Socket option to modify.
 * @param option_value New option_key value.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed.
 */
avs_error_t avs_net_socket_set_opt(avs_net_socket_t *socket,
                                   avs_net_socket_opt_key_t option_key,
                                   avs_net_socket_opt_value_t option_value);

/**
 * Returns a pointer to bare system socket (e.g. to invoke <c>select</c> or
 * <c>poll</c>).
 *
 * <example>
 * @code
 * int socket_fd;
 * const void *socket_ptr = avs_net_socket_get_system(connreq_socket);
 * socket_fd = *((const int *)socket_ptr);
 * @endcode
 * </example>
 *
 * @param socket pointer to <c>avs_net</c> socket
 * @return const pointer to system socket
 */
const void *avs_net_socket_get_system(avs_net_socket_t *socket);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_SOCKET_H */
