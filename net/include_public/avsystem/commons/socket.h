/*
 * Copyright 2017 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_SOCKET_H
#define AVS_COMMONS_SOCKET_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <avsystem/commons/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* glibc's sockaddr_storage is 128 bytes long, we follow suit */
#define AVS_NET_SOCKET_RAW_RESOLVED_ENDPOINT_MAX_SIZE 128

#define AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT (30 * 1000) /* 30 sec timeout */

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

struct avs_net_abstract_socket_struct;

/**
 * Type for socket abstraction object.
 */
typedef struct avs_net_abstract_socket_struct avs_net_abstract_socket_t;

/**
 * This is a type of data used for binding socket to a specific network
 * interface. For POSIX interfaces it is array of IF_NAMESIZE characters.
 */
typedef char avs_net_socket_interface_name_t[IF_NAMESIZE];

/**
 * Function type for callbacks to be executed for additional SSL configuration.
 *
 * It can be used to set values such as allowed cipher suites.
 *
 * Note that the @ref library_ssl_context parameter is a pointer to a native
 * SSL context object of the SSL library in use. It shall be case to
 * <c>SSL_CTX *</c> for OpenSSL or <c>ssl_context *</c> for XySSL-derivatives.
 *
 * @param library_ssl_context pointer to a native SSL context object of the
 *                            SSL library in use
 *
 * @return 0 on success, negative value on failure
 */
typedef int avs_ssl_additional_configuration_clb_t(void *library_ssl_context);

/**
 * Structure that contains additional configuration options for creating TCP and
 * UDP network sockets.
 *
 * A structure initialized with all zeroes (e.g. using <c>memset()</c>) is
 * a valid, default configuration - it is used when <c>NULL</c> is passed to
 * @ref avs_net_socket_create, and may also be used as a starting point for
 * customizations.
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
} avs_net_socket_configuration_t;

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
 * Private key type. Needs to be specified in cases where the key is given as
 * raw data instead of being read from PEM file.
 */
typedef enum {
    AVS_NET_KEY_TYPE_DEFAULT = 0,
    AVS_NET_KEY_TYPE_EC = AVS_NET_KEY_TYPE_DEFAULT /**< ECC (Elliptic Curve Cryptography) key */
} avs_net_key_type_t;

/**
 * Raw EC private key data.
 */
typedef struct {
    const char *curve_name; /**< elliptic curve name for EC keys */
    const void *private_key; /**< A buffer containing private key data. */
    size_t private_key_size; /**< Length (in bytes) of the @p private_key . */
} avs_net_ssl_raw_ec_t;

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
    AVS_NET_SECURITY_CERTIFICATE = AVS_NET_SECURITY_DEFAULT /**< X509 Certificate + private key */
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
} avs_net_psk_t;

typedef enum {
    AVS_NET_DATA_FORMAT_EC,
    AVS_NET_DATA_FORMAT_DER,
    AVS_NET_DATA_FORMAT_PEM,
    AVS_NET_DATA_FORMAT_PKCS8,
    AVS_NET_DATA_FORMAT_PKCS12
} avs_net_data_format_t;

typedef enum {
    AVS_NET_DATA_SOURCE_FILE,
    AVS_NET_DATA_SOURCE_PATHS,
    AVS_NET_DATA_SOURCE_BUFFER
} avs_net_data_source_t;

typedef struct {
    /** Path to the file */
    const char *path;
    /** NULL-terminated password protecting contents of the file */
    const char *password;
} avs_net_file_t;

typedef struct {
    avs_net_data_source_t source;
    union {
        avs_net_file_t file;
        avs_net_ssl_raw_ec_t ec;
        avs_net_ssl_raw_data_t cert;
        avs_net_ssl_raw_data_t pkcs8;
        avs_net_ssl_raw_data_t pkcs12;
        struct {
            const char *cert_file;
            const char *cert_path;
        } paths;
    } data;
    avs_net_data_format_t format;
} avs_net_security_info_union_t;

typedef struct {
    avs_net_security_info_union_t impl;
} avs_net_client_cert_t;

avs_net_client_cert_t
avs_net_client_cert_from_file(const char *file,
                              const char *password,
                              avs_net_data_format_t format);

avs_net_client_cert_t avs_net_client_cert_from_x509(const void *data,
                                                    size_t data_size);

avs_net_client_cert_t
avs_net_client_cert_from_pkcs12(const void *data,
                                size_t data_size,
                                const char *password);

typedef struct {
    avs_net_security_info_union_t impl;
} avs_net_private_key_t;

avs_net_private_key_t
avs_net_private_key_from_file(const char *path,
                              const char *password,
                              avs_net_data_format_t format);

avs_net_private_key_t avs_net_private_key_from_ec(const char *curve_name,
                                                  const void *private_key,
                                                  size_t private_key_size);

avs_net_private_key_t avs_net_private_key_from_pkcs8(const void *data,
                                                     size_t size,
                                                     const char *password);

avs_net_private_key_t avs_net_private_key_from_pkcs12(const void *data,
                                                      size_t size,
                                                      const char *password);

typedef struct {
    avs_net_security_info_union_t impl;
} avs_net_trusted_cert_source_t;

avs_net_trusted_cert_source_t
avs_net_trusted_cert_source_from_paths(const char *cert_path,
                                       const char *cert_file);

avs_net_trusted_cert_source_t
avs_net_trusted_cert_source_from_file(const char *file,
                                      const char *password,
                                      avs_net_data_format_t format);

avs_net_trusted_cert_source_t
avs_net_trusted_cert_source_from_x509(const void *der, size_t data_size);

avs_net_trusted_cert_source_t
avs_net_trusted_cert_source_from_pkcs12(const void *data,
                                        size_t data_size,
                                        const char *password);

/**
 * Certificate and key information may be read from files or passed as raw data.
 *
 * User should initialize:
 *  - @ref avs_net_certificate_info_t#client_cert,
 *  - @ref avs_net_certificate_info_t#client_key,
 *  - @ref avs_net_certificate_info_t#trusted_certs
 * via helper functions:
 *  - @ref avs_net_client_cert_from_*
 *  - @ref avs_net_client_key_from_*
 *  - @ref avs_net_trusted_cert_source_from_*
 *
 * Moreover, to enable CA chain validation one MUST set @ref
 * avs_net_certificate_info_t#server_cert_validation to true.
 */
typedef struct {
    bool server_cert_validation;
    avs_net_trusted_cert_source_t trusted_certs;

    avs_net_client_cert_t client_cert;
    avs_net_private_key_t client_key;
} avs_net_certificate_info_t;

typedef struct {
    avs_net_security_mode_t mode;
    union {
        avs_net_psk_t psk;
        avs_net_certificate_info_t cert;
    } data;
} avs_net_security_info_t;

avs_net_security_info_t avs_net_security_info_from_psk(avs_net_psk_t psk);
avs_net_security_info_t
avs_net_security_info_from_certificates(avs_net_certificate_info_t info);

#if INT_MAX >= INT_LEAST32_MAX
typedef int avs_net_timeout_t;
#define AVS_FORMAT_NET_TIMEOUT(Type, Letter) #Letter
#else
typedef int_least32_t avs_net_timeout_t;
#define AVS_FORMAT_NET_TIMEOUT(Type, Letter) Type##Letter##LEAST32
#endif

typedef struct {
    avs_net_timeout_t min_ms;
    avs_net_timeout_t max_ms;
} avs_net_dtls_handshake_timeouts_t;

typedef struct {
    avs_net_ssl_version_t version;
    avs_net_security_info_t security;
    const avs_net_dtls_handshake_timeouts_t *dtls_handshake_timeouts;
    avs_ssl_additional_configuration_clb_t *additional_configuration_clb;
    avs_net_socket_configuration_t backend_configuration;
} avs_net_ssl_configuration_t;

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
     * Used the get the maximum size of a buffer that can be passed to
     * @ref avs_net_socket_send or @ref avs_net_socket_send_to and transmitted
     * as a single packet. The value is passed as bytes in the <c>mtu</c> field
     * of the @ref avs_net_socket_opt_value_t union.
     */
    AVS_NET_SOCKET_OPT_INNER_MTU
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

typedef union {
    avs_net_timeout_t recv_timeout;
    avs_net_socket_state_t state;
    avs_net_af_t addr_family;
    int mtu;
} avs_net_socket_opt_value_t;

int avs_net_socket_debug(int value);

/**
 * Creates a new socket of a specified type.
 *
 * @param socket        A variable to hold the newly created socket in. If it
 *                      already is initialized to any socket, the existing
 *                      socket will be destroyed and freed. This also means that
 *                      at first use, the variable <strong>MUST</strong> be
 *                      initialized to <c>NULL</c>.
 *
 * @param sock_type     Type of the socket to create.
 *
 * @param configuration Pointer to additional configuration for the socket to
 *                      create. The type of configuration data is dependent on
 *                      the type of the socket:
 *                      @ref avs_net_socket_configuration_t for a TCP or UDP
 *                      socket (in which case it may also be <c>NULL</c> for
 *                      defaults) or @ref avs_net_ssl_configuration_t for an SSL
 *                      or DTLS socket.
 *
 * @returns 0 on success, a negative value in case of error.
 */
int avs_net_socket_create(avs_net_abstract_socket_t **socket,
                          avs_net_socket_type_t sock_type,
                          const void *configuration);

/**
 * Shuts down @p socket , cleans up any allocated resources and sets
 * <c>*socket</c> to NULL. When called on a socket decorator, also cleans up all
 * lower-layer sockets.
 *
 * @param[inout] socket Socket to clean up.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error. Note that regardless
 *              of the return value, all resources associated with @p socket
 *              are cleaned up and <c>*socket</c> is set to NULL.
 */
int avs_net_socket_cleanup(avs_net_abstract_socket_t **socket);

/**
 * Sets the remote endpoint of @p socket to given @p host : @p port pair.
 * If applicable for given socket type, performs handshakes necessary for
 * setting up communication.
 *
 * @param socket Socket to operate on.
 * @param host   Remote hostname or IP address to connect to.
 * @param port   Remote port to connect to.
 *
 * @returns 0 on success, a negative value in case of error.
 */
int avs_net_socket_connect(avs_net_abstract_socket_t *socket,
                           const char *host,
                           const char *port);

/**
 * Makes @p socket use @p backend_socket as a lower-level socket interface.
 * Used e.g. for decorating a TCP socket with an SSL/TLS one, or for creating
 * a debug proxy.
 *
 * @param socket         Wrapper socket. It must be a newly-created socket
 *                       object (in @ref AVS_NET_SOCKET_STATE_CLOSED state).
 * @param backend_socket Lower-layer socket to wrap.
 *
 * @returns 0 on success, a negative value in case of error.
 */
int avs_net_socket_decorate(avs_net_abstract_socket_t *socket,
                            avs_net_abstract_socket_t *backend_socket);

/**
 * Creates a new socket using given @p new_type and @p configuration ,
 * then performs @ref avs_net_socket_decorate with <c>*socket</c> as the
 * backend socket and replaces <c>*socket</c> with newly-created socket.
 *
 * @param[inout] socket        Pointer to a socket object to use as backend.
 *                             On success, <c>*socket</c> is replaced with
 *                             a newly-created socket of given @p new_type .
 * @param[in]    new_type      Type of the socket to create.
 * @param[in]    configuration Pointer to additional socket configuration to
 *                             pass to @ref avs_net_socket_create .
 *
 * @returns 0 on success, a negative value in case of error. On failure,
 *          <c>*socket</c> value is guaranteed to be left untouched.
 */
int avs_net_socket_decorate_in_place(avs_net_abstract_socket_t **socket,
                                     avs_net_socket_type_t new_type,
                                     const void *configuration);

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
 * @returns @li 0 if exactly @p buffer_length bytes were written,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_send(avs_net_abstract_socket_t *socket,
                        const void *buffer,
                        size_t buffer_length);

/**
 * Sends up to @p buffer_length bytes from @p buffer to @p host / @p port,
 * using @p socket.
 *
 * @li For TCP sockets: @p host and @p are ignored if @p socket is already
 *     connected.
 * @li For UDP sockets: @p buffer is handled as a single datagram. If there is
 *     too much data to fit into a single datagram, the function fails.
 *
 * @param[in]  socket         Socket object to send data to.
 * @param[out] out_bytes_sent On success, set to number of bytes successfully
 *                            sent to @p socket .
 * @param[in]  buffer         Data to send.
 * @param[in]  buffer_length  Number of bytes to send.
 * @param[in]  host           Remote host to send data to. May be an IP address
 *                            as a string, or a domain name.
 * @param[in]  port           Remote port to send data to: an integer as string.
 *
 * @returns @li 0 on success. Unlike @ref avs_net_socket_send, this does not
 *              necessarily mean all @p buffer_length bytes were written.
 *              Inspect @p out_bytes_sent value to check for a short write.
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_send_to(avs_net_abstract_socket_t *socket,
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
 * - the function returns a negative value,
 * - @p socket errno is set to EMSGSIZE. See @ref avs_net_socket_errno .
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
 * @returns @li 0 on success,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_receive(avs_net_abstract_socket_t *socket,
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
 * - the function returns a negative value,
 * - @p socket errno is set to EMSGSIZE. See @ref avs_net_socket_errno .
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
 * @returns @li 0 on success,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_receive_from(avs_net_abstract_socket_t *socket,
                                size_t *out_bytes_received,
                                void *buffer,
                                size_t buffer_length,
                                char *host, size_t host_size,
                                char *port, size_t port_size);

/**
 * Binds @p socket to specified local @p address and @p port .
 *
 * @param socket  Socket object to operate on.
 * @param address Local IP address to bind to.
 * @param port    Local port to bind to.
 *
 * @returns 0 on success, a negative value in case of error.
 */
int avs_net_socket_bind(avs_net_abstract_socket_t *socket,
                        const char *address,
                        const char *port);

/**
 * Accepts an incoming connection targeted at @p server_socket and prepares
 * @p client_socket for communication with connecting host.
 *
 * @param server_socket Listening socket.
 * @param client_socket Socket that will be later used for the accepted
 *                      connection.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 *
 * NOTE: this function fails for connectionless sockets (e.g. UDP).
 */
int avs_net_socket_accept(avs_net_abstract_socket_t *server_socket,
                          avs_net_abstract_socket_t *client_socket);

/**
 * Shuts down the @p socket , so that further communication is not allowed.
 * Discards any buffered, but not yet processed data.
 *
 * @p socket may later be reused by calling @ref avs_net_socket_connect
 * or @ref avs_net_socket_bind .
 *
 * @param socket Socket to close.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 *
 *          Regardless of the return value, the socket is left in
 *          @ref AVS_NET_SOCKET_STATE_CLOSED state and needs to be connected
 *          or bound before using again.
 */
int avs_net_socket_close(avs_net_abstract_socket_t *socket);

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
 * @returns @li 0 on success,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 *
 *          Regardless of the return value, the socket is left in
 *          @ref AVS_NET_SOCKET_STATE_SHUTDOWN state and needs to be connected
 *          or bound before using again.
 */
int avs_net_socket_shutdown(avs_net_abstract_socket_t *socket);

/**
 * Returns the name of an interface @p socket is currently bound to.
 *
 * @param[in]  socket  Bound socket to retrieve interface name for.
 * @param[out] if_name Retrieved interface name.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_interface_name(avs_net_abstract_socket_t *socket,
                                  avs_net_socket_interface_name_t *if_name);

/**
 * Returns the IP address of the remote endpoint @p socket is connected to.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store remote endpoint IP address in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li 0 on success, in which case @p out_buffer is guaranteed to be
 *              null-terminated,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_get_remote_host(avs_net_abstract_socket_t *socket,
                                   char *out_buffer, size_t out_buffer_size);

/**
 * Returns the hostname of the remote endpoint that was used when connecting
 * @p socket. If the socket was connected using the IP address and not
 * a hostname, a stringified IP address is returned.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store remote endpoint hostname in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li 0 on success, in which case @p out_buffer is guaranteed to be
 *              null-terminated,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_get_remote_hostname(avs_net_abstract_socket_t *socket,
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
 * @returns @li 0 on success, in which case @p out_buffer is guaranteed to be
 *              null-terminated,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_get_remote_port(avs_net_abstract_socket_t *socket,
                                   char *out_buffer, size_t out_buffer_size);

/**
 * Returns the IP address @p socket is bound to.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store bound-to IP address in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li 0 on success, in which case @p out_buffer is guaranteed to be
 *              null-terminated,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_get_local_host(avs_net_abstract_socket_t *socket,
                                  char *out_buffer, size_t out_buffer_size);

/**
 * Returns the local port @p socket is bound to.
 *
 * @param[in]  socket          Socket object to operate on.
 * @param[out] out_buffer      Buffer to store the port (converted
 *                             to a string) in.
 * @param[out] out_buffer_size Number of bytes available in @p out_buffer .
 *
 * @returns @li 0 on success, in which case @p out_buffer is guaranteed to be
 *              null-terminated,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_get_local_port(avs_net_abstract_socket_t *socket,
                                  char *out_buffer, size_t out_buffer_size);

/**
 * Returns a socket option value. See @ref avs_net_socket_opt_key_t for
 * a list of available socket options.
 *
 * @param[in]  socket           Socket to operate on.
 * @param[in]  option_key       Socket option to retrieve.
 * @param[out] out_option_value Buffer to store retrieved option value in.
 *
 * @returns @li 0 on success,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_get_opt(avs_net_abstract_socket_t *socket,
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
 * @returns @li 0 on success,
 *          @li a negative value in case of error, in which case @p socket
 *              errno (see @ref avs_net_socket_errno) is set to an appropriate
 *              value.
 */
int avs_net_socket_set_opt(avs_net_abstract_socket_t *socket,
                           avs_net_socket_opt_key_t option_key,
                           avs_net_socket_opt_value_t option_value);

/**
 * @param socket Socket to get errno value from.
 *
 * @returns Current @p socket errno value.
 *
 * NOTE: socket errno is NOT the same as the standard C global <c>errno</c>.
 */
int avs_net_socket_errno(avs_net_abstract_socket_t *socket);

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
const void *avs_net_socket_get_system(avs_net_abstract_socket_t *socket);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_SOCKET_H */
