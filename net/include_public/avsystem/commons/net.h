/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_NET_H
#define AVS_COMMONS_NET_H

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

struct avs_net_addrinfo_struct;

/**
 * Type for address resolution abstraction context.
 */
typedef struct avs_net_addrinfo_struct avs_net_addrinfo_t;

#define AVS_NET_ADDRINFO_END 1

/**
 * When calling @ref avs_net_addrinfo_resolve_ex with this bit set in the
 * <c>flags</c> parameter, a DNS query is not performed. Binary endpoint will
 * only be available for successful retrieval if the <c>host</c> passed is a
 * valid, unambiguous textual representation of an already resolved IP address.
 *
 * This is equivalent to <c>AI_PASSIVE</c> flag to <c>getaddrinfo()</c>.
 */
#define AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE  (1 << 0)

/**
 * When calling @ref avs_net_addrinfo_resolve_ex with this bit set in the
 * <c>flags</c> parameter and with <c>family</c> set to <c>AVS_NET_AF_INET6</c>,
 * IPv4 addresses will be resolved as well, and converted to IPv4-mapped IPv6
 * addresses in output.
 *
 * This is roughly equivalent to <c>AI_V4MAPPED | AI_ALL</c> flags to
 * <c>getaddrinfo()</c>, but implemented independently of them.
 *
 * This flag is meaningful only if the plaform supports both IPv4 and IPv6.
 * Otherwise it is ignored.
 */
#define AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED (1 << 1)

/**
 * Resolves a text-represented host and port address to its binary
 * representation, possibly executing a DNS query as necessary.
 *
 * If there are multiple addresses that correspond to the specified names, they
 * are returned in randomized order.
 *
 * @param socket_type        Type of the socket for which the resolving is
 *                           performed. Valid values are
 *                           <c>AVS_NET_TCP_SOCKET</c> and
 *                           <c>AVS_NET_UDP_SOCKET</c>.
 *
 * @param family             Family of the address to resolve.
 *                           <c>AVS_NET_AF_UNSPEC</c> means that an address of
 *                           any supported type may be returned.
 *
 * @param host               Host name.
 *
 * @param port               Port number represented as a string.
 *
 * @param flags              Either 0 or a bit mask of one or more
 *                           <c>AVS_NET_ADDRINFO_RESOLVE_F_*</c> constants.
 *                           Please see their documentation for details.
 *
 * @param preferred_endpoint Preferred resolved address. If it is found among
 *                           the resolved addresses, it is returned on the first
 *                           position.
 *
 * @return A new instance of @ref avs_net_addrinfo_t that may be queried using
 *         @ref avs_net_addrinfo_next and has to be freed using
 *         @ref avs_net_addrinfo_delete. If an error occured, <c>NULL</c> is
 *         returned.
 */
avs_net_addrinfo_t *avs_net_addrinfo_resolve_ex(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        int flags,
        const avs_net_resolved_endpoint_t *preferred_endpoint);

/**
 * Equivalent to @ref avs_net_addrinfo_resolve_ex with <c>flags</c> set to 0.
 */
avs_net_addrinfo_t *avs_net_addrinfo_resolve(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        const avs_net_resolved_endpoint_t *preferred_endpoint);

/**
 * Frees an object allocated by @ref avs_net_addrinfo_resolve or
 * @ref avs_net_addrinfo_resolve_ex.
 *
 * @param ctx Pointer to a variable holding an instance of
 *            @ref avs_net_addrinfo_t. It will be freed and zeroed.
 */
void avs_net_addrinfo_delete(avs_net_addrinfo_t **ctx);

/**
 * Returns a binary representation of the address previously queried for
 * resolution using @ref avs_net_addrinfo_resolve or
 * @ref avs_net_addrinfo_resolve_ex.
 *
 * Calling this function more than once will return subsequent alternative
 * addresses, if any.
 *
 * @param ctx A context object returned from @ref avs_net_addrinfo_resolve or
 *            @ref avs_net_addrinfo_resolve_ex.
 * @param out Pointer to variable in which to store the result.
 *
 * @return @li 0 for success
 *         @li negative value in case of error
 *         @li <c>AVS_NET_ADDRINFO_END</c> if there are no more addresses to
 *             return
 */
int avs_net_addrinfo_next(avs_net_addrinfo_t *ctx,
                          avs_net_resolved_endpoint_t *out);

/**
 * "Rewinds" a list of resolved addresses, so that a following call to
 * @ref avs_net_addrinfo_next will return the same value as the first call for
 * given context.
 *
 * @param ctx A context object returned from @ref avs_net_addrinfo_resolve or
 *            @ref avs_net_addrinfo_resolve_ex.
 */
void avs_net_addrinfo_rewind(avs_net_addrinfo_t *ctx);

/**
 * Translates a binary representation of a socket address to textual
 * representation.
 *
 * @param endp    The socket address to convert.
 *
 * @param host    Buffer in which to store the textual representation of the
 *                numerical host address.
 *
 * @param hostlen Size in bytes of the buffer pointed to by <c>host</c>.
 *
 * @param serv    Buffer in which to store the textual representation of the
 *                port number.
 *
 * @param servlen Size in bytes of the buffer pointed to by <c>serv</c>.
 *
 * Either <c>host</c> or <c>serv</c> arguments may be <c>NULL</c> in which case
 * only the non-<c>NULL</c> argument is filled in.
 *
 * @return 0 for success, or a negative value in case of error.
 */
int avs_net_resolved_endpoint_get_host_port(
        const avs_net_resolved_endpoint_t *endp,
        char *host, size_t hostlen,
        char *serv, size_t servlen);

/**
 * Equivalent to @ref avs_net_resolved_endpoint_get_host_port with the
 * <c>serv</c> argument set to <c>NULL</c>.
 *
 * @param endp    The socket address to convert.
 *
 * @param host    Buffer in which to store the textual representation of the
 *                numerical host address.
 *
 * @param hostlen Size in bytes of the buffer pointed to by <c>host</c>.
 *
 * @return 0 for success, or a negative value in case of error.
 */
int avs_net_resolved_endpoint_get_host(const avs_net_resolved_endpoint_t *endp,
                                       char *host, size_t hostlen);

/**
 * A convenience function that handles the most common use case of host address
 * resolution. It resolves a host name (possibly by doing a DNS query in the
 * common case of it being a symbolic name) and returns a string representation
 * of one of its numerical addresses. If multiple addresses are available, one
 * of them is chosen at random.
 *
 * This call is essentially equivalent to calling @ref avs_net_addrinfo_resolve
 * (with a dummy port number), getting the first result (if available) using
 * @ref avs_net_addrinfo_next and stringifying it using
 * @ref avs_net_resolved_endpoint_get_host.
 *
 * @param socket_type       Type of the socket for which the resolving is
 *                          performed. Valid values are
 *                          <c>AVS_NET_TCP_SOCKET</c> and
 *                          <c>AVS_NET_UDP_SOCKET</c>.
 *
 * @param family            Family of the address to resolve.
 *                          <c>AVS_NET_AF_UNSPEC</c> means that an address of
 *                          any supported type may be returned.
 *
 * @param host              Host name to resolve.
 *
 * @param resolved_buf      Buffer in which to store the textual representation
 *                          of the numerical host address.
 *
 * @param resolved_buf_size Size in bytes of the buffer pointed to by
 *                          <c>resolved_buf</c>.
 *
 * @ref 0 for success, or a non-zero value in case of error.
 */
int avs_net_resolve_host_simple(avs_net_socket_type_t socket_type,
                                avs_net_af_t family,
                                const char *host,
                                char *resolved_buf, size_t resolved_buf_size);

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

typedef struct {
    void *psk;
    size_t psk_size;
    void *identity;
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

typedef struct {
    uint32_t min_seconds;
    uint32_t max_seconds;
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

#if INT_MAX >= INT_LEAST32_MAX
typedef int avs_net_timeout_t;
#define AVS_FORMAT_NET_TIMEOUT(Type, Letter) #Letter
#else
typedef int_least32_t avs_net_timeout_t;
#define AVS_FORMAT_NET_TIMEOUT(Type, Letter) Type##Letter##LEAST32
#endif

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
 */
int avs_net_socket_create(avs_net_abstract_socket_t **socket,
                          avs_net_socket_type_t sock_type,
                          const void *configuration);

int avs_net_socket_decorate_in_place(avs_net_abstract_socket_t **socket,
                                     avs_net_socket_type_t new_type,
                                     const void *configuration);

int avs_net_socket_cleanup(avs_net_abstract_socket_t **socket);

int avs_net_socket_connect(avs_net_abstract_socket_t *socket,
                           const char *host,
                           const char *port);
int avs_net_socket_decorate(avs_net_abstract_socket_t *socket,
                            avs_net_abstract_socket_t *backend_socket);
int avs_net_socket_send(avs_net_abstract_socket_t *socket,
                        const void *buffer,
                        size_t buffer_length);
int avs_net_socket_send_to(avs_net_abstract_socket_t *socket,
                           size_t *out_bytes_sent,
                           const void *buffer,
                           size_t buffer_length,
                           const char *host,
                           const char *port);
/**
 * @param      socket             Socket object to read data from.
 * @param[out] out_bytes_received Number of bytes successfully read into
 *                                @p buffer after a call to this function.
 * @param      buffer             Buffer to write read bytes to.
 * @param      buffer_length      Number of bytes available in @p buffer .
 *
 * @returns 0 on success, a negative value in case of error. If an error
 *          occurred, socket errno is set to indicate a specific error case.
 *          See @ref avs_net_socket_errno .
 *
 * For UDP datagrams whose length exceeds @p buffer_length :
 * - @p buffer is filled with @p buffer_length initial bytes of data,
 * - @p buffer_length is returned via @p out_bytes_received ,
 * - the function returns a negative value,
 * - @p socket errno is set to EMSGSIZE. See @ref avs_net_socket_errno .
 * That means, one can still access the truncated message if required. Note
 * that the actual length of received datagram is lost.
 *
 * WARNING: When LwIP is used as a UDP/IP stack, this function will report the
 * UDP datagram as truncated if it is exactly @p buffer_length bytes long.
 */
int avs_net_socket_receive(avs_net_abstract_socket_t *socket,
                           size_t *out_bytes_received,
                           void *buffer,
                           size_t buffer_length);

/**
 * @param      socket             Socket object to read data from.
 * @param[out] out_bytes_received Number of bytes successfully read into
 *                                @p buffer after a call to this function.
 * @param      buffer             Buffer to write received bytes to.
 * @param      buffer_length      Number of bytes available in @p buffer .
 * @param[out] host               Buffer to store sender hostname. If possible,
 *                                @p host is set to sender domain name,
 *                                otherwise it is the sender IP address
 *                                converted to a string.
 * @param      host_size          Number of bytes available in @p host .
 * @param[out] port               Buffer to store the port a message was sent
 *                                from, converted to a string.
 * @param      port_size          Number of bytes available in @p port .
 *
 * @returns 0 on success, a negative value in case of error. If an error
 *          occurred, socket errno is set to indicate a specific error case.
 *          See @ref avs_net_socket_errno .
 *
 * For UDP datagrams whose length exceeds @p buffer_length :
 * - @p buffer is filled with @p buffer_length initial bytes of data,
 * - @p buffer_length is returned via @p out_bytes_received ,
 * - the function returns a negative value,
 * - @p socket errno is set to EMSGSIZE. See @ref avs_net_socket_errno .
 * That means, one can still access the truncated message if required. Note
 * that the actual length of received datagram is lost.
 *
 * WARNING: When LwIP is used as a UDP/IP stack, this function will report the
 * UDP datagram as truncated if it is exactly @p buffer_length bytes long.
 */
int avs_net_socket_receive_from(avs_net_abstract_socket_t *socket,
                                size_t *out_bytes_received,
                                void *buffer,
                                size_t buffer_length,
                                char *host, size_t host_size,
                                char *port, size_t port_size);
int avs_net_socket_bind(avs_net_abstract_socket_t *socket,
                        const char *address,
                        const char *port);
int avs_net_socket_accept(avs_net_abstract_socket_t *server_socket,
                          avs_net_abstract_socket_t *client_socket);
int avs_net_socket_close(avs_net_abstract_socket_t *socket);
int avs_net_socket_shutdown(avs_net_abstract_socket_t *socket);
int avs_net_socket_interface_name(avs_net_abstract_socket_t *socket,
                                  avs_net_socket_interface_name_t *if_name);
int avs_net_socket_get_remote_host(avs_net_abstract_socket_t *socket,
                                   char *out_buffer, size_t out_buffer_size);
int avs_net_socket_get_remote_hostname(avs_net_abstract_socket_t *socket,
                                       char *out_buffer,
                                       size_t out_buffer_size);
int avs_net_socket_get_remote_port(avs_net_abstract_socket_t *socket,
                                   char *out_buffer, size_t out_buffer_size);
int avs_net_socket_get_local_port(avs_net_abstract_socket_t *socket,
                                  char *out_buffer, size_t out_buffer_size);
int avs_net_socket_get_opt(avs_net_abstract_socket_t *socket,
                           avs_net_socket_opt_key_t option_key,
                           avs_net_socket_opt_value_t *out_option_value);
int avs_net_socket_set_opt(avs_net_abstract_socket_t *socket,
                           avs_net_socket_opt_key_t option_key,
                           avs_net_socket_opt_value_t option_value);
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

int avs_net_local_address_for_target_host(const char *target_host,
                                          avs_net_af_t addr_family,
                                          char *address_buffer,
                                          size_t buffer_size);

int avs_net_validate_ip_address(avs_net_af_t family, const char *ip_address);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_NET_H */
