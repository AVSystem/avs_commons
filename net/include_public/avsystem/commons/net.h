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
 * @param preferred_endpoint Preferred resolved address. If it is found among
 *                           the resolved addresses, it is returned on the first
 *                           position.
 *
 * @return A new instance of @ref avs_net_addrinfo_t that may be queried using
 *         @ref avs_net_addrinfo_next and has to be freed using
 *         @ref avs_net_addrinfo_delete. If an error occured, <c>NULL</c> is
 *         returned.
 */
avs_net_addrinfo_t *avs_net_addrinfo_resolve(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        const avs_net_resolved_endpoint_t *preferred_endpoint);

/**
 * Frees an object allocated by @ref avs_net_addrinfo_resolve.
 *
 * @param ctx Pointer to a variable holding an instance of
 *            @ref avs_net_addrinfo_t. It will be freed and zeroed.
 */
void avs_net_addrinfo_delete(avs_net_addrinfo_t **ctx);

/**
 * Returns a binary representation of the address previously queried for
 * resolution using @ref avs_net_addrinfo_resolve.
 *
 * Calling this function more than once will return subsequent alternative
 * addresses, if any.
 *
 * @param ctx A context object returned from @ref avs_net_addrinfo_resolve.
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
 * @param ctx A context object returned from @ref avs_net_addrinfo_resolve.
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

typedef struct {
    uint8_t                         dscp;
    uint8_t                         priority;
    /**
     * This flag is used to set SO_REUSEADDR on the underlying system socket.
     */
    uint8_t                         reuse_addr;
    uint8_t                         transparent;
    avs_net_socket_interface_name_t interface_name;
    avs_net_resolved_endpoint_t    *preferred_endpoint;
    avs_net_af_t                    address_family;
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
 * Raw private key data.
 */
typedef struct {
    avs_net_key_type_t type; /**< Type of the key stored in @p private_key buffer. */
    const char *curve_name; /**< elliptic curve name for EC keys */
    const void *private_key; /**< A buffer containing private key data. */
    size_t private_key_size; /**< Length (in bytes) of the @p private_key . */
} avs_net_ssl_raw_key_t;

/**
 * X509 certificate data in DER format.
 */
typedef struct {
    const void *cert_der; /**< DER-encoded X509 certificate. */
    size_t cert_size; /**< Length (in bytes) of the @p cert_der . */
} avs_net_ssl_raw_cert_t;

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
    AVS_NET_DATA_FORMAT_DER,
    AVS_NET_DATA_FORMAT_PEM,
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
    avs_net_data_format_t format;
    union {
        avs_net_file_t file;
        avs_net_ssl_raw_cert_t buffer;
    } data;
} avs_net_client_cert_t;

avs_net_client_cert_t
avs_net_client_cert_from_file(const char *file,
                              const char *password,
                              avs_net_data_format_t format);

avs_net_client_cert_t avs_net_client_cert_from_memory(const void *der_cert,
                                                      size_t cert_size);

typedef struct {
    avs_net_data_source_t source;
    avs_net_data_format_t format;
    union {
        avs_net_file_t file;
        avs_net_ssl_raw_key_t buffer;
    } data;
} avs_net_private_key_t;

avs_net_private_key_t
avs_net_private_key_from_file(const char *path,
                              const char *password,
                              avs_net_data_format_t format);

avs_net_private_key_t avs_net_private_key_from_memory(avs_net_key_type_t type,
                                                      const char *curve_name,
                                                      const void *private_key,
                                                      size_t private_key_size);

typedef struct {
    avs_net_data_source_t source;
    avs_net_data_format_t format;
    union {
        avs_net_file_t file;
        avs_net_ssl_raw_cert_t raw;
        struct {
            const char *cert_file;
            const char *cert_path;
        } paths;
    } data;
} avs_net_trusted_cert_source_t;

avs_net_trusted_cert_source_t
avs_net_trusted_cert_source_from_paths(const char *cert_file,
                                       const char *cert_path);

avs_net_trusted_cert_source_t
avs_net_trusted_cert_source_from_file(const char *file,
                                      const char *password,
                                      avs_net_data_format_t format);

avs_net_trusted_cert_source_t
avs_net_trusted_cert_source_from_memory(const void *der, size_t size);

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
 * avs_net_certificate_info_t#server_cert_validation to a nonzero value.
 */
typedef struct {
    char server_cert_validation;
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
    avs_net_ssl_version_t version;
    avs_net_security_info_t security;
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
    AVS_NET_SOCKET_STATE_CLOSED,
    AVS_NET_SOCKET_STATE_SHUTDOWN,
    AVS_NET_SOCKET_STATE_LISTENING,
    AVS_NET_SOCKET_STATE_SERVING,
    AVS_NET_SOCKET_STATE_CONSUMING
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
int avs_net_socket_receive(avs_net_abstract_socket_t *socket,
                           size_t *out_bytes_received,
                           void *buffer,
                           size_t buffer_length);
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
