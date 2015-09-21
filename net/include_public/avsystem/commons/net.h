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

#include <stdint.h>
#include <stdlib.h>

#include <avsystem/commons/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* glibc's sockaddr_storage is 128 bytes long, we follow suit */
#define AVS_NET_SOCKET_RAW_RESOLVED_ENDPOINT_MAX_SIZE 128

#define AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT (30 * 1000) /* 30 sec timeout */

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
    uint8_t size;
    char data[AVS_NET_SOCKET_RAW_RESOLVED_ENDPOINT_MAX_SIZE];
} avs_net_socket_raw_resolved_endpoint_t;

/**
 * Alias for address family to avoid leaking POSIX socket API.
 */
typedef enum {
    AVS_NET_AF_UNSPEC,
    AVS_NET_AF_INET4,
    AVS_NET_AF_INET6
} avs_net_af_t;

typedef struct {
    uint8_t                                dscp;
    uint8_t                                priority;
    uint8_t                                transparent;
    avs_net_socket_interface_name_t        interface_name;
    avs_net_socket_raw_resolved_endpoint_t *preferred_endpoint;
    avs_net_af_t                           address_family;
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
    AVS_NET_SSL_VERSION_TLSv1_2 = AVS_NET_SSL_VERSION_DEFAULT
} avs_net_ssl_version_t;

/**
 * Private key type. Needs to be specified in cases where the key is given as
 * raw data instead of being read from PEM file.
 */
typedef enum {
    AVS_NET_KEY_TYPE_DEFAULT = 0,
    AVS_NET_KEY_TYPE_EC = AVS_NET_KEY_TYPE_DEFAULT //< ECC (Elliptic Curve Cryptography) key
} avs_net_key_type_t;

/**
 * Raw private key data.
 */
typedef struct {
    avs_net_key_type_t type; //< Type of the key stored in @p private_key buffer.
    const char *curve_name; //< elliptic curve name for EC keys
    const void *private_key; //< A buffer containing private key data.
    size_t private_key_size; //< Length (in bytes) of the @p private_key .
} avs_net_ssl_raw_key_t;

/**
 * X509 certificate data in DER format.
 */
typedef struct {
    const void *cert_der; //< DER-encoded X509 certificate.
    size_t cert_size; //< Length (in bytes) of the @p cert_der .
} avs_net_ssl_raw_cert_t;

typedef enum {
    AVS_NET_SECURITY_DEFAULT = 0,
    AVS_NET_SECURITY_PSK, //< Pre-Shared Key
    AVS_NET_SECURITY_CERTIFICATE = AVS_NET_SECURITY_DEFAULT //< X509 Certificate + private key
} avs_net_security_mode_t;

/**
 * @returns number of bytes written to @p out_key on success,
 * 0 in case of error. On success @p out_identity must be NULL-terminated.
 */
typedef size_t avs_net_psk_getter_t(void *user_data,
                                    const char *identity_hint,
                                    char *out_identity,
                                    size_t identity_size,
                                    void *out_key,
                                    size_t key_size);
typedef void avs_net_psk_free_data_t(void *data);

typedef struct {
    avs_net_psk_getter_t *getter; //< PSK getter handler, called whenever the library needs the key to perform SSL handshake.
    void *getter_data; //< Custom data passed to the @p getter .
    avs_net_psk_free_data_t *free_getter_data; //< A handler used to release @p getter_data when it is no longer needed. May be NULL if @p getter_data does not need cleanup. Will not be called on NULL @p getter_data.
} avs_net_psk_t;

typedef enum {
    AVS_NET_DATA_SOURCE_FILE,
    AVS_NET_DATA_SOURCE_BUFFER
} avs_net_data_source_t;

typedef struct {
    avs_net_data_source_t source;
    union {
        const char *file;
        avs_net_ssl_raw_cert_t buffer;
    } data;
} avs_net_client_cert_t;

static inline avs_net_client_cert_t
avs_net_client_cert_from_file(const char *file) {
    return (avs_net_client_cert_t) {
        .source = AVS_NET_DATA_SOURCE_FILE,
        .data = {
            .file = file
        }
    };
}

static inline avs_net_client_cert_t
avs_net_client_cert_from_memory(const void *cert_der,
                                size_t cert_size) {
    return (avs_net_client_cert_t) {
        .source = AVS_NET_DATA_SOURCE_BUFFER,
        .data = {
            .buffer = {
                .cert_der = cert_der,
                .cert_size = cert_size
            }
        }
    };
}

typedef struct {
    avs_net_data_source_t source;
    union {
        struct {
            const char *path; //< private key file path
            const char *password; //< NULL-terminated password for the private key file
        } file;
        avs_net_ssl_raw_key_t buffer;
    } data;
} avs_net_private_key_t;

static inline avs_net_private_key_t
avs_net_private_key_from_file(const char *path,
                              const char *password) {
    return (avs_net_private_key_t) {
        .source = AVS_NET_DATA_SOURCE_FILE,
        .data = {
            .file = {
                .path = path,
                .password = password
            }
        }
    };
}

static inline avs_net_private_key_t
avs_net_private_key_from_memory(avs_net_key_type_t type,
                                const char *curve_name,
                                const void *private_key,
                                size_t private_key_size) {
    return (avs_net_private_key_t) {
        .source = AVS_NET_DATA_SOURCE_BUFFER,
        .data = {
            .buffer = {
                .type = type,
                .curve_name = curve_name,
                .private_key = private_key,
                .private_key_size = private_key_size
            }
        }
    };
}

/**
 * Certificate and key information may be read from files or passed as raw data.
 *
 * Setting both filename and data pointer for client_key/client_cert is invalid.
 *
 * ca_cert_raw may be used with ca_cert_file/ca_cert_path to add an extra CA
 * certificate to the certificate store,
 */
typedef struct {
    const char *ca_cert_file;
    const char *ca_cert_path;
    avs_net_ssl_raw_cert_t ca_cert_raw;

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

static inline avs_net_security_info_t
avs_net_security_info_from_psk(avs_net_psk_t psk) {
    return (avs_net_security_info_t) {
        .mode = AVS_NET_SECURITY_PSK,
        .data.psk = psk
    };
}

static inline avs_net_security_info_t
avs_net_security_info_from_certificates(avs_net_certificate_info_t info) {
    return (avs_net_security_info_t) {
        .mode = AVS_NET_SECURITY_CERTIFICATE,
        .data.cert = info
    };
}

typedef struct {
    avs_net_ssl_version_t version;
    avs_net_security_info_t security;
    avs_ssl_additional_configuration_clb_t *additional_configuration_clb;
    avs_net_socket_configuration_t backend_configuration;
} avs_net_ssl_configuration_t;

typedef enum {
    AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
    AVS_NET_SOCKET_OPT_STATE,
    AVS_NET_SOCKET_OPT_ADDR_FAMILY,
    AVS_NET_SOCKET_OPT_MTU
} avs_net_socket_opt_key_t;

typedef enum {
    AVS_NET_SOCKET_STATE_CLOSED,
    AVS_NET_SOCKET_STATE_SHUTDOWN,
    AVS_NET_SOCKET_STATE_LISTENING,
    AVS_NET_SOCKET_STATE_SERVING,
    AVS_NET_SOCKET_STATE_CONSUMING
} avs_net_socket_state_t;

typedef union {
    int recv_timeout;
    avs_net_socket_state_t state;
    avs_net_af_t addr_family;
    int mtu;
} avs_net_socket_opt_value_t;

typedef enum {
    AVS_NET_TCP_SOCKET,
    AVS_NET_UDP_SOCKET,
    AVS_NET_SSL_SOCKET,
    AVS_NET_DTLS_SOCKET
} avs_net_socket_type_t;

int avs_net_socket_debug(int value);

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

int avs_net_socket_get_interface(avs_net_abstract_socket_t *socket,
                                 avs_net_socket_interface_name_t *if_name);

int avs_net_local_address_for_target_host(const char *target_host,
                                            avs_net_af_t addr_family,
                                            char *address_buffer,
                                            size_t buffer_size);

int avs_net_validate_ip_address(avs_net_af_t family, const char *ip_address);

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_NET_H */
