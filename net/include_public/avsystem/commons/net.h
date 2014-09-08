/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_SOCKET_H
#define AVS_COMMONS_SOCKET_H

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

typedef struct {
    uint8_t size;
    char data[AVS_NET_SOCKET_RAW_RESOLVED_ENDPOINT_MAX_SIZE];
} avs_net_socket_raw_resolved_endpoint_t;

typedef struct {
    uint8_t                                dscp;
    uint8_t                                priority;
    avs_net_socket_interface_name_t        interface_name;
    avs_net_socket_raw_resolved_endpoint_t *preferred_endpoint;
} avs_net_socket_configuration_t;

/**
 * Alias for address family to avoid leaking POSIX socket API.
 */
typedef enum {
    AVS_NET_AF_UNSPEC,
    AVS_NET_AF_INET4,
    AVS_NET_AF_INET6
} avs_net_af_t;

/**
 * Available SSL versions that can be used by SSL sockets.
 */
typedef enum {
    AVS_SSL_VERSION_DEFAULT = 0,
    AVS_SSL_VERSION_SSLv2_OR_3,
    AVS_SSL_VERSION_SSLv2,
    AVS_SSL_VERSION_SSLv3,
    AVS_SSL_VERSION_TLSv1,
    AVS_SSL_VERSION_TLSv1_1,
    AVS_SSL_VERSION_TLSv1_2 = AVS_SSL_VERSION_DEFAULT
} avs_net_ssl_version_t;

typedef struct {
    avs_net_ssl_version_t version;
    const char *ca_cert_file;
    const char *ca_cert_path;
    const char *client_cert_file;
    const char *client_key_file;
    const char *client_key_password;
    avs_net_socket_configuration_t backend_configuration;
} avs_net_ssl_configuration_t;

typedef enum {
    AVS_NET_SOCKET_OPT_RECV_TIMEOUT,
    AVS_NET_SOCKET_OPT_STATE
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
} avs_net_socket_opt_value_t;

typedef enum {
    AVS_TCP_SOCKET,
    AVS_UDP_SOCKET,
    AVS_SSL_SOCKET
} avs_net_socket_type_t;

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

int avs_net_interface_rx_bytes(avs_net_socket_interface_name_t if_name,
                               uint64_t *bytes);
int avs_net_interface_tx_bytes(avs_net_socket_interface_name_t if_name,
                               uint64_t *bytes);

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

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_SOCKET_H */
