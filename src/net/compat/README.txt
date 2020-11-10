When not using the implementation written for POSIX-compatible and POSIX-like
operating systems (WITH_POSIX_AVS_SOCKET=OFF), the following functions need to
be implemented:


avs_error_t _avs_net_create_tcp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration);

avs_error_t _avs_net_create_udp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration);

avs_net_addrinfo_t *avs_net_addrinfo_resolve_ex(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port,
        int flags,
        const avs_net_resolved_endpoint_t *preferred_endpoint);

int avs_net_addrinfo_next(avs_net_addrinfo_t *ctx,
                          avs_net_resolved_endpoint_t *out);

void avs_net_addrinfo_rewind(avs_net_addrinfo_t *ctx);

void avs_net_addrinfo_delete(avs_net_addrinfo_t **ctx);

avs_error_t
avs_net_resolved_endpoint_get_host_port(const avs_net_resolved_endpoint_t *endp,
                                        char *host,
                                        size_t hostlen,
                                        char *serv,
                                        size_t servlen);

avs_error_t avs_net_local_address_for_target_host(const char *target_host,
                                                  avs_net_af_t addr_family,
                                                  char *address_buffer,
                                                  size_t buffer_size);
