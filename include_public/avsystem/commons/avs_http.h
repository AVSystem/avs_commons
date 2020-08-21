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

#ifndef AVS_COMMONS_HTTP_H
#define AVS_COMMONS_HTTP_H

#include <avsystem/commons/avs_list.h>
#include <avsystem/commons/avs_net.h>
#include <avsystem/commons/avs_stream.h>
#include <avsystem/commons/avs_url.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file avs_http.h
 *
 * Simple HTTP client.
 */

/**
 * Structure that configures buffer sizes for the HTTP client.
 */
typedef struct {
    /**
     * Size of a buffer used when receiving content body.
     *
     * Configured to 4096 in @ref AVS_HTTP_DEFAULT_BUFFER_SIZES.
     */
    size_t body_recv;

    /**
     * Size of a buffer used when sending content body.
     *
     * Configured to 4096 in @ref AVS_HTTP_DEFAULT_BUFFER_SIZES.
     */
    size_t body_send;

    /**
     * When zlib-based compression or decompression of HTTP content body is
     * used, this will be the size of the input buffer for zlib operation.
     *
     * Additionally, zlib's output buffer is hard-configured to 120% of this
     * value.
     *
     * Configured to 4096 in @ref AVS_HTTP_DEFAULT_BUFFER_SIZES, which means
     * 4096 bytes in input buffer and 4915 bytes in output buffer.
     *
     * Setting this to 0 will disable support for HTTP compression.
     */
    size_t content_coding_input;

    /**
     * When zlib-based compression or decompression of HTTP content body is
     * used, this will be the minimum number of bytes fed into compression or
     * decompression algorithm whenever more processed data is necessary
     * (provided that enough data is available in the input stream).
     *
     * In other words, this is the minimum number of bytes on input for which it
     * is considered that zlib is guaranteed to generate some output, during
     * both compression and decompression.
     *
     * Configured to 128 in @ref AVS_HTTP_DEFAULT_BUFFER_SIZES.
     */
    size_t content_coding_min_input;

    /**
     * Size of buffer used when receiving HTTP headers. Header lines that do not
     * fit in this limit (including the terminating null byte) will cause an
     * error.
     *
     * Configured to 512 in @ref AVS_HTTP_DEFAULT_BUFFER_SIZES.
     */
    size_t header_line;

    /**
     * Size of the receive buffer attached to communication socket. Its value is
     * normally relevant only when receiving non-body data such as headers and
     * chunk sizes for chunked encoding. When receiving the content body, the
     * <c>body_recv</c> buffer size, which is expected to be much larger, is
     * generally more important. However, the expectation is that even when
     * receiving auxiliary data, the application will not call to the operating
     * system more often than once every <c>recv_shaper</c> received bytes.
     *
     * Configured to 128 in @ref AVS_HTTP_DEFAULT_BUFFER_SIZES.
     */
    size_t recv_shaper;

    /**
     * Size of the send buffer attached to communication socket. Its value is
     * normally relevant only when sending non-body data such as headers and
     * chunk sizes for chunked encoding. When sending the content body, the
     * <c>body_send</c> buffer size, which is expected to be much larger, is
     * generally more important. However, the expectation is that even when
     * sending auxiliary data, the application will not send IP packets smaller
     * than <c>send_shaper</c> bytes.
     *
     * Configured to 128 in @ref AVS_HTTP_DEFAULT_BUFFER_SIZES.
     */
    size_t send_shaper;
} avs_http_buffer_sizes_t;

/**
 * Default configuration for HTTP client buffer sizes. See
 * @ref avs_http_buffer_sizes_t for details.
 */
extern const avs_http_buffer_sizes_t AVS_HTTP_DEFAULT_BUFFER_SIZES;

/**
 * HTTP request method.
 */
typedef enum { AVS_HTTP_GET, AVS_HTTP_POST, AVS_HTTP_PUT } avs_http_method_t;

/**
 * HTTP Content-Encoding type.
 *
 * Note that <c>AVS_HTTP_CONTENT_GZIP</c> and <c>AVS_HTTP_CONTENT_DEFLATE</c>
 * are supported only if the library has been compiled with the
 * <c>WITH_AVS_HTTP_ZLIB</c> compile-time flag, and
 * <c>AVS_HTTP_CONTENT_COMPRESS</c> is currently unsupported and only present
 * for API completeness.
 */
typedef enum {
    AVS_HTTP_CONTENT_IDENTITY,
    AVS_HTTP_CONTENT_GZIP,
    AVS_HTTP_CONTENT_COMPRESS,
    AVS_HTTP_CONTENT_DEFLATE
} avs_http_content_encoding_t;

/**
 * Information about a header line received in a HTTP response.
 *
 * Instances accessible to the user using @ref avs_http_set_header_storage will
 * contain values of the key and value in the same chunk of allocated memory as
 * the structure itself, so a single @ref AVS_LIST_DELETE is sufficient to clean
 * up all used resources.
 */
typedef struct {
    /**
     * Keyword of the HTTP header.
     */
    const char *key;

    /**
     * Value of the HTTP header.
     */
    const char *value;

    /**
     * True if the header has already been internally interpreted by
     * <c>avs_http</c>, or false otherwise.
     */
    bool handled;
} avs_http_header_t;

/**
 * HTTP client object type.
 *
 * The HTTP client manages data that may be persisted between individual
 * requests within a related session. Namely, it contains cookie storage and
 * global configuration: user agent, TCP and SSL socket configuration options.
 */
struct avs_http;
typedef struct avs_http avs_http_t;

/**
 * Creates a new HTTP client object.
 *
 * @param buffer_sizes Buffer sizes to use in the created client.
 *
 * @returns The created HTTP client object, or <c>NULL</c> in case of error.
 */
avs_http_t *avs_http_new(const avs_http_buffer_sizes_t *buffer_sizes);

/**
 * Deletes an HTTP client object and frees any resources used by it.
 *
 * NOTE: If any streams spawned from the specified client still exist,
 * attempting to delete the client yields undefined behaviour.
 *
 * @param http The HTTP client object to clean up.
 */
void avs_http_free(avs_http_t *http);

#ifdef AVS_COMMONS_WITH_AVS_CRYPTO
/**
 * Sets SSL/TLS configuration for sockets created by the the HTTP client when
 * connecting to HTTPS addresses.
 *
 * @param http              HTTP client to operate on.
 *
 * @param ssl_configuration Pointer to SSL configuration structure to use. The
 *                          structure is not copied, so it shall remain valid
 *                          for the entire lifetime of the HTTP client object.
 *                          <c>NULL</c> may be used to revert to default
 *                          configuration.
 */
void avs_http_ssl_configuration(
        avs_http_t *http,
        const volatile avs_net_ssl_configuration_t *ssl_configuration);
#endif // AVS_COMMONS_WITH_AVS_CRYPTO

/**
 * Callback function type used by @ref avs_http_ssl_pre_connect_cb .
 *
 * @param http     HTTP client for which the function is called.
 *
 * @param socket   Freshly created SSL/TLS socket.
 *
 * @param hostname Name of the host to which the socket will be connected after
 *                 successful return from this callback.
 *
 * @param port     Port to which the socket will be connected after successful
 *                 return from this function.
 *
 * @param user_ptr Opaque pointer previously set using
 *                 @ref avs_http_ssl_pre_connect_cb.
 *
 * @return Error code. If not AVS_OK, the exchange will be aborted and the error
 *         will be forwarded through @ref avs_http_open_stream (or some stream
 *         method in case of redirection attempt).
 */
typedef avs_error_t avs_http_ssl_pre_connect_cb_t(avs_http_t *http,
                                                  avs_net_socket_t *socket,
                                                  const char *hostname,
                                                  const char *port,
                                                  void *user_ptr);

/**
 * Sets callback that will be executed before calling
 * @ref avs_net_socket_connect on a newly created SSL/TLS socket.
 *
 * It can be used to e.g. support DANE.
 *
 * @param http     HTTP client to operate on.
 *
 * @param cb       Pointer to a callback function.
 *
 * @param user_ptr Opaque pointer that will be forwarded to the callback
 *                 function on every call.
 */
void avs_http_ssl_pre_connect_cb(avs_http_t *http,
                                 avs_http_ssl_pre_connect_cb_t *cb,
                                 void *user_ptr);

/**
 * Sets TCP configuration for sockets created by the the HTTP client when
 * connecting to both HTTP and HTTPS addresses.
 *
 * NOTE: If both @ref avs_http_ssl_configuration and
 * @ref avs_http_tcp_configuration are set with non-NULL configuration
 * structures, when connecting to HTTPS addresses, the structure passed to
 * @ref avs_http_tcp_configuration takes precedence over the
 * <c>backend_configuration</c> field from the structure passed to
 * @ref avs_http_ssl_configuration.
 *
 * @param http              HTTP client to operate on.
 *
 * @param ssl_configuration Pointer to TCP configuration structure to use. The
 *                          structure is not copied, so it shall remain valid
 *                          for the entire lifetime of the HTTP client object.
 *                          <c>NULL</c> may be used to revert to default
 *                          configuration.
 */
void avs_http_tcp_configuration(
        avs_http_t *http,
        const volatile avs_net_socket_configuration_t *tcp_configuration);

/**
 * Configures the HTTP user agent string to use when making HTTP requests.
 *
 * @param http       HTTP client to operate on.
 *
 * @param user_agent The user agent string to use. May be <c>NULL</c>, in which
 *                   case the <c>User-Agent</c> header will not be sent at all.
 *                   The string is copied using <c>strdup()</c>, so there are no
 *                   requirements on the lifetime of the pointer passed.
 *
 * @return 0 for success, or a negative value in case of an out-of-memory error.
 */
int avs_http_set_user_agent(avs_http_t *http, const char *user_agent);

/**
 * Creates a new HTTP stream, which may be used to perform a series of related
 * HTTP requests, nominally within a single connection to the same server.
 *
 * The stream may reconnect if necessary, it may even change the target location
 * if an HTTP 3xx status code is received - but from the user standpoint, it can
 * be seen as a single conversation with a single server.
 *
 * <c>avs_stream_t</c> methods are implemented as follows:
 *
 * - <c>avs_stream_write_some</c> - appends some data to the request content,
 *   possibly compressing it on the fly according to the <c>encoding</c>
 *   specified.
 *
 * - <c>avs_stream_finish_message</c> - performs the HTTP request, with content
 *   formed from preceding writes, and possibly custom headers specified via
 *   @ref avs_http_add_header. Puts the stream in receiving state afterwards.
 *
 * - <c>avs_stream_read</c> - reads from the content of the response sent by the
 *   server, decompressing it on the fly if possible and applicable. At the end
 *   of the response, <c>message_finished</c> is set to true and the stream is
 *   put in sending state afterwards.
 *
 * - <c>avs_stream_peek</c> - peeks a byte from the content of the response
 *   without consuming it. The possible peek range varies depending on content
 *   and transfer encodings used by the server, but will be the value of the
 *   <c>body_recv</c> field of the @ref avs_http_buffer_sizes_t structure (4 KiB
 *   by default), decreased by chunked encoding header line length if used, for
 *   uncompressed response bodies, and in the order of the
 *   <c>content_coding_min_input</c> field from the same structure (128 bytes by
 *   default) for compressed bodies.
 *
 * - <c>avs_stream_reset</c> - puts the stream in sending mode, allowing to send
 *   a new request. If there is buffered data to send, it is discarded. If there
 *   is unread response content data, it is read to end and discarded. In some
 *   cases (e.g. aborting a request with chunked encoding), a reconnection of
 *   the communication socket may be ordered. The actual reconnect will take
 *   place when there is data to send.
 *
 *   Note that <c>avs_stream_reset()</c> does NOT reset the authentication
 *   state, so for example, if there was any response requesting the Digest
 *   authentication during the lifetime of this stream, appropriate
 *   Authorization header will be sent even after resetting the stream.
 *
 * The stream also supports the "net" extension (<c>avs_stream_net_getsock()</c>
 * and <c>avs_stream_net_setsock()</c>).
 *
 * The stream is initially created in sending state. Even for GET requests
 * without any content, it is necessary to call
 * <c>avs_stream_finish_message()</c> to actually send the request. This makes
 * it possible to pass any custom headers via @ref avs_http_add_header
 * beforehand. Mixing read and write calls without paying attention to the state
 * transitions as described above is undefined behaviour.
 *
 * All requests that fit within a single buffer of size configured by the
 * <c>body_send</c> field of the @ref avs_http_buffer_sizes_t (4 KiB by
 * default), are sent directly using the default transfer encoding and the
 * Content-Length header. Larger requests are automatically split and sent using
 * chunked encoding.
 *
 * If authentication credentials are specified, they are automatically sent
 * using the Basic scheme if HTTPS encryption is used. For plain unencrypted
 * HTTP, they are not sent by default, but only if the server requests them
 * using the 401 Unauthorized status code.
 *
 * @param out           Pointer to the target variable to store the created
 *                      stream in. It is expected that <c>*out</c> is initially
 *                      <c>NULL</c>.
 *
 * @param http          The HTTP client object that the created stream shall be
 *                      related to. Its socket configuration and cookie storage
 *                      will be used.
 *
 * @param method        The HTTP method to use for the requests.
 *
 * @param encoding      The Content-Encoding (content compression method) to use
 *                      for the requests.
 *
 *                      <strong>NOTE:</strong> The stream will NOT automatically
 *                      degrade to identity encoding upon receiving HTTP 415
 *                      status code. It is the responsibility of the higher
 *                      layers to appropriately handle this case.
 *
 *                      <strong>NOTE:</strong> Attemping to use a
 *                      Content-Encoding not compiled into the library will
 *                      result in an error.
 *
 * @param parsed_url    The URL to access.
 *
 * @param auth_username Username to use for HTTP authentication if requested by
 *                      the server. Overrides the one specified within
 *                      <c>parsed_url</c> if any. May be <c>NULL</c> if unknown
 *                      or not necessary.
 *
 * @param auth_password Password to use for HTTP authentication if requested by
 *                      the server. Overrides the one specified within
 *                      <c>parsed_url</c> if any. May be <c>NULL</c> if unknown
 *                      or not necessary.
 *
 * @returns @ref AVS_OK, or an error condition for which creating the
 *          stream failed.
 */
avs_error_t avs_http_open_stream(avs_stream_t **out,
                                 avs_http_t *http,
                                 avs_http_method_t method,
                                 avs_http_content_encoding_t encoding,
                                 const avs_url_t *parsed_url,
                                 const char *auth_username,
                                 const char *auth_password);

/**
 * Clears the cookie storage used by the specified HTTP client and all
 * associated connection streams.
 *
 * @param http HTTP client object to operate on.
 */
void avs_http_clear_cookies(avs_http_t *http);

/**
 * Adds a specific HTTP header to be sent with the next request, in addition to
 * standard, automatically generated headers.
 *
 * This function shall be called after the stream is put in the sending state
 * (see @ref avs_http_open_stream for details), before any calls to
 * <c>avs_stream_write()</c> or <c>avs_stream_finish_message()</c> for the same
 * request. Calling it at any other time is undefined behaviour.
 *
 * User-defined headers are reset after each successful request, and need to be
 * specified again if they need to be repeated in subsequent requests.
 *
 * The values of <c>key</c> and <c>value</c> arguments are <strong>NOT</strong>
 * copied, only the pointers to null-terminated strings are stored. This means
 * that they need to remain valid for at least until a successful call to
 * <c>avs_stream_finish_message()</c> on the same stream.
 *
 * @param stream Stream to operate on. Need to be a stream created by
 *               @ref avs_http_open_stream.
 * @param key    Key of the HTTP header to send.
 * @param value  Value of the HTTP header to send.
 *
 * @return 0 for success, or a negative value in case of an out-of-memory error.
 */
int avs_http_add_header(avs_stream_t *stream,
                        const char *key,
                        const char *value);

/**
 * Enables storage of received HTTP headers and sets the storage location to the
 * specified list variable.
 *
 * @param stream             Stream to operate on. Need to be a stream created
 *                           by @ref avs_http_open_stream.
 * @param header_storage_ptr Pointer to a variable in which to store received
 *                           headers, or <c>NULL</c> if header storage is to be
 *                           disabled. At any given time, the list will contain
 *                           headers from the most recently received response.
 *                           The list will automatically be cleaned and
 *                           repopulated at each received HTTP response. It will
 *                           also be cleaned upon deleting the stream or
 *                           resetting this setting to <c>NULL</c>.
 */
void avs_http_set_header_storage(
        avs_stream_t *stream,
        AVS_LIST(const avs_http_header_t) *header_storage_ptr);

/**
 * Determines whether an unsuccessful request should be repeated by user code.
 *
 * The HTTP stream implementation attempts to retry requests whenever they fail
 * for reasons that can be automatically handled - including the 401
 * Unauthorized code if there are credentials available, 417 Expectation Failed
 * code if "Expect: 100-continue" was sent, as well as any 3xx redirects.
 *
 * This automatic retrying can be performed if the request content fits within a
 * single buffer and the attempt to sending was performed using the plain
 * transfer encoding, or if chunked encoding was attempted and the error code
 * was received early as a response to "Expect: 100-continue".
 *
 * However, when an error or redirect reply arrives late, after having sent a
 * big, chunked-encoded request, the stream logic has no means to automatically
 * retry, because the request body is no longer accessible in its entirety.
 *
 * The site that called <c>avs_stream_finish_message()</c> and received an error
 * return value may then use this function to determine whether the error is a
 * fatal one, or if simply repeating the request (regenerating it from scratch)
 * is appropriate for the current state of the stream.
 *
 * @param stream Stream to operate on. Need to be a stream created by
 *               @ref avs_http_open_stream.
 *
 * @return 0 if the last request was either successful or a fatal error, or
 *         1 if it is appropriate to retry the last request
 */
int avs_http_should_retry(avs_stream_t *stream);

/**
 * Category for @ref avs_error_t containing a HTTP status code.
 *
 * The <c>code</c> field in errors of this type will contain a HTTP status code
 * such as 404 or 503.
 *
 * Errors of this type will be returned by stream operations if everything was
 * fine on the network layer, but a request failed due to the server responding
 * with a status code outside the 2xx range (including exceeding the limit of
 * redirections, see below).
 *
 * NOTE: As codes from 1xx and 2xx classes are not error conditions, they will
 * NEVER be returned via an @ref avs_error_t object. All 2xx responses will be
 * mapped to @ref AVS_OK. If you need to query the actual status code of a
 * successful response, you may use @ref avs_http_status_code.
 *
 * NOTE: If the statuscode is in 3xx class, it indicates that the number of
 * redirects exceeded the maximum allowed number (5 chained HTTP 3xx
 * redirections).
 */
#define AVS_HTTP_ERROR_CATEGORY 4887 // 'HTTP' on phone keypad

/**
 * Retrieves the last response code received on a given stream.
 *
 * May be used to distinguish zero-length 200 response from 204.
 *
 * NOTE: If the returned code is in 3xx class, it indicates that the number of
 * redirects exceeded the maximum allowed number (5 chained HTTP 3xx
 * redirections).
 *
 * @return HTTP status code (nominally in the range 200-599), or 0 if it cannot
 *         be determined.
 */
int avs_http_status_code(avs_stream_t *stream);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_HTTP_H */
