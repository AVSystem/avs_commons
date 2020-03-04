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

#ifndef AVS_COMMONS_URL_H
#define AVS_COMMONS_URL_H

#include <avsystem/commons/avs_stream.h>

/**
 * @file avs_url.h
 *
 * URL handling routines.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Default set of unreserved characters for percent-encoding, as defined in
 * RFC 3986 section 2.1.
 */
#define AVS_URL_PERCENT_UNRESERVED "-_.~"

/**
 * Encodes a string with percent-encoding as defined in RFC 3986 section 2.1 and
 * writes the result to a stream.
 *
 * @param stream           Output stream into which to write the result.
 *
 * @param input            Input data as a NULL-terminated string.
 *
 * @param unreserved_chars A null-terminated string containing non-alphanumeric
 *                         characters that do not need percent-encoding. For
 *                         maximum RFC compatibility, use
 *                         @ref AVS_URL_PERCENT_UNRESERVED.
 *
 * @returns @ref AVS_OK for success, or an error condition for which the
 *          operation failed (propagated from @p stream).
 */
avs_error_t avs_url_percent_encode(avs_stream_t *stream,
                                   const char *input,
                                   const char *unreserved_chars);

/**
 * Decodes a string that uses percent-encoding as defined in RFC 3986 section
 * 2.1. Data is decoded in-place, so that each "%xx" substring is replaced
 * within the input buffer.
 *
 * @param data             Pointer to the data to decode. On input, it shall
 *                         point at a null-terminated percent-encoded string.
 *                         After successful return from this function, it will
 *                         hold the decoded data. It is safe to do so, because
 *                         the decoded string is never longer than an encoded
 *                         one.
 *
 * @param unescaped_length Pointer to a variable that, upon successful return
 *                         from this function, will contain the number of bytes
 *                         in the decoded string. It will usually be equal to
 *                         <c>strlen(data)</c>, but might be different if a
 *                         percent-encoded null-byte was present in the input.
 *
 * @return 0 for success, or -1 in case of error (invalid input string format).
 *         Note that upon returning -1, the contents of the string pointed to by
 *         <c>data</c> are undefined.
 */
int avs_url_percent_decode(char *data, size_t *unescaped_length);

/**
 * Opaque internal type used to hold parsed URL data.
 */
struct avs_url;
typedef struct avs_url avs_url_t;

/**
 * Parses an URL and stores the parsed data in a newly allocated @ref avs_url_t
 * object.
 *
 * The returned object should be accessed using the <c>avs_url_*</c> functions
 * and freed using @ref avs_url_free.
 *
 * @param raw_url A null-terminated string representation of the original URL.
 *
 * @return New heap-allocated parsed URL object, or <c>NULL</c> in case of
 *         error.
 */
avs_url_t *avs_url_parse(const char *raw_url);

/**
 * Parses an URL and stores the parsed data in a newly allocated @ref avs_url_t
 * object. This variant allows several forms of URLs that are considered invalid
 * by @ref avs_url_parse:
 *
 * - URL scheme (protocol) is optional - protocol-relative URLs such as
 *   "//example.com/test.html" are supported and will cause
 *   @ref avs_url_protocol to return NULL.
 * - Host portion is allowed to be empty and is also not verified to be a valid
 *   Internet host address.
 * - Port is allowed to have an arbitrary number of digits. Zero-length port
 *   will be represented as non-NULL, but zero-length string returned via
 *   @ref avs_url_port.
 * - Path is not validated for syntax.
 *
 * The returned object should be accessed using the <c>avs_url_*</c> functions
 * and freed using @ref avs_url_free.
 *
 * @param raw_url A null-terminated string representation of the original URL.
 *
 * @return New heap-allocated parsed URL object, or <c>NULL</c> in case of
 *         error.
 */
avs_url_t *avs_url_parse_lenient(const char *raw_url);

/**
 * Checks whther a given string is a valid hostname according to criteria used
 * by @ref avs_url_parse.
 *
 * @param str String to validate for being a proper hostname; NULL is safely
 *            handled, although treated as invalid.
 *
 * @return 0 if the hostname is valid, -1 otherwise.
 */
int avs_url_validate_host(const char *str);

/**
 * Checks whther a given string is a valid relative or absolute path portion of
 * a URL according to criteria used by @ref avs_url_parse.
 *
 * @param str String to validate for being a proper path; NULL is safely
 *            handled, although treated as invalid.
 *
 * @return 0 if the hostname is valid, -1 otherwise.
 */
int avs_url_validate_relative_path(const char *str);

/**
 * Checks whther a given string is a valid absolute path portion of a URL
 * according to criteria used by @ref avs_url_parse.
 *
 * This is equivalent to @ref avs_url_validate_relative_path with an additional
 * check that the first character is '/'.
 *
 * @param str String to validate for being a proper path; NULL is safely
 *            handled, although treated as invalid.
 *
 * @return 0 if the hostname is valid, -1 otherwise.
 */
int avs_url_validate_path(const char *str);

/**
 * Checks whether an URL parsed using @ref avs_url_parse_lenient is valid
 * according to criteria used by @ref avs_url_parse.
 *
 * @param url URL to validate.
 *
 * @return 0 if the URL is valid, -1 otherwise.
 */
int avs_url_validate(const avs_url_t *url);

/**
 * Makes a copy of a @ref avs_url_t object.
 *
 * @param url Original URL to copy.
 *
 * @return New heap-allocated parsed URL object, or <c>NULL</c> in case of
 *         error.
 */
avs_url_t *avs_url_copy(const avs_url_t *url);

/**
 * Returns the protocol (scheme name) portion of the parsed URL, or <c>NULL</c>
 * if it was not present (only possible for @ref avs_url_parse_lenient).
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse
 *            or @ref avs_url_parse_lenient.
 *
 * @return Value of the protocol portion of the URL.
 */
const char *avs_url_protocol(const avs_url_t *url);

/**
 * Returns the username part of the userinfo portion of the parsed URL, or
 * <c>NULL</c> if it was not present.
 *
 * NOTE: Any percent-encoding in the password is already decoded.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse
 *            or @ref avs_url_parse_lenient.
 *
 * @return Value of the username given in the URL.
 */
const char *avs_url_user(const avs_url_t *url);

/**
 * Returns the password part of the userinfo portion of the parsed URL, or
 * <c>NULL</c> if it was not present.
 *
 * NOTE: Any percent-encoding in the password is already decoded.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse
 *            or @ref avs_url_parse_lenient.
 *
 * @return Value of the password given in the URL.
 */
const char *avs_url_password(const avs_url_t *url);

/**
 * Returns the hostname portion of the parsed URL, which may be an empty string
 * or @c NULL (if there was no @c // in the URL) when using
 * @ref avs_url_parse_lenient.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse
 *            or @ref avs_url_parse_lenient.
 *
 * @return Value of the hostname portion of the URL.
 */
const char *avs_url_host(const avs_url_t *url);

/**
 * Returns the port portion of the parsed URL, or <c>NULL</c> if it was not
 * present in the URL.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse
 *            or @ref avs_url_parse_lenient.
 *
 * @return Value of the port portion of the URL.
 */
const char *avs_url_port(const avs_url_t *url);

/**
 * Returns the path portion of the parsed URL. Guaranteed to be non-<c>NULL</c>.
 *
 * NOTE: Any percent-encoding in the path is NOT decoded automatically.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse
 *            or @ref avs_url_parse_lenient.
 *
 * @return Value of the path portion of the URL.
 */
const char *avs_url_path(const avs_url_t *url);

/**
 * Frees the memory used by a parsed URL structure.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse.
 */
void avs_url_free(avs_url_t *url);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_URL_H */
