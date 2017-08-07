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

#ifndef AVS_COMMONS_URL_H
#define AVS_COMMONS_URL_H

#ifdef	__cplusplus
extern "C" {
#endif

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
 * Makes a copy of a @ref avs_url_t object.
 *
 * @param url Original URL to copy.
 *
 * @return New heap-allocated parsed URL object, or <c>NULL</c> in case of
 *         error.
 */
avs_url_t *avs_url_copy(const avs_url_t *url);

/**
 * Returns the protocol (scheme name) portion of the parsed URL.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse.
 *
 * @return Value of the protocol portion of the URL.
 */
const char *avs_url_protocol(const avs_url_t *url);

/**
 * Returns the username part of the userinfo portion of the parsed URL, or
 * <c>NULL</c> if it was not present.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse.
 *
 * @return Value of the username given in the URL.
 */
const char *avs_url_user(const avs_url_t *url);

/**
 * Returns the password part of the userinfo portion of the parsed URL, or
 * <c>NULL</c> if it was not present.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse.
 *
 * @return Value of the password given in the URL.
 */
const char *avs_url_password(const avs_url_t *url);

/**
 * Returns the hostname portion of the parsed URL.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse.
 *
 * @return Value of the hostname portion of the URL.
 */
const char *avs_url_host(const avs_url_t *url);

/**
 * Returns the port portion of the parsed URL. It may be an empty string if the
 * port was not given in the URL - scheme defaults are not implicitly supported.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse.
 *
 * @return Value of the port portion of the URL.
 */
const char *avs_url_port(const avs_url_t *url);

/**
 * Returns the path portion of the parsed URL.
 *
 * @param url A parsed URL object previously returned by @ref avs_url_parse.
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

#ifdef	__cplusplus
}
#endif

#endif /* AVS_COMMONS_URL_H */
