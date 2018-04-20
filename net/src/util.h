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

#ifndef NET_UTIL_H
#define NET_UTIL_H

VISIBILITY_PRIVATE_HEADER_BEGIN

/**
 * Both mbedTLS and openSSL provide an API allowing to load certificates / keys
 * / whatever from files and paths. However, this is something we do not have a
 * direct control over - i.e. we don't control what C API is used to load files,
 * nor how they are being loaded, we don't control their overhead, and so on.
 *
 * It thus made sense to develop a single and uniform method to deal with
 * security related file loading and path traversal.
 */
char *_avs_read_file(const char *name, size_t *out_size);

typedef void entry_callback_t(void *context, const char *filename);
int _avs_iterate_directory(const char *directory,
                           entry_callback_t *clb,
                           void *context);

VISIBILITY_PRIVATE_HEADER_END

#endif /* NET_UTIL_H */
