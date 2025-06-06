/*
 * Copyright 2025 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_STREAM_MD5_H
#define AVS_COMMONS_STREAM_MD5_H

#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVS_COMMONS_MD5_LENGTH 16

avs_stream_t *avs_stream_md5_create(void);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_STREAM_MD5_H */
