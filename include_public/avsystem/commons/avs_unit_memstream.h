/*
 * Copyright 2021 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_UNIT_MEMSTREAM_H
#define AVS_COMMONS_UNIT_MEMSTREAM_H

#include <avsystem/commons/avs_stream.h>

#ifdef __cplusplus
extern "C" {
#endif

int avs_unit_memstream_alloc(avs_stream_t **stream, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_UNIT_MEMSTREAM_H */
