/*
 * Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_STREAM_MEMBUF_H
#define AVS_COMMONS_STREAM_MEMBUF_H

#include <avsystem/commons/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define AVS_STREAM_V_TABLE_EXTENSION_MEMBUF 0x4d454d42UL /* MEMB */

typedef int (*avs_stream_membuf_fit_t)(avs_stream_abstract_t *stream);

typedef struct {
    avs_stream_membuf_fit_t fit;
} avs_stream_v_table_extension_membuf_t;

/**
 * Resizes stream internal buffers to optimize memory usage.
 *
 * @param stream    membuf stream pointer
 */
int avs_stream_membuf_fit(avs_stream_abstract_t *stream);

typedef struct avs_stream_membuf_struct avs_stream_membuf_t;

/**
 * Creates a new in-memory auto-resizable bidirectional stream.
 *
 * @return NULL in case of an error, pointer to the newly allocated
 *         stream otherwise
 */
avs_stream_abstract_t *avs_stream_membuf_create(void);

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_STREAM_MEMBUF_H */
