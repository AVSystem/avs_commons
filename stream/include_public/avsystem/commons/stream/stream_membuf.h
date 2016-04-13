/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_FILE_H
#define AVS_COMMONS_STREAM_FILE_H

#include <avsystem/commons/net.h>
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
avs_stream_abstract_t *avs_stream_membuf_create();

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_STREAM_FILE_H */
