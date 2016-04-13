/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2016 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_STREAM_FILE_H
#define	AVS_COMMONS_STREAM_FILE_H

#include <avsystem/commons/net.h>
#include <avsystem/commons/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

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
