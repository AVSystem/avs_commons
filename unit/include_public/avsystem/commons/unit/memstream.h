/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_UNIT_MEMSTREAM_H
#define	AVS_COMMONS_UNIT_MEMSTREAM_H

#include <avsystem/commons/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

int avs_unit_memstream_alloc(avs_stream_abstract_t** stream,
                             size_t buffer_size);

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_UNIT_MEMSTREAM_H */

