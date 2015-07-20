/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifdef LOG
#undef LOG
#endif

#ifdef WITH_INTERNAL_LOGS

#ifdef WITH_INTERNAL_TRACE
#define AVS_LOG_WITH_TRACE
#endif

#include <avsystem/commons/log.h>
#define LOG(...) avs_log(MODULE_NAME, __VA_ARGS__)

#else

#define LOG(...) ((void) 0)

#endif
