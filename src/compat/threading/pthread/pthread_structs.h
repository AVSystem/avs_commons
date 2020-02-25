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

#ifndef AVS_COMMONS_COMPAT_THREADING_PTHREAD_STRUCTS_H
#define AVS_COMMONS_COMPAT_THREADING_PTHREAD_STRUCTS_H

#include <avsystem/commons/avs_condvar.h>
#include <avsystem/commons/avs_mutex.h>

#include <pthread.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

struct avs_condvar {
    pthread_cond_t pthread_cond;
};

struct avs_mutex {
    pthread_mutex_t pthread_mutex;
};

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_COMMONS_COMPAT_THREADING_PTHREAD_STRUCTS_H */
