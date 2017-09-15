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

#include <avs-config.h>

#include <avsystem/commons/utils.h>

#include <stdlib.h>

VISIBILITY_SOURCE_BEGIN

int avs_rand_r(unsigned int *seed) {
    return (*seed = *seed * 1103515245u + 12345u)
           % (unsigned int) (AVS_RAND_MAX + 1);
}
