/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2017 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */
#include <config.h>

#include <avsystem/commons/utils.h>

#include <stdlib.h>

int avs_rand_r(unsigned int *seed) {
    return (*seed = *seed * 1103515245u + 12345u)
           % (unsigned int) (AVS_RAND_MAX + 1);
}
