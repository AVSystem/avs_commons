/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2014 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#include <config.h>

#include <avsystem/commons/defs.h>
#include <avsystem/commons/unit/test.h>

AVS_UNIT_TEST(align_pointer, correct_alignment) {
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 510, 4),
            512);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 511, 4),
            512);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 512, 4),
            512);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 513, 4),
            516);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 514, 4),
            516);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 515, 4),
            516);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 516, 4),
            516);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 517, 4),
            520);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 518, 4),
            520);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 519, 4),
            520);
    AVS_UNIT_ASSERT_EQUAL(
            (uintptr_t) AVS_ALIGN_POINTER_INTERNAL__(char *, (char *) 520, 4),
            520);
}

AVS_UNIT_TEST(aligned_stack_allocation, correct_alignment) {
    AVS_ALIGNED_STACK_BUF(A, 42);
    AVS_UNIT_ASSERT_TRUE(((unsigned long) A) % sizeof(avs_max_align_t) == 0);

    AVS_ALIGNED_VLA(long, B, 11, long);
    AVS_UNIT_ASSERT_TRUE((unsigned long) B % AVS_ALIGNOF(long) == 0);

    AVS_ALIGNED_VLA(char, C, 15, long);
    AVS_UNIT_ASSERT_TRUE((unsigned long) C % AVS_ALIGNOF(long) == 0);

    AVS_ALIGNED_VLA(char, D, 16, long double);
    AVS_UNIT_ASSERT_TRUE((unsigned long) D % AVS_ALIGNOF(long double) == 0);
}
