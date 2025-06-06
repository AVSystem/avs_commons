/*
 * Copyright 2025 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_UNIT_STACKTRACE_H
#define AVS_UNIT_STACKTRACE_H

#include <stdio.h>

VISIBILITY_PRIVATE_HEADER_BEGIN

void _avs_unit_stack_trace_init(int argc, char **argv);

void _avs_unit_stack_trace_print(FILE *file);

VISIBILITY_PRIVATE_HEADER_END

#endif /* AVS_UNIT_STACKTRACE_H */
