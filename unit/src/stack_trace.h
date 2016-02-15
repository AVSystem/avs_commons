#ifndef AVS_UNIT_STACKTRACE_H
#define AVS_UNIT_STACKTRACE_H

#include <stdio.h>

void _avs_unit_stack_trace_init(int argc, char **argv);

void _avs_unit_stack_trace_print(FILE *file);

#endif /* AVS_UNIT_STACKTRACE_H */
