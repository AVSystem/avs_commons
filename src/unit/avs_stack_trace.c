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

#define AVS_UNIT_SOURCE
#include <avsystem/commons/avs_commons_config.h>

#ifdef AVS_COMMONS_WITH_AVS_UNIT

#    include <avs_commons_posix_init.h>

#    include <avsystem/commons/avs_defs.h>
#    include <avsystem/commons/avs_memory.h>
#    include <avsystem/commons/avs_utils.h>

#    include "avs_stack_trace.h"

#    ifdef AVS_COMMONS_UNIT_POSIX_HAVE_BACKTRACE
#        include <execinfo.h>
#    endif

#    include <signal.h>

#    include <assert.h>
#    include <stdarg.h>
#    include <stddef.h>
#    include <stdint.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    include "avs_unit_test_private.h"

VISIBILITY_SOURCE_BEGIN

#    define MAX_TRACE_LEVELS 256

#    ifndef AVS_COMMONS_UNIT_POSIX_HAVE_BACKTRACE

void _avs_unit_stack_trace_init(int argc, char **argv) {
    (void) argc;
    (void) argv;
}

void _avs_unit_stack_trace_print(FILE *file) {
    fprintf(file, "(stack trace not available)\n");
}

#    else /* AVS_COMMONS_UNIT_POSIX_HAVE_BACKTRACE */

typedef struct stack_frame {
    void *address;
    char symbol_name[1]; /* FAM */
} stack_frame_t;

typedef struct stack_trace {
    size_t num_frames;
    stack_frame_t *frames[1]; /* FAM */
} stack_trace_t;

static char *const *_saved_argv;
static int addr2line_pid = -1;
static FILE *addr2line_read;
static FILE *addr2line_write;

static int is_addr2line_available(void) {
    return addr2line_pid >= 0 && addr2line_read != NULL
           && addr2line_write != NULL;
}

static void cleanup_addr2line(void) {
    if (addr2line_read) {
        fclose(addr2line_read);
        addr2line_read = NULL;
    }

    if (addr2line_write) {
        fclose(addr2line_write);
        addr2line_write = NULL;
    }

    if (addr2line_pid >= 0) {
        int status = 0;
        struct timespec wait_time = { 0, 100 * 1000 * 1000 }; /* 100ms */

        while (wait_time.tv_sec > 0 || wait_time.tv_nsec > 0) {
            struct timespec time_remaining = { 0, 0 };

            if (nanosleep(&wait_time, &time_remaining)) {
                wait_time = time_remaining;
            } else {
                wait_time.tv_sec = 0;
                wait_time.tv_nsec = 0;
            }

            if (waitpid(addr2line_pid, &status, WNOHANG) != 0) {
                addr2line_pid = -1;
                return;
            }
        }

        fprintf(stderr, "Could not terminate addr2line process (PID = %d)\n",
                addr2line_pid);
    }
}

static void start_addr2line(int argc, char **argv) {
    char addr2line_cmd[] = "/usr/bin/addr2line";
    char addr2line_arg[] = "-Capfe";
    char *addr2line_argv[4];

    (void) argc;

    addr2line_argv[0] = addr2line_cmd;
    addr2line_argv[1] = addr2line_arg;
    addr2line_argv[2] = argv[0];
    addr2line_argv[3] = NULL;

    execv(addr2line_argv[0], addr2line_argv);
    perror("execv() failed");
    fprintf(stderr,
            "Could not start %s, stacktrace symbols will not be"
            " resolved\n",
            addr2line_cmd);
}

static int addr2line_ask(char **out_answer,
                         size_t *out_answer_size,
                         const char *format,
                         va_list args) {
    ssize_t bytes_read;

    if (vfprintf(addr2line_write, format, args) < 0) {
        return -1;
    }

    fflush(addr2line_write);

    bytes_read = getline(out_answer, out_answer_size, addr2line_read);
    if (bytes_read < 0) {
        return -1;
    }

    *out_answer_size = (size_t) bytes_read;

    if (out_answer && (*out_answer)[*out_answer_size - 1] != '\n') {
        return -1;
    }

    return 0;
}

static int addr2line_safe_ask(char **out_answer,
                              size_t *out_answer_size,
                              const char *format,
                              ...) {
    va_list list;
    int result;
    struct sigaction ignore_signal;
    struct sigaction previous_action;

    memset(&ignore_signal, 0, sizeof(ignore_signal));
    ignore_signal.sa_handler = SIG_IGN;
    sigemptyset(&ignore_signal.sa_mask);

    /*
     * If the addr2line process was not started (e.g. addr2line executable does
     * not exist), write() call causes SIGPIPE to be raised.
     * We try to avoid that by temporarily ignoring that signal.
     */
    if (sigaction(SIGPIPE, &ignore_signal, &previous_action)) {
        cleanup_addr2line();
        return -1;
    }

    va_start(list, format);
    result = addr2line_ask(out_answer, out_answer_size, format, list);
    va_end(list);

    if (sigaction(SIGPIPE, &previous_action, NULL)) {
        cleanup_addr2line();
        return -1;
    }

    return result;
}

static int is_addr2line_process_ready(void) {

    char answer[256] = "";
    char *answer_ptr = answer;
    size_t answer_size = sizeof(answer);
    return addr2line_safe_ask(&answer_ptr, &answer_size, "\n") == 0;
}

static void close_pipe(int pipe[2]) {
    if (pipe[0] >= 0) {
        close(pipe[0]);
    }
    if (pipe[1] >= 0) {
        close(pipe[1]);
    }
}

void _avs_unit_stack_trace_init(int argc, char **argv) {
    const int READ = 0;
    const int WRITE = 1;

    int addr_pipe[2] = { -1, -1 };
    int line_pipe[2] = { -1, -1 };

    _saved_argv = argv;

    if (pipe(addr_pipe) != 0 || pipe(line_pipe) != 0) {
        goto fail;
    }

    switch (addr2line_pid = fork()) {
    case -1:
        goto fail;
    case 0:
        if (dup2(addr_pipe[READ], 0) < 0 || dup2(line_pipe[WRITE], 1) < 0) {
            goto fail;
        }

        close(addr_pipe[WRITE]);
        close(line_pipe[READ]);

        start_addr2line(argc, argv);
        break;
    default:
        close(addr_pipe[READ]);
        addr2line_write = fdopen(addr_pipe[WRITE], "w");

        close(line_pipe[WRITE]);
        addr2line_read = fdopen(line_pipe[READ], "r");

        if (is_addr2line_process_ready()) {
            atexit(cleanup_addr2line);
        } else {
            cleanup_addr2line();
        }
        break;
    }

    return;

fail:
    close_pipe(addr_pipe);
    close_pipe(line_pipe);
}

static char *find_last_not_of(char *haystack, const char *needles) {
    size_t len = strlen(haystack);
    size_t at = len - 1;

    while (at--) {
        if (strchr(needles, haystack[at]) == NULL) {
            return &haystack[at];
        }
    }

    return NULL;
}

static char *addr2line(void *addr) {
    char *line = NULL;
    size_t size = 0;
    char *last = NULL;

    if (addr2line_safe_ask(&line, &size, "%p\n", addr)) {
        return avs_strdup("<addr2line failed>");
    }

    last = find_last_not_of(line, "\r\n");
    if (last) {
        *(last + 1) = '\0';
    }

    return line;
}

static int is_own_symbol(const char *symbol) {
    const char *prog = _saved_argv[0];
    size_t prog_len;

    if (!prog) {
        return 0;
    }

    prog_len = strlen(prog);
    return (strncmp(symbol, prog, prog_len) == 0 && symbol[prog_len] == '(');
}

static stack_frame_t *frame_from_symbol(void *address, const char *symbol) {
    size_t symbol_len = strlen(symbol);
    stack_frame_t *frame = (stack_frame_t *) avs_calloc(
            1, sizeof(stack_frame_t) + symbol_len + 1);

    if (!frame) {
        return NULL;
    }

    frame->address = address;
    memcpy(frame->symbol_name, symbol, symbol_len);

    return frame;
}

static stack_frame_t *frame_from_address(void *address) {
    stack_frame_t *frame = NULL;
    char *symbol = addr2line(address);
    if (!symbol) {
        return NULL;
    }

    frame = frame_from_symbol(address, symbol);

    avs_free(symbol);
    return frame;
}

static stack_frame_t *stack_frame_create(void *address, const char *symbol) {
    if (is_own_symbol(symbol) && is_addr2line_available()) {
        return frame_from_address(address);
    } else {
        return frame_from_symbol(address, symbol);
    }
}

static void stack_trace_release(stack_trace_t **trace) {
    if (trace && *trace) {
        size_t i;
        for (i = 0; i < (*trace)->num_frames; ++i) {
            avs_free((*trace)->frames[i]);
        }

        avs_free(*trace);
        *trace = NULL;
    }
}

static int fill_stack_trace(stack_trace_t *trace,
                            void **addrs,
                            size_t num_addrs,
                            char **symbols) {
    size_t i;

    trace->num_frames = num_addrs;

    for (i = 0; i < num_addrs; ++i) {
        assert(trace->frames[i] == NULL);
        trace->frames[i] = stack_frame_create(addrs[i], symbols[i]);

        if (!trace->frames[i]) {
            return -1;
        }
    }

    return 0;
}

static stack_trace_t *stack_trace_create(size_t skip_entries_count) {
    void *addrs[MAX_TRACE_LEVELS];
    int num_addrs = backtrace(addrs, AVS_ARRAY_SIZE(addrs));
    char **symbols = NULL;
    int result;
    stack_trace_t *trace = NULL;

    if ((int) skip_entries_count > num_addrs) {
        return NULL;
    }

    trace = (stack_trace_t *) avs_calloc(
            1,
            sizeof(stack_trace_t) + (size_t) num_addrs * sizeof(stack_frame_t));
    if (!trace) {
        return NULL;
    }

    symbols = backtrace_symbols(addrs, num_addrs);
    result = fill_stack_trace(trace, addrs + skip_entries_count,
                              (size_t) num_addrs - skip_entries_count, symbols);
    avs_free(symbols);

    if (result) {
        stack_trace_release(&trace);
        return NULL;
    }

    return trace;
}

void _avs_unit_stack_trace_print(FILE *file) {
    /* skip stack frame for this function and `stack_trace_create` call */
    const size_t SKIP_FRAMES = 2;
    stack_trace_t *trace = stack_trace_create(SKIP_FRAMES);
    size_t i;

    if (!trace) {
        fprintf(file, "(stack trace not available)\n");
        return;
    }

    fprintf(file, "--- STACK TRACE ---\n");
    for (i = 0; i < trace->num_frames; ++i) {
        if (trace->frames[i]->symbol_name[0]) {
            fprintf(file, "%s\n", trace->frames[i]->symbol_name);
        } else {
            fprintf(file, "%p (no symbol name)\n", trace->frames[i]->address);
        }
    }
    fprintf(file, "-------------------\n");

    stack_trace_release(&trace);
}

#    endif /* AVS_COMMONS_UNIT_POSIX_HAVE_BACKTRACE */

#endif // AVS_COMMONS_WITH_AVS_UNIT
