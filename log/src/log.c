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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <avsystem/commons/list.h>
#include <avsystem/commons/log.h>

VISIBILITY_SOURCE_BEGIN

#define MAX_LOG_LINE_LENGTH 512

static void default_log_handler(avs_log_level_t level,
                                const char *module,
                                const char *message) {
    (void) level;
    (void) module;
    fprintf(stderr, "%s\n", message);
}

static avs_log_handler_t * volatile HANDLER = default_log_handler;

void avs_log_set_handler(avs_log_handler_t *log_handler) {
    HANDLER = log_handler;
}

static volatile avs_log_level_t DEFAULT_LEVEL = AVS_LOG_INFO;

typedef struct {
    volatile avs_log_level_t level;
    char module[1];
} module_level_t;

static AVS_LIST(module_level_t) MODULE_LEVELS = NULL;

void avs_log_reset(void) {
    AVS_LIST_CLEAR(&MODULE_LEVELS);
    avs_log_set_handler(default_log_handler);
    avs_log_set_default_level(AVS_LOG_INFO);
}

static volatile avs_log_level_t *level_for(const char *module, int create) {
    if (module) {
        AVS_LIST(module_level_t) *entry_ptr;
        int cmp = 1;
        AVS_LIST_FOREACH_PTR(entry_ptr, &MODULE_LEVELS) {
            cmp = strcmp((*entry_ptr)->module, module);
            if (cmp >= 0) {
                break;
            }
        }
        if (cmp == 0) {
            return &(*entry_ptr)->level;
        } else if (create) {
            size_t module_size = strlen(module);
            module_level_t *new_entry = (module_level_t*)
                    AVS_LIST_NEW_BUFFER(offsetof(module_level_t, module) + module_size + 1);
            if (!new_entry) {
                return NULL;
            }
            new_entry->level = DEFAULT_LEVEL;
            memcpy(new_entry->module, module, module_size);
            new_entry->module[module_size] = '\0';
            AVS_LIST_INSERT(entry_ptr, new_entry);
            return &new_entry->level;
        }
    }
    return &DEFAULT_LEVEL;
}

int avs_log_should_log__(avs_log_level_t level, const char *module) {
    return level >= AVS_LOG_QUIET || level >= *level_for(module, 0);
}

static const char *level_as_string(avs_log_level_t level) {
    switch (level) {
    case AVS_LOG_TRACE:
        return "TRACE";
    case AVS_LOG_DEBUG:
        return "DEBUG";
    case AVS_LOG_INFO:
        return "INFO";
    case AVS_LOG_WARNING:
        return "WARNING";
    case AVS_LOG_ERROR:
        return "ERROR";
    default:
        return "WTF";
    }
}

void avs_log_internal_forced_v__(avs_log_level_t level,
                                 const char *module,
                                 const char *file,
                                 unsigned line,
                                 const char *msg,
                                 va_list ap) {
    char log_buf[MAX_LOG_LINE_LENGTH];
    char *log_buf_ptr = log_buf;
    size_t log_buf_left = sizeof(log_buf) - 1;
    int pfresult = snprintf(log_buf_ptr, log_buf_left, "%s [%s] [%s:%u]: ",
                            level_as_string(level), module, file, line);
    if (pfresult < 0) {
        // it's hard to imagine why snprintf() above might fail,
        // but well, let's be compliant and check it
        return;
    }
    if ((size_t) pfresult > log_buf_left) {
        pfresult = (int) log_buf_left;
    }
    log_buf_ptr += pfresult;
    log_buf_left -= (size_t) pfresult;
    if (log_buf_left) {
        pfresult = vsnprintf(log_buf_ptr, log_buf_left, msg, ap);
        if (pfresult < 0) {
            // erroneous user-provided format string?
            return;
        }
        if ((size_t) pfresult > log_buf_left) {
            pfresult = (int) log_buf_left;
        }
        log_buf_ptr += pfresult;
    }
    *log_buf_ptr = '\0';
    HANDLER(level, module, log_buf);
}

void avs_log_internal_v__(avs_log_level_t level,
                          const char *module,
                          const char *file,
                          unsigned line,
                          const char *msg,
                          va_list ap) {
    if (avs_log_should_log__(level, module)) {
        avs_log_internal_forced_v__(level, module, file, line, msg, ap);
    }
}

void avs_log_internal_forced_l__(avs_log_level_t level,
                                 const char *module,
                                 const char *file,
                                 unsigned line,
                                 const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    avs_log_internal_forced_v__(level, module, file, line, msg, ap);
    va_end(ap);
}

void avs_log_internal_l__(avs_log_level_t level,
                          const char *module,
                          const char *file,
                          unsigned line,
                          const char *msg, ...) {
    if (avs_log_should_log__(level, module)) {
        va_list ap;
        va_start(ap, msg);
        avs_log_internal_forced_v__(level, module, file, line, msg, ap);
        va_end(ap);
    }
}

int avs_log_set_level__(const char *module, avs_log_level_t level) {
    volatile avs_log_level_t *level_ptr = level_for(module, 1);
    if (!level_ptr) {
        if (AVS_LOG_ERROR >= DEFAULT_LEVEL) {
            avs_log_internal_forced_l__(
                    AVS_LOG_ERROR, "avs_log", __FILE__, __LINE__,
                    "could not allocate level entry for module: %s", module);
        }
        return -1;
    }
    *level_ptr = level;
    return 0;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_log.c"
#endif
