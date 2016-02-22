/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#define _BSD_SOURCE /* for vsnprintf when not C99 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <avsystem/commons/list.h>
#include <avsystem/commons/log.h>

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
            if (new_entry) {
                new_entry->level = DEFAULT_LEVEL;
                memcpy(new_entry->module, module, module_size);
                new_entry->module[module_size] = '\0';
                AVS_LIST_INSERT(entry_ptr, new_entry);
                return &new_entry->level;
            }
        }
    }
    return &DEFAULT_LEVEL;
}

int avs_log_should_log__(avs_log_level_t level, const char *module) {
    return level >= AVS_LOG_QUIET || level >= *level_for(module, 0);
}

void avs_log_internal_forced_v__(avs_log_level_t level,
                                 const char *module,
                                 const char *msg,
                                 va_list ap) {
    char log_buf[MAX_LOG_LINE_LENGTH];
    vsnprintf(log_buf, sizeof(log_buf) - 1, msg, ap);
    log_buf[sizeof(log_buf) - 1] = '\0';
    HANDLER(level, module, log_buf);
}

void avs_log_internal_v__(avs_log_level_t level,
                          const char *module,
                          const char *msg,
                          va_list ap) {
    if (avs_log_should_log__(level, module)) {
        avs_log_internal_forced_v__(level, module, msg, ap);
    }
}

void avs_log_internal_forced_l__(avs_log_level_t level,
                                 const char *module,
                                 const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    avs_log_internal_forced_v__(level, module, msg, ap);
    va_end(ap);
}

void avs_log_internal_l__(avs_log_level_t level,
                          const char *module,
                          const char *msg, ...) {
    if (avs_log_should_log__(level, module)) {
        va_list ap;
        va_start(ap, msg);
        avs_log_internal_forced_v__(level, module, msg, ap);
        va_end(ap);
    }
}

void avs_log_set_level__(const char *module, avs_log_level_t level) {
    *level_for(module, 1) = level;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_log.c"
#endif
