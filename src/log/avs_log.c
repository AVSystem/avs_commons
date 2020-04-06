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

#define AVS_LOG_LOG_C
#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_LOG

#    include <stdarg.h>
#    include <stdio.h>
#    include <string.h>

#    include <avsystem/commons/avs_list.h>
#    include <avsystem/commons/avs_log.h>

#    ifdef AVS_COMMONS_WITH_AVS_COMPAT_THREADING
#        include <avsystem/commons/avs_init_once.h>
#        include <avsystem/commons/avs_mutex.h>
#    endif // AVS_COMMONS_WITH_AVS_COMPAT_THREADING

VISIBILITY_SOURCE_BEGIN

static void default_log_handler(avs_log_level_t level,
                                const char *module,
                                const char *message) {
    (void) level;
    (void) module;
#ifdef AVS_COMMONS_LOG_WITH_DEFAULT_HANDLER
    fprintf(stderr, "%s\n", message ? message : "(null)");
#else // AVS_COMMONS_LOG_WITH_DEFAULT_HANDLER
    (void) message;
#endif // AVS_COMMONS_LOG_WITH_DEFAULT_HANDLER
}

typedef struct {
    avs_log_level_t level;
    char module[1];
} module_level_t;

static struct {
    avs_log_handler_t *handler;
    avs_log_level_t default_level;
    AVS_LIST(module_level_t) module_levels;

#    ifdef AVS_COMMONS_LOG_USE_GLOBAL_BUFFER
    char buffer[AVS_COMMONS_LOG_MAX_LINE_LENGTH];
#    endif // AVS_COMMONS_LOG_USE_GLOBAL_BUFFER
} g_log = {
    .handler = default_log_handler,
    .default_level = AVS_LOG_INFO,
    .module_levels = NULL
};

#    ifdef AVS_COMMONS_WITH_AVS_COMPAT_THREADING
static avs_mutex_t *g_log_mutex;
static avs_init_once_handle_t g_log_init_handle;

void _avs_log_cleanup_global_state(void);
void _avs_log_cleanup_global_state(void) {
    avs_log_reset();
    avs_mutex_cleanup(&g_log_mutex);
    g_log_init_handle = NULL;
}

static int initialize_global_state(void *unused) {
    (void) unused;
    return avs_mutex_create(&g_log_mutex);
}

static int _log_lock(const char *init_fail_msg, const char *lock_fail_msg) {
    if (avs_init_once(&g_log_init_handle, initialize_global_state, NULL)) {
        g_log.handler(AVS_LOG_ERROR, "avs_log", init_fail_msg);
        return -1;
    }
    if (avs_mutex_lock(g_log_mutex)) {
        g_log.handler(AVS_LOG_ERROR, "avs_log", lock_fail_msg);
        return -1;
    }
    return 0;
}

#        define LOG_LOCK()                                                     \
            _log_lock(                                                         \
                    "ERROR [avs_log] "                                         \
                    "[" __FILE__ ":" AVS_QUOTE_MACRO(                          \
                            __LINE__) "]: "                                    \
                                      "could not initialize global log state", \
                    "ERROR [avs_log] "                                         \
                    "[" __FILE__                                               \
                    ":" AVS_QUOTE_MACRO(__LINE__) "]: "                        \
                                                  "could not lock log mutex")
#        define LOG_UNLOCK() avs_mutex_unlock(g_log_mutex)

#    else // AVS_COMMONS_WITH_AVS_COMPAT_THREADING

#        define LOG_LOCK() 0
#        define LOG_UNLOCK()

#    endif // AVS_COMMONS_WITH_AVS_COMPAT_THREADING

static inline void set_log_handler_unlocked(avs_log_handler_t *log_handler) {
    g_log.handler = (log_handler ? log_handler : default_log_handler);
}

void avs_log_set_handler(avs_log_handler_t *log_handler) {
    if (LOG_LOCK()) {
        return;
    }
    set_log_handler_unlocked(log_handler);
    LOG_UNLOCK();
}

static avs_log_level_t *level_for(const char *module, int create) {
    if (module) {
        AVS_LIST(module_level_t) *entry_ptr;
        int cmp = 1;
        AVS_LIST_FOREACH_PTR(entry_ptr, &g_log.module_levels) {
            cmp = strcmp((*entry_ptr)->module, module);
            if (cmp >= 0) {
                break;
            }
        }
        if (cmp == 0) {
            return &(*entry_ptr)->level;
        } else if (create) {
            size_t module_size = strlen(module);
            module_level_t *new_entry = (module_level_t *) AVS_LIST_NEW_BUFFER(
                    offsetof(module_level_t, module) + module_size + 1);
            if (!new_entry) {
                return NULL;
            }
            new_entry->level = g_log.default_level;
            memcpy(new_entry->module, module, module_size);
            new_entry->module[module_size] = '\0';
            AVS_LIST_INSERT(entry_ptr, new_entry);
            return &new_entry->level;
        }
    }
    return &g_log.default_level;
}

static int set_log_level_unlocked(const char *module, avs_log_level_t level) {
    avs_log_level_t *level_ptr = level_for(module, 1);
    if (!level_ptr) {
        if (AVS_LOG_ERROR >= g_log.default_level) {
            avs_log_internal_forced_l__(
                    AVS_LOG_ERROR, "avs_log", __FILE__, __LINE__,
                    "could not allocate level entry for module: %s", module);
        }
        return -1;
    }
    *level_ptr = level;
    return 0;
}

int avs_log_set_level__(const char *module, avs_log_level_t level) {
    if (LOG_LOCK()) {
        return -1;
    }
    int result = set_log_level_unlocked(module, level);
    LOG_UNLOCK();
    return result;
}

void avs_log_reset(void) {
    if (LOG_LOCK()) {
        return;
    }
    AVS_LIST_CLEAR(&g_log.module_levels);
    set_log_handler_unlocked(default_log_handler);
    set_log_level_unlocked(NULL, AVS_LOG_INFO);
    LOG_UNLOCK();
}

int avs_log_should_log__(avs_log_level_t level, const char *module) {
    if (level >= AVS_LOG_QUIET) {
        return 1;
    }

    if (LOG_LOCK()) {
        return 1;
    }
    int result = (level >= *level_for(module, 0));
    LOG_UNLOCK();
    return result;
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

static void log_with_buffer_unlocked_v(char *log_buf,
                                       size_t log_buf_size,
                                       avs_log_level_t level,
                                       const char *module,
                                       const char *file,
                                       unsigned line,
                                       const char *msg,
                                       va_list ap) {
    char *log_buf_ptr = log_buf;
    size_t log_buf_left = log_buf_size;
    int pfresult = snprintf(log_buf_ptr, log_buf_left,
                            "%s [%s] [%s:%u]: ", level_as_string(level), module,
                            file, line);
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
            pfresult = (int) log_buf_left - 1;
            log_buf_ptr = log_buf_ptr + pfresult - 3;
            for (int i = 0; i < 3; i++) {
                *log_buf_ptr = '.';
                ++log_buf_ptr;
            }
        }
    }
    g_log.handler(level, module, log_buf);
}

void avs_log_internal_forced_v__(avs_log_level_t level,
                                 const char *module,
                                 const char *file,
                                 unsigned line,
                                 const char *msg,
                                 va_list ap) {
#    ifdef AVS_COMMONS_LOG_USE_GLOBAL_BUFFER
    if (LOG_LOCK()) {
        return;
    }
    log_with_buffer_unlocked_v(g_log.buffer, sizeof(g_log.buffer), level,
                               module, file, line, msg, ap);
    LOG_UNLOCK();
#    else  // AVS_COMMONS_LOG_USE_GLOBAL_BUFFER
    char log_buf[AVS_COMMONS_LOG_MAX_LINE_LENGTH];
    log_with_buffer_unlocked_v(log_buf, sizeof(log_buf), level, module, file,
                               line, msg, ap);
#    endif // AVS_COMMONS_LOG_USE_GLOBAL_BUFFER
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
                                 const char *msg,
                                 ...) {
    va_list ap;
    va_start(ap, msg);
    avs_log_internal_forced_v__(level, module, file, line, msg, ap);
    va_end(ap);
}

void avs_log_internal_l__(avs_log_level_t level,
                          const char *module,
                          const char *file,
                          unsigned line,
                          const char *msg,
                          ...) {
    if (avs_log_should_log__(level, module)) {
        va_list ap;
        va_start(ap, msg);
        avs_log_internal_forced_v__(level, module, file, line, msg, ap);
        va_end(ap);
    }
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/log/test_log.c"
#    endif

#endif // AVS_COMMONS_WITH_AVS_LOG
