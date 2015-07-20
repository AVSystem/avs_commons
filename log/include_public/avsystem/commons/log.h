/*
 * AVSystem Commons Library
 *
 * Copyright (C) 2015 AVSystem <http://www.avsystem.com/>
 *
 * This code is free and open source software licensed under the MIT License.
 * See the LICENSE file for details.
 */

#ifndef AVS_COMMONS_LOG_H
#define	AVS_COMMONS_LOG_H

#include <stdarg.h>

#include <avsystem/commons/defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Specifies log level used by function @ref avs_log_set_level.
 */
typedef enum {
    AVS_LOG_TRACE,
    AVS_LOG_DEBUG,
    AVS_LOG_INFO,
    AVS_LOG_WARNING,
    AVS_LOG_ERROR,
    AVS_LOG_QUIET
} avs_log_level_t;

/**
 * User-defined handler for logging.
 *
 * The messages sent to the log handler are already pre-formatted using the
 * following format:
 *
 * <c><i>log_level</i> [<i>module_name</i>]
 * [<i>source_file_name</i>:<i>line_number</i>]: <i>message</i></c>
 *
 * @param level   Log level of the logged message.
 *
 * @param module  Name of the module that generated the message.
 *
 * @param message A pre-formatted message to log.
 */
typedef void avs_log_handler_t(avs_log_level_t level,
                               const char *module,
                               const char *message);

/**
 * Sets the handler for the library's logging system. There may be only one
 * handler registered at a time.
 *
 * The default log handler prints the log message to <c>stderr</c>.
 *
 * For example on implementing a log handler, refer to <c>demo.c</c>, where a
 * handler using different colors for log levels is used.
 *
 * @param log_handler New log handler function to use.
 *
 * <example>
 * @code
 * static int get_color_for_level(avs_log_level_t level) {
 *     switch (level) {
 *     case AVS_LOG_TRACE:
 *     case AVS_LOG_DEBUG:
 *         return 37; // white
 *     case AVS_LOG_INFO:
 *         return 32; // green
 *     case AVS_LOG_WARNING:
 *         return 33; // yellow
 *     case AVS_LOG_ERROR:
 *         return 31; // red
 *     }
 *     return 37; // white
 * }
 *
 * static void demo_log_handler(avs_log_level_t level,
 *                              const char *module,
 *                              const char *message) {
 *     (void) module;
 *     char time_buf[256] = "";
 *     time_t current_time;
 *     struct tm current_tm;
 *     current_time = time(NULL);
 *     memset(&current_tm, 0, sizeof (current_tm));
 *     localtime_r(&current_time, &current_tm);
 *     strftime(time_buf, sizeof (time_buf), "%c", &current_tm);
 *     fprintf(stderr, "\033[0;%dm%s %s\033[0m\n",
 *             get_color_for_level(level), time_buf, message);
 * }
 *
 * int main() {
 *     avs_log_set_handler(demo_log_handler);
 *     // ...
 * }
 * @endcode
 * </example>
 */
void avs_log_set_handler(avs_log_handler_t *log_handler);

/**
 * Resets the logging system to default settings and frees all resources that
 * may be used by it.
 */
void avs_log_reset(void);

/**
 * @name Logging subsystem internals
 */
/**@{*/
void avs_log_internal_v__(avs_log_level_t level,
                          const char *module,
                          const char *msg,
                          va_list ap);

void avs_log_internal_l__(avs_log_level_t level,
                          const char *module,
                          const char *msg, ...)
        AVS_F_PRINTF(3, 4);

#define AVS_QUOTE(x) #x
#define AVS_QUOTE_MACRO(x) AVS_QUOTE(x)

#define AVS_LOG_MSG_PREFIX_IMPL__(Level, Module) \
        #Level " [" #Module "] [" __FILE__ ":" AVS_QUOTE_MACRO(__LINE__) "]: "

#define AVS_LOG_IMPL__(Level, Variant, ...) \
        avs_log_internal_##Variant##__(Level, __VA_ARGS__)

#define AVS_LOG__TRACE(...) AVS_LOG_IMPL__(AVS_LOG_TRACE, __VA_ARGS__)
#define AVS_LOG__DEBUG(...) AVS_LOG_IMPL__(AVS_LOG_DEBUG, __VA_ARGS__)
#define AVS_LOG__INFO(...) AVS_LOG_IMPL__(AVS_LOG_INFO, __VA_ARGS__)
#define AVS_LOG__WARNING(...) AVS_LOG_IMPL__(AVS_LOG_WARNING, __VA_ARGS__)
#define AVS_LOG__ERROR(...) AVS_LOG_IMPL__(AVS_LOG_ERROR, __VA_ARGS__)

#define AVS_LOG_MSG_PREFIX__TRACE(Module)   AVS_LOG_MSG_PREFIX_IMPL__(TRACE,   Module)
#define AVS_LOG_MSG_PREFIX__DEBUG(Module)   AVS_LOG_MSG_PREFIX_IMPL__(DEBUG,   Module)
#define AVS_LOG_MSG_PREFIX__INFO(Module)    AVS_LOG_MSG_PREFIX_IMPL__(INFO,    Module)
#define AVS_LOG_MSG_PREFIX__WARNING(Module) AVS_LOG_MSG_PREFIX_IMPL__(WARNING, Module)
#define AVS_LOG_MSG_PREFIX__ERROR(Module)   AVS_LOG_MSG_PREFIX_IMPL__(ERROR,   Module)

/* enable compiling-in TRACE messages */
#ifndef AVS_LOG_WITH_TRACE
#undef AVS_LOG__TRACE
#define AVS_LOG__TRACE(...) ((void) 0)
#endif

/* disable compiling-in DEBUG messages */
#ifdef AVS_LOG_WITHOUT_DEBUG
#undef AVS_LOG__DEBUG
#define AVS_LOG__DEBUG(...) ((void) 0)
#endif

void avs_log_set_level__(const char *module, avs_log_level_t level);
/**@}*/

/**
 * Creates a log message and displays it on a specified error output. Message
 * format and additional arguments are the same as for standard C library
 * <c>printf</c>.
 *
 * @param Module Name of the module that generates the message, given as a raw
 *               token.
 *
 * @param Level  Log level, specified as a name of @ref avs_log_level_t (other
 *               than <c>QUIET</c>) with the leading <c>AVS_LOG_</c> omitted.
 */
#define avs_log(Module, Level, ...) \
        AVS_LOG__##Level(l, #Module, AVS_LOG_MSG_PREFIX__##Level (Module) __VA_ARGS__)

/**
 * Creates a log message and displays it on a specified error output. Message
 * format and additional arguments are the same as for standard C library
 * <c>vprintf</c>.
 *
 * @param Module Name of the module that generates the message, given as a raw
 *               token.
 *
 * @param Level  Log level, specified as a name of @ref avs_log_level_t (other
 *               than <c>QUIET</c>) with the leading <c>AVS_LOG_</c> omitted.
 */
#define avs_log_v(Module, Level, ...) \
        AVS_LOG__##Level(v, #Module, AVS_LOG_MSG_PREFIX__##Level (Module) __VA_ARGS__)

/**
 * Sets the logging level for a given module. Messages with lower level than the
 * one set will not be passed to the log writer.
 *
 * If not set, the value set via @ref avs_log_set_default_level is used.
 *
 * @param Module Name of the module that generates the message, given as a raw
 *               token.
 *
 * @param Level  Log level to set (see @ref avs_log_level_t for list of possible
 *               values).
 *
 * <example>
 * @code
 * int main() {
 *     avs_log_set_level(app, AVS_LOG_DEBUG);
 *     avs_log_set_level(libcwmp, AVS_LOG_INFO);
 *     // ...
 * }
 * @endcode
 * </example>
 */
#define avs_log_set_level(Module, Level) avs_log_set_level__(#Module, Level)

/**
 * Sets the logging level for a given module. Messages with lower level than the
 * one set will not be passed to the log writer.
 *
 * Default log level is @ref AVS_LOG_INFO.
 *
 * @param Level  Log level to set (see @ref avs_log_level_t for list of possible
 *               values).
 */
#define avs_log_set_default_level(Level) avs_log_set_level__(NULL, Level)

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_LOG_H */

