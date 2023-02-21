/*
 * Copyright 2023 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_LOG_H
#define AVS_COMMONS_LOG_H

#include <stdarg.h>

#include <avsystem/commons/avs_defs.h>

#ifdef AVS_COMMONS_WITH_EXTERNAL_LOG_LEVELS_HEADER
#    include AVS_COMMONS_WITH_EXTERNAL_LOG_LEVELS_HEADER
#    define AVS_LOGS_CHECKED_DURING_COMPILE_TIME
#    ifndef AVS_LOG_LEVEL_DEFAULT
#        define AVS_LOG_LEVEL_DEFAULT INFO
#    endif
#endif

#ifdef __cplusplus
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
 * User-defined extended handler for logging.
 *
 * The messages sent to the extended log handler only contain formatted string
 * with parameters. Additional information such as log level, module or line
 * number can be added by extended log handler.
 *
 * @param level   Log level of the logged message.
 *
 * @param module  Name of the module that generated the message.
 *
 * @param file    File where message was generated.
 *
 * @param line    Line where message was generated.
 *
 * @param message A pre-formatted message to log.
 */
typedef void avs_log_extended_handler_t(avs_log_level_t level,
                                        const char *module,
                                        const char *file,
                                        unsigned line,
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
 * @param log_handler New log handler function to use. If @c NULL , log handler
 *                    will be reset to the default one.
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
 * Sets the extended handler for the library's logging system.
 *
 * For example on implementing a log handler, refer to <c>demo.c</c>, where an
 * alternative log handler is implemented using extended log handler. While
 * running the demo use option <c>--alternative-logger</c>.
 *
 * @param log_handler New extended log handler function to use. If @c NULL ,
 *                    log handler will be reset to the default one.
 */
void avs_log_set_extended_handler(avs_log_extended_handler_t *log_handler);

/**
 * Resets the logging system to default settings and frees all resources that
 * may be used by it.
 */
void avs_log_reset(void);

#ifndef AVS_COMMONS_WITHOUT_LOG_CHECK_IN_RUNTIME
int avs_log_set_level__(const char *module, avs_log_level_t level);
#endif /* AVS_COMMONS_WITHOUT_LOG_CHECK_IN_RUNTIME */

#ifdef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
/**
 * A group of helper macros for @ref AVS_IS_LOG_LEVEL_ALLOWED.
 */
#    define AVS_LOG_QUIET_NOT_CONTAIN_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_NOT_CONTAIN_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_NOT_CONTAIN_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_NOT_CONTAIN_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_NOT_CONTAIN_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_NOT_CONTAIN_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_NOT_CONTAIN_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_NOT_CONTAIN_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_NOT_CONTAIN_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_NOT_CONTAIN_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_NOT_CONTAIN_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_LAZY_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_LAZY_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_LAZY_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_LAZY_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_QUIET_NOT_CONTAIN_LAZY_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_NOT_CONTAIN_LAZY_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_NOT_CONTAIN_LAZY_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_NOT_CONTAIN_LAZY_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_NOT_CONTAIN_LAZY_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_NOT_CONTAIN_LAZY_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_NOT_CONTAIN_LAZY_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_NOT_CONTAIN_LAZY_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_NOT_CONTAIN_LAZY_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_NOT_CONTAIN_LAZY_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_NOT_CONTAIN_LAZY_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_CONTAIN_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_CONTAIN_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_CONTAIN_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_CONTAIN_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_CONTAIN_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_CONTAIN_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_CONTAIN_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_CONTAIN_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_CONTAIN_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_CONTAIN_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_ERROR_CONTAIN_LAZY_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_CONTAIN_LAZY_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_WARNING_CONTAIN_LAZY_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_CONTAIN_LAZY_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_CONTAIN_LAZY_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_INFO_CONTAIN_LAZY_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_CONTAIN_LAZY_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_CONTAIN_LAZY_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_CONTAIN_LAZY_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_DEBUG_CONTAIN_LAZY_ERROR _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_LAZY_TRACE _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_LAZY_DEBUG _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_LAZY_INFO _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_LAZY_WARNING _ADDED_DUMMY_ARG,
#    define AVS_LOG_TRACE_CONTAIN_LAZY_ERROR _ADDED_DUMMY_ARG,

#    define _AVS_IS_LOG_LEVEL_ALLOWED3(Ignored, Val, ...) Val
#    define AVS_IS_LOG_DEFAULT_LEVEL_ALLOWED2(FalseValue, TrueValue, DummyArg) \
        _AVS_IS_LOG_LEVEL_ALLOWED3(DummyArg FalseValue, TrueValue, dummy)
#    define AVS_IS_LOG_DEFAULT_LEVEL_ALLOWED(                     \
            TrueValue, FalseValue, Level, DefaultLevel, DummyArg) \
        AVS_IS_LOG_DEFAULT_LEVEL_ALLOWED2(                        \
                _AVS_IS_LOG_LEVEL_ALLOWED3(                       \
                        DummyArg TrueValue, FalseValue, dummy),   \
                TrueValue,                                        \
                AVS_LOG_##DefaultLevel##_NOT_CONTAIN_##Level)
#    define _AVS_IS_LOG_LEVEL_ALLOWED2(                                        \
            TrueValue, FalseValue, Level, DefaultLevel, Macro, DummyArg)       \
        _AVS_IS_LOG_LEVEL_ALLOWED3(DummyArg FalseValue,                        \
                                   AVS_IS_LOG_DEFAULT_LEVEL_ALLOWED(           \
                                           TrueValue,                          \
                                           FalseValue,                         \
                                           Level,                              \
                                           DefaultLevel,                       \
                                           AVS_LOG_##Macro##_CONTAIN_##Level), \
                                   dummy)
#    define _AVS_IS_LOG_LEVEL_ALLOWED1(                        \
            Macro, TrueValue, FalseValue, Level, DefaultLevel) \
        _AVS_IS_LOG_LEVEL_ALLOWED2(TrueValue,                  \
                                   FalseValue,                 \
                                   Level,                      \
                                   DefaultLevel,               \
                                   Macro,                      \
                                   AVS_LOG_##Macro##_NOT_CONTAIN_##Level)

/**
 * Checks if macro <c>Macro</c> is defined and log level allows to
 * put logging message into the compiled code.
 * Expands to <c>TrueValue</c> if so, otherwise expands to <c>FalseValue</c>.
 */
#    define AVS_IS_LOG_LEVEL_ALLOWED(                          \
            Macro, TrueValue, FalseValue, Level, DefaultLevel) \
        _AVS_IS_LOG_LEVEL_ALLOWED1(                            \
                Macro, TrueValue, FalseValue, Level, DefaultLevel)

/**
 * Decides if logs for module <c>Module</c> should be compiled into the
 * application. Expands to:
 *     - <c>EMPTY</c> - logs won't be compiled into the application
 *     - <c>NOT_EMPTY</c> - logs will be compiled into the application
 */
#    define AVS_LOG_MODULE_LOGGING_TYPE(Module, Level)                 \
        AVS_IS_LOG_LEVEL_ALLOWED(AVS_CONCAT(AVS_LOG_LEVEL_FOR_MODULE_, \
                                            Module),                   \
                                 NOT_EMPTY,                            \
                                 EMPTY,                                \
                                 Level,                                \
                                 AVS_LOG_LEVEL_DEFAULT)
#endif /* AVS_LOGS_CHECKED_DURING_COMPILE_TIME */

/**
 * Used when using @ref avs_log for module <c>Module</c> if
 * "AVS_LOG_DISABLE_MODULE_<Module>" macro is defined as "1". That way no logs
 * for module <c>Module</c> are compiled into the application.
 */
#define AVS_LOG_EMPTY(...) (void) sizeof(AVS_LOG_NOT_EMPTY(__VA_ARGS__), 0)

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
 *               It may be also prefixed with <c>LAZY_</c> (e.g.
 *               <c>LAZY_INFO</c>) - in that case the log message arguments will
 *               not be evaluated if the current log level is lower than the
 *               currently set for the specified module.
 */
#define AVS_LOG_NOT_EMPTY(Module, Level, ...) \
    AVS_LOG__##Level(l, AVS_QUOTE_MACRO(Module), __VA_ARGS__)

/**
 * Wrapper for the @ref avs_log. Expands to "AVS_LOG_<LogType>", where
 * <c>LogType</c> will be either "EMPTY" or "NOT_EMPTY".
 *
 * @param Module  Name of the module that generates the message, given as a raw
 *                token.
 *
 * @param Level   Log level, specified as a name of @ref avs_log_level_t (other
 *                than <c>QUIET</c>) with the leading <c>AVS_LOG_</c> omitted.
 *                It may be also prefixed with <c>LAZY_</c> (e.g.
 *                <c>LAZY_INFO</c>) - in that case the log message arguments
 *                will not be evaluated if the current log level is lower than
 *                the currently set for the specified module.
 *
 * @param LogType Type of a log for specified <c>Module</c>. Can be <c>EMPTY</c>
 *                or <c>NOT_EMPTY</c>.
 */
#define _AVS_LOG(Module, Level, LogType, ...) \
    AVS_CONCAT(AVS_LOG_, LogType)(Module, Level, __VA_ARGS__)

#ifndef AVS_LOGS_CHECKED_DURING_COMPILE_TIME
/**
 * @param Module Name of the module that generates the message, given as a raw
 *               token.
 *
 * @param Level  Log level, specified as a name of @ref avs_log_level_t (other
 *               than <c>QUIET</c>) with the leading <c>AVS_LOG_</c> omitted.
 *               It may be also prefixed with <c>LAZY_</c> (e.g.
 *               <c>LAZY_INFO</c>) - in that case the log message arguments will
 *               not be evaluated if the current log level is lower than the
 *               currently set for the specified module.
 */
#    define avs_log(Module, Level, ...) \
        _AVS_LOG(Module, Level, NOT_EMPTY, __VA_ARGS__)
#else
/**
 * If <Level> value is higher or equal to "AVS_LOG_LEVEL_FOR_MODULE_<Module>"
 * (if exist) or "AVS_LOG_LEVEL_DEFAULT":
 *     Expands to @ref AVS_LOG_NOT_EMPTY, creates a log message and displays
 *     it on a specified error output. Message format and additional arguments
 *     are the same as for standard C library <c>printf</c>.
 * If <Level> value is lower than "AVS_LOG_LEVEL_FOR_MODULE_<Module>"(if exist)
 * and "AVS_LOG_LEVEL_DEFAULT":
 *     Expands to @ref AVS_LOG_EMPTY so log are not
 *     compiled into the application.
 *
 * @param Module Name of the module that generates the message, given as a raw
 *               token.
 *
 * @param Level  Log level, specified as a name of @ref avs_log_level_t (other
 *               than <c>QUIET</c>) with the leading <c>AVS_LOG_</c> omitted.
 *               It may be also prefixed with <c>LAZY_</c> (e.g.
 *               <c>LAZY_INFO</c>) - in that case the log message arguments will
 *               not be evaluated if the current log level is lower than the
 *               currently set for the specified module.
 */
#    define avs_log(Module, Level, ...)                      \
        _AVS_LOG(Module,                                     \
                 Level,                                      \
                 AVS_LOG_MODULE_LOGGING_TYPE(Module, Level), \
                 __VA_ARGS__)
#endif /* AVS_LOGS_CHECKED_DURING_COMPILE_TIME */

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
 *               It may be also prefixed with <c>LAZY_</c> (e.g.
 *               <c>LAZY_INFO</c>) - in that case the log message arguments will
 *               not be evaluated if the current log level is lower than the
 *               currently set for the specified module.
 */
#define avs_log_v(Module, Level, ...) \
    AVS_LOG__##Level(v, AVS_QUOTE_MACRO(Module), __VA_ARGS__)

/**
 * If the current log level is high enough, creates a log message and displays
 * it on a specified error output. Message format and additional arguments are
 * the same as for standard C library <c>printf</c>.
 *
 * This is alternate syntax for specifying one of <c>LAZY_*</c> pseudo-levels
 * to @ref avs_log.
 *
 * @param Module Name of the module that generates the message, given as a raw
 *               token.
 *
 * @param Level  Log level, specified as a name of @ref avs_log_level_t (other
 *               than <c>QUIET</c>) with the leading <c>AVS_LOG_</c> omitted.
 */
#define avs_log_lazy(Module, Level, ...) \
    avs_log(Module, LAZY_##Level, __VA_ARGS__)

/**
 * If the current log level is high enough, creates a log message and displays
 * it on a specified error output. Message format and additional arguments are
 * the same as for standard C library <c>vprintf</c>.
 *
 * This is alternate syntax for specifying one of <c>LAZY_*</c> pseudo-levels
 * to @ref avs_log_v.
 *
 * @param Module Name of the module that generates the message, given as a raw
 *               token.
 *
 * @param Level  Log level, specified as a name of @ref avs_log_level_t (other
 *               than <c>QUIET</c>) with the leading <c>AVS_LOG_</c> omitted.
 */
#define avs_log_lazy_v(Module, Level, ...) \
    avs_log_v(Module, LAZY_##Level, __VA_ARGS__)

#ifndef AVS_COMMONS_WITHOUT_LOG_CHECK_IN_RUNTIME
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
 * @return 0 on success, negative value in case of an error (i.e. out of memory)
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
#    define avs_log_set_level(Module, Level) \
        avs_log_set_level__(AVS_QUOTE_MACRO(Module), Level)

/**
 * Sets the logging level for a given module. Messages with lower level than the
 * one set will not be passed to the log writer.
 *
 * Default log level is @ref AVS_LOG_INFO.
 *
 * @param Level  Log level to set (see @ref avs_log_level_t for list of possible
 *               values).
 */
#    define avs_log_set_default_level(Level) \
        ((void) avs_log_set_level__(NULL, Level))
#endif /* AVS_COMMONS_WITHOUT_LOG_CHECK_IN_RUNTIME */

#ifndef AVS_COMMONS_WITH_MICRO_LOGS
#    define AVS_DISPOSABLE_LOG(Arg) Arg
#else
#    define AVS_DISPOSABLE_LOG(Arg) " "
#endif // AVS_COMMONS_WITH_MICRO_LOGS

#define AVS_COMMONS_LOG_IMPL_INCLUDE_GUARD
#include "avs_log_impl.h"
#undef AVS_COMMONS_LOG_IMPL_INCLUDE_GUARD

#ifdef __cplusplus
}
#endif

#endif /* AVS_COMMONS_LOG_H */
