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

#ifndef AVS_COMMONS_LOG_IMPL_INCLUDE_GUARD
#    error "avs_log_impl.h shall not be included directly"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef AVS_COMMONS_WITH_EXTERNAL_LOGGER_HEADER
#    include AVS_COMMONS_WITH_EXTERNAL_LOGGER_HEADER
#else
/**
 * @name Logging subsystem internals
 */
/**@{*/
#    ifndef AVS_COMMONS_WITHOUT_LOG_CHECK_IN_RUNTIME
int avs_log_should_log__(avs_log_level_t level, const char *module);
#    endif /* AVS_COMMONS_WITHOUT_LOG_CHECK_IN_RUNTIME */

void avs_log_internal_forced_v__(avs_log_level_t level,
                                 const char *module,
                                 const char *file,
                                 unsigned line,
                                 const char *msg,
                                 va_list ap);

void avs_log_internal_v__(avs_log_level_t level,
                          const char *module,
                          const char *file,
                          unsigned line,
                          const char *msg,
                          va_list ap);

void avs_log_internal_forced_l__(avs_log_level_t level,
                                 const char *module,
                                 const char *file,
                                 unsigned line,
                                 const char *msg,
                                 ...) AVS_F_PRINTF(5, 6);

void avs_log_internal_l__(avs_log_level_t level,
                          const char *module,
                          const char *file,
                          unsigned line,
                          const char *msg,
                          ...) AVS_F_PRINTF(5, 6);

#    define AVS_LOG_IMPL__(Level, Variant, ModuleStr, ...)                   \
        avs_log_internal_##Variant##__(Level, ModuleStr, __FILE__, __LINE__, \
                                       __VA_ARGS__)
#    ifndef AVS_COMMONS_WITHOUT_LOG_CHECK_IN_RUNTIME
#        define AVS_LOG_LAZY_IMPL__(Level, Variant, ModuleStr, ...)  \
            (avs_log_should_log__(Level, ModuleStr)                  \
                     ? avs_log_internal_forced_##Variant##__(        \
                               Level, ModuleStr, __FILE__, __LINE__, \
                               __VA_ARGS__)                          \
                     : (void) 0)
#    else
#        define AVS_LOG_LAZY_IMPL__(Level, Variant, ModuleStr, ...)           \
            avs_log_internal_forced_##Variant##__(Level, ModuleStr, __FILE__, \
                                                  __LINE__, __VA_ARGS__)
#    endif /* AVS_COMMONS_WITHOUT_LOG_CHECK_IN_RUNTIME */
#    define AVS_LOG__TRACE(...) AVS_LOG_IMPL__(AVS_LOG_TRACE, __VA_ARGS__)
#    define AVS_LOG__DEBUG(...) AVS_LOG_IMPL__(AVS_LOG_DEBUG, __VA_ARGS__)
#    define AVS_LOG__INFO(...) AVS_LOG_IMPL__(AVS_LOG_INFO, __VA_ARGS__)
#    define AVS_LOG__WARNING(...) AVS_LOG_IMPL__(AVS_LOG_WARNING, __VA_ARGS__)
#    define AVS_LOG__ERROR(...) AVS_LOG_IMPL__(AVS_LOG_ERROR, __VA_ARGS__)

#    define AVS_LOG__LAZY_TRACE(...) \
        AVS_LOG_LAZY_IMPL__(AVS_LOG_TRACE, __VA_ARGS__)
#    define AVS_LOG__LAZY_DEBUG(...) \
        AVS_LOG_LAZY_IMPL__(AVS_LOG_DEBUG, __VA_ARGS__)
#    define AVS_LOG__LAZY_INFO(...) \
        AVS_LOG_LAZY_IMPL__(AVS_LOG_INFO, __VA_ARGS__)
#    define AVS_LOG__LAZY_WARNING(...) \
        AVS_LOG_LAZY_IMPL__(AVS_LOG_WARNING, __VA_ARGS__)
#    define AVS_LOG__LAZY_ERROR(...) \
        AVS_LOG_LAZY_IMPL__(AVS_LOG_ERROR, __VA_ARGS__)

#    ifdef AVS_LOG_LEVEL_DEFAULT
#        if defined(AVS_LOG_WITH_TRACE) || defined(AVS_LOG_WITHOUT_DEBUG)
#            error "if AVS_LOG_LEVEL_DEFAULT is set, AVS_LOG_WITH_TRACE && AVS_LOG_WITHOUT_DEBUG are redundant"
#        endif
#    else
/* enable compiling-in TRACE messages */
#        ifndef AVS_LOG_WITH_TRACE
#            undef AVS_LOG__TRACE
#            define AVS_LOG__TRACE(...) \
                ((void) sizeof(AVS_LOG_IMPL__(AVS_LOG_TRACE, __VA_ARGS__), 0))
#            undef AVS_LOG__LAZY_TRACE
#            define AVS_LOG__LAZY_TRACE(...) \
                ((void) sizeof(              \
                        AVS_LOG_LAZY_IMPL__(AVS_LOG_DEBUG, __VA_ARGS__), 0))
#        endif

/* disable compiling-in DEBUG messages */
#        ifdef AVS_LOG_WITHOUT_DEBUG
#            undef AVS_LOG__DEBUG
#            define AVS_LOG__DEBUG(...) \
                ((void) sizeof(AVS_LOG_IMPL__(AVS_LOG_DEBUG, __VA_ARGS__), 0))
#            undef AVS_LOG__LAZY_DEBUG
#            define AVS_LOG__LAZY_DEBUG(...) \
                ((void) sizeof(              \
                        AVS_LOG_LAZY_IMPL__(AVS_LOG_DEBUG, __VA_ARGS__), 0))
#        endif
#    endif /*AVS_LOG_LEVEL_DEFAULT*/

/**@}*/
#endif

#ifdef __cplusplus
}
#endif
