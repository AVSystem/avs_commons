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

#if defined(AVS_COMMONS_WITH_POISONING) && !defined(AVS_COMMONS_POISON_H) \
        && !defined(AVS_UNIT_TESTING)
#    define AVS_COMMONS_POISON_H

// This file ensures that some functions we "don't like" from the standard
// library (for reasons described below) are not used in any of the source
// files. This file is included only when compiling using GCC
//
// Also note that some functions (such as time()) are blacklisted with whole
// headers, through test_headers.py.

// STDIO ///////////////////////////////////////////////////////////////////////

// Forward inclusion of stdio.h, before poisoning all of its names
#    include <stdio.h>

// We need to define AVS_F_PRINTF (normally defined in defs.h)
// before poisoning "printf"
#    define AVS_F_PRINTF(fmt_idx, ellipsis_idx) \
        __attribute__((format(printf, fmt_idx, ellipsis_idx)))

#    ifndef AVS_STREAM_STREAM_FILE_C
// File handling funcitons used in stream/src/stream_file.c
#        pragma GCC poison clearerr
#        pragma GCC poison feof
#        pragma GCC poison ferror
#        pragma GCC poison fread
#        pragma GCC poison fseek
#        pragma GCC poison ftell
#    endif // AVS_STREAM_STREAM_FILE_C

#    ifndef AVS_UNIT_SOURCE
// stdout functions used in unit test framework

#        undef stdout
#        pragma GCC poison stdout

#        pragma GCC poison perror
#        pragma GCC poison printf
#        pragma GCC poison vfprintf
#        pragma GCC poison vprintf

#        ifndef AVS_LOG_LOG_C
// stderr is used in unit test framework and default log handler
#            undef stderr
#            pragma GCC poison stderr
#        endif // AVS_LOG_LOG_C

#        ifndef AVS_STREAM_STREAM_FILE_C
// fclose is used in unit test framework and stream/src/stream_file.c
#            pragma GCC poison fclose
#        endif // AVS_STREAM_STREAM_FILE_C

#        ifndef AVS_NET_API_C
// fflush is used in unit test framework and network debug log
#            pragma GCC poison fflush
#        endif // AVS_NET_API_C

#        if !defined(AVS_LOG_LOG_C) && !defined(AVS_NET_API_C)
// fprintf is used in unit test framework, network debug log and logging
#            pragma GCC poison fprintf
#        endif // !defined(AVS_LOG_LOG_C) && !defined(AVS_NET_API_C)

#    endif // AVS_UNIT_SOURCE

#    if !defined(AVS_STREAM_STREAM_FILE_C) && !defined(AVS_NET_API_C)

// fopen and fwrite are used in stream/src/stream_file.c and network debug log
#        pragma GCC poison fopen
#        pragma GCC poison fwrite

#    endif // !defined(AVS_STREAM_STREAM_FILE_C) && !defined(AVS_NET_API_C)

#    pragma GCC poison gets
#    pragma GCC poison puts

// stdin is not used anywhere
#    undef stdin
#    pragma GCC poison stdin

// getc and putc are macros in GNU libc for some reason
#    ifdef getc
#        undef getc
#    endif
#    pragma GCC poison getc

#    ifdef putc
#        undef putc
#    endif
#    pragma GCC poison putc

// rest of the file handling functions, not used anywhere
#    pragma GCC poison fgetwc
#    pragma GCC poison fgetws
#    pragma GCC poison getwc
#    pragma GCC poison getwchar
#    pragma GCC poison fwscanf
#    pragma GCC poison wscanf
#    pragma GCC poison vfwscanf
#    pragma GCC poison vwscanf
#    pragma GCC poison fputwc
#    pragma GCC poison fputws
#    pragma GCC poison putwc
#    pragma GCC poison putwchar
#    pragma GCC poison fwprintf
#    pragma GCC poison wprintf
#    pragma GCC poison vfwprintf
#    pragma GCC poison vwprintf
#    pragma GCC poison ungetwc
#    pragma GCC poison fgetc
#    pragma GCC poison fgets
#    pragma GCC poison fputc
#    pragma GCC poison fputs
#    pragma GCC poison fscanf
#    pragma GCC poison getchar
#    pragma GCC poison putchar
#    pragma GCC poison scanf
#    pragma GCC poison ungetc
#    pragma GCC poison vfscanf
#    pragma GCC poison vscanf
#    pragma GCC poison remove
#    pragma GCC poison rename
#    pragma GCC poison tmpfile
#    pragma GCC poison tmpnam
#    pragma GCC poison freopen
#    pragma GCC poison setbuf
#    pragma GCC poison setvbuf
#    pragma GCC poison fgetpos
#    pragma GCC poison fsetpos
#    pragma GCC poison rewind

// STDLIB //////////////////////////////////////////////////////////////////////

// Forward inclusion of stdlib.h, before poisoning all of its names
#    include <stdlib.h>

#    ifndef AVS_UTILS_COMPAT_STDLIB_MEMORY_C
// Memory allocation functions - only allowed in utils/compat/stdlib/memory.c;
// in all other places avs_malloc() etc. shall be used instead.
#        pragma GCC poison malloc
#        pragma GCC poison calloc
#        pragma GCC poison realloc
#        pragma GCC poison free
#    endif // AVS_UTILS_COMPAT_STDLIB_MEMORY_C

#    if !defined(AVS_UNIT_SOURCE) && !defined(AVS_GLOBAL_SOURCE)
// used in unit testing framework and some global settings
#        pragma GCC poison atexit
#        pragma GCC poison exit
#        pragma GCC poison getenv
#    endif // AVS_UNIT_SOURCE

#    if !defined(AVS_UNIT_SOURCE) \
            && !defined(AVS_COMPAT_THREADING_PTHREAD_INIT_ONCE)
// abort() is also used in PThread init_once implementation if initialization
// fails really hard
#        pragma GCC poison abort
#    endif // !defined(AVS_UNIT_SOURCE) &&
           // !defined(AVS_COMPAT_THREADING_PTHREAD_INIT_ONCE)

// System program control flow functions
#    pragma GCC poison _Exit
#    pragma GCC poison system

// Default (and not thread-safe) PRNG
#    pragma GCC poison rand
#    pragma GCC poison srand

// multibyte character conversions
#    pragma GCC poison mblen
#    pragma GCC poison mbtowc
#    pragma GCC poison mbstowc
#    pragma GCC poison wcstombs
#    pragma GCC poison wctomb

#endif // defined(AVS_COMMONS_WITH_POISONING) && !defined(AVS_COMMONS_POISON_H)
