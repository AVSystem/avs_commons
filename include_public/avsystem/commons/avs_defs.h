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

#ifndef AVS_COMMONS_DEFS_H
#define AVS_COMMONS_DEFS_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <avsystem/commons/avs_commons_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file avs_defs.h
 *
 * Global common definitions.
 */

#ifdef AVS_COMMONS_NET_WITH_IPV6
#    define AVS_ADDRSTRLEN \
        sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#elif defined(AVS_COMMONS_NET_WITH_IPV4)
#    define AVS_ADDRSTRLEN sizeof("255.255.255.255")
#endif

#ifndef IF_NAMESIZE
#    ifdef AVS_COMMONS_HAVE_NET_IF_H
#        include <net/if.h>
#    else
#        define IF_NAMESIZE 16
#    endif
#endif // IF_NAMESIZE

/**
 * Internal definitions used by the library to implement the functionality.
 */
/**@{*/
#define AVS_VARARG_LENGTH_INTERNAL__(                    \
        _10, _9, _8, _7, _6, _5, _4, _3, _2, _1, N, ...) \
    N

#define AVS_VARARG0_INTERNAL__(Arg, ...) Arg

#define AVS_CONCAT_RAW_INTERNAL__(prefix, suffix) prefix##suffix

#define AVS_CONCAT_INTERNAL__(prefix, suffix) \
    AVS_CONCAT_RAW_INTERNAL__(prefix, suffix)

#define AVS_CONCAT_INTERNAL_1__(_1) _1
#define AVS_CONCAT_INTERNAL_2__(_1, _2) AVS_CONCAT_INTERNAL__(_1, _2)
#define AVS_CONCAT_INTERNAL_3__(_1, ...) \
    AVS_CONCAT_INTERNAL__(_1, AVS_CONCAT_INTERNAL_2__(__VA_ARGS__))
#define AVS_CONCAT_INTERNAL_4__(_1, ...) \
    AVS_CONCAT_INTERNAL__(_1, AVS_CONCAT_INTERNAL_3__(__VA_ARGS__))
#define AVS_CONCAT_INTERNAL_5__(_1, ...) \
    AVS_CONCAT_INTERNAL__(_1, AVS_CONCAT_INTERNAL_4__(__VA_ARGS__))
#define AVS_CONCAT_INTERNAL_6__(_1, ...) \
    AVS_CONCAT_INTERNAL__(_1, AVS_CONCAT_INTERNAL_5__(__VA_ARGS__))
#define AVS_CONCAT_INTERNAL_7__(_1, ...) \
    AVS_CONCAT_INTERNAL__(_1, AVS_CONCAT_INTERNAL_6__(__VA_ARGS__))
#define AVS_CONCAT_INTERNAL_8__(_1, ...) \
    AVS_CONCAT_INTERNAL__(_1, AVS_CONCAT_INTERNAL_7__(__VA_ARGS__))
#define AVS_CONCAT_INTERNAL_9__(_1, ...) \
    AVS_CONCAT_INTERNAL__(_1, AVS_CONCAT_INTERNAL_8__(__VA_ARGS__))
#define AVS_CONCAT_INTERNAL_10__(_1, ...) \
    AVS_CONCAT_INTERNAL__(_1, AVS_CONCAT_INTERNAL_9__(__VA_ARGS__))

#define AVS_ALIGN_POINTER_INTERNAL__(type, ptr, alignment) \
    (type)((uintptr_t) (ptr)                               \
           + ((alignment) -1                               \
              - ((uintptr_t) (ptr) + ((alignment) -1)) % (alignment)))

#define VARARG_REST_IMPL_1__(Arg)
#define VARARG_REST_IMPL_2_OR_MORE__(Arg, ...) , __VA_ARGS__
#define VARARG_REST_IMPL_2__ VARARG_REST_IMPL_2_OR_MORE__
#define VARARG_REST_IMPL_3__ VARARG_REST_IMPL_2_OR_MORE__
#define VARARG_REST_IMPL_4__ VARARG_REST_IMPL_2_OR_MORE__
#define VARARG_REST_IMPL_5__ VARARG_REST_IMPL_2_OR_MORE__
#define VARARG_REST_IMPL_6__ VARARG_REST_IMPL_2_OR_MORE__
#define VARARG_REST_IMPL_7__ VARARG_REST_IMPL_2_OR_MORE__
#define VARARG_REST_IMPL_8__ VARARG_REST_IMPL_2_OR_MORE__
#define VARARG_REST_IMPL_9__ VARARG_REST_IMPL_2_OR_MORE__
#define VARARG_REST_IMPL_10__ VARARG_REST_IMPL_2_OR_MORE__
/**@}*/

/**
 * Returns the first argument from a variable argument pack.
 */
#define AVS_VARARG0(...) AVS_VARARG0_INTERNAL__(__VA_ARGS__, _)

/**
 * Returns the variable argument pack without the first argument (but including
 * the comma after it, if present).
 */
#define AVS_VARARG_REST(...)                                          \
    AVS_CONCAT(VARARG_REST_IMPL_, AVS_VARARG_LENGTH(__VA_ARGS__), __) \
    (__VA_ARGS__)

/**
 * Calculates the number of arguments to the macro. Works with up to 10
 * arguments.
 */
#define AVS_VARARG_LENGTH(...) \
    AVS_VARARG_LENGTH_INTERNAL__(__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

/**
 * Returns a pointer to a structure member given by offset. Can be thought of as
 * an inverse operation to standard library <c>offsetof</c>
 *
 * @param type       Type of the data member.
 *
 * @param struct_ptr Pointer to a data structure.
 *
 * @param offset     Offset in bytes from <c>struct_ptr</c>.
 */
#define AVS_APPLY_OFFSET(type, struct_ptr, offset) \
    ((type *) (void *) (((char *) (intptr_t) (struct_ptr)) + (offset)))

/**
 * Concatenates tokens passed as arguments. Can be used to do macro expansion
 * before standard C preprocessor concatenation.
 */
#define AVS_CONCAT(...)                                            \
    AVS_CONCAT_INTERNAL__(                                         \
            AVS_CONCAT_INTERNAL__(AVS_CONCAT_INTERNAL_,            \
                                  AVS_VARARG_LENGTH(__VA_ARGS__)), \
            __)                                                    \
    (__VA_ARGS__)

/**
 * Stringifies a token.
 *
 * @param Value Token to stringify.
 */
#define AVS_QUOTE(Value) #Value

/**
 * Stringifies a token with performing additional macro expansion step.
 *
 * @param Value Token to stringify.
 */
#define AVS_QUOTE_MACRO(Value) AVS_QUOTE(Value)

/**
 * C89-compliant replacement for <c>max_align_t</c>.
 *
 * <c>max_align_t</c> is a type defined in C11 and C++11 standards, that has
 * alignment requirements suitable for any primitive data type.
 *
 * This type simulates it with an union of types that are considered candidates
 * for the largest type available - a pointer, a function pointer,
 * <c>long double</c> and <c>intmax_t</c>.
 */
typedef union {
    /** @cond Doxygen_Suppress */
    /* candidates for "largest type"
     * add offending type if getting alignment errors */
    void *ptr;
    void (*fptr)();
    long double ld;
    intmax_t i;
    /** @endcond */
} avs_max_align_t;

/**
 * Returns @p type alignment requirements.
 */
#ifdef __cplusplus
} // } extern "C"
// Source: http://wambold.com/Martin/writings/alignof.html
namespace {
template <typename T>
struct avs_commons_alignment_trick__ {
    char c;
    T member;
};
} // namespace
#    define AVS_ALIGNOF(type) \
        offsetof(::avs_commons_alignment_trick__<type>, member)
extern "C" {
#elif __STDC_VERSION__ >= 201112L /* C11 */
#    define AVS_ALIGNOF(type) _Alignof(type)
#else
#    define AVS_ALIGNOF(type)   \
        offsetof(               \
                struct {        \
                    char pad;   \
                    type value; \
                },              \
                value)
#endif

/**
 * Allocates stack storage that is aligned as @p align_as type.
 */
#if __STDC_VERSION__ >= 201112L /* C11 */
#    define AVS_ALIGNED_VLA(type, name, size, align_as) \
        _Alignas(align_as) type name[size]
#elif defined(__GNUC__) || defined(__clang__) /* GCC or clang */
#    define AVS_ALIGNED_VLA(type, name, size, align_as) \
        type name[size] __attribute__((aligned(AVS_ALIGNOF(align_as))))
#else /* C99 standard fallback (might waste few bytes) */
#    define AVS_ALIGNED_VLA(type, name, size, align_as)                      \
        uint8_t AVS_CONCAT(                                                  \
                name,                                                        \
                __vla_,                                                      \
                __LINE__)[sizeof(type[size]) + (AVS_ALIGNOF(align_as) - 1)]; \
        type *const name = (AVS_ALIGN_POINTER_INTERNAL__(                    \
                type *,                                                      \
                AVS_CONCAT(name, __vla_, __LINE__),                          \
                AVS_ALIGNOF(align_as)))
#endif

/**
 * Allocates stack buffer properly aligned to store arbitrary data type.
 */
#define AVS_ALIGNED_STACK_BUF(name, size) \
    AVS_ALIGNED_VLA(uint8_t, name, size, avs_max_align_t)

/**
 * C89-compliant replacement for <c>static_assert</c>.
 */
#define AVS_STATIC_ASSERT(condition, message)    \
    struct AVS_CONCAT(static_assert_, message) { \
        char message[(condition) ? 1 : -1];      \
    }

typedef long avs_off_t;

#ifdef __cplusplus
}
#endif

#if !defined(AVS_CONFIG_TYPEOF) && !defined(AVS_CONFIG_NO_TYPEOF) \
        && !defined(__cplusplus) && __GNUC__
/**
 * Alias to the <c>typeof</c> keyword, if available.
 *
 * It will be automatically defined as <c>__typeof__(symbol)</c> if compiling on
 * a GNU compiler or compatible.
 *
 * <c>typeof</c> is not necessary for the library to function, but it increases
 * type safety and in some cases allows for cleaner code.
 *
 * It can be defined prior to including <c>defs.h</c> to use the <c>typeof</c>
 * keyword available in the target compiler.
 *
 * Alternatively, <c>AVS_CONFIG_NO_TYPEOF</c> can be defined to suppress using
 * <c>typeof</c> even on GNU compilers (e.g. for testing).
 */
#    define AVS_CONFIG_TYPEOF __typeof__
#endif

/**
 * @def AVS_TYPEOF_PTR(symbol)
 *
 * This macro is used to avoid having to specify pointer type where possible.
 * It uses <c>typeof</c> if possible. Otherwise, it just produces casts to
 * <c>void *</c>, which is unsafe, but permitted by the C standard
 * (usage might produce warnings, though).
 */
#ifdef AVS_CONFIG_TYPEOF
#    define AVS_TYPEOF_PTR(symbol) AVS_CONFIG_TYPEOF(symbol)
#elif defined(__cplusplus) \
        && (__cplusplus >= 201103L || defined(__GXX_EXPERIMENTAL_CXX0X__))
#    include <type_traits>
#    define AVS_TYPEOF_PTR(symbol) std::decay<decltype((symbol))>::type
#else
#    define AVS_TYPEOF_PTR(symbol) void *
#endif

#define AVS_0_STARS__
#define AVS_1_STARS__ *
#define AVS_STARS__(Count) AVS_CONCAT(AVS_, Count, _STARS__)

#ifdef __cplusplus
namespace {

template <typename CastTo>
struct AvsCallWithCast__ {
    template <typename Func, typename T>
    static inline T *call(const Func &func, T *arg) {
        return (T *) (intptr_t) func((CastTo) (intptr_t) arg);
    }

    template <typename Func, typename T, typename Arg2>
    static inline T *call(const Func &func, T *arg, const Arg2 &arg2) {
        return (T *) (intptr_t) func((CastTo) (intptr_t) arg, arg2);
    }

    template <typename Func, typename T, typename Arg2, typename Arg3>
    static inline T *
    call(const Func &func, T *arg, const Arg2 &arg2, const Arg3 &arg3) {
        return (T *) (intptr_t) func((CastTo) (intptr_t) arg, arg2, arg3);
    }

    template <typename Func,
              typename T,
              typename Arg2,
              typename Arg3,
              typename Arg4>
    static inline T *call(const Func &func,
                          T *arg,
                          const Arg2 &arg2,
                          const Arg3 &arg3,
                          const Arg4 &arg4) {
        return (T *) (intptr_t) func((CastTo) (intptr_t) arg, arg2, arg3, arg4);
    }
};

} // namespace

#    define AVS_CALL_WITH_CAST(LevelsOfIndirection, Func, ...)               \
        (::AvsCallWithCast__<void * AVS_STARS__(LevelsOfIndirection)>::call( \
                Func, __VA_ARGS__))
#else
#    define AVS_CALL_WITH_CAST(LevelsOfIndirection, Func, ...)               \
        ((AVS_TYPEOF_PTR(AVS_STARS__(LevelsOfIndirection)(                   \
                AVS_VARARG0(__VA_ARGS__))) AVS_STARS__(LevelsOfIndirection)) \
                 Func((void *AVS_STARS__(LevelsOfIndirection))(              \
                         intptr_t) __VA_ARGS__))
#endif

#if (__GNUC__ >= 4)
#    define AVS_F_SENTINEL __attribute__((sentinel(0)))
#endif
#if !defined(AVS_F_PRINTF) && defined(__GNUC__) \
        && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2))
#    define AVS_F_PRINTF(fmt_idx, ellipsis_idx) \
        __attribute__((format(printf, fmt_idx, ellipsis_idx)))
#endif

#ifndef AVS_F_SENTINEL
#    define AVS_F_SENTINEL
#endif
#ifndef AVS_F_PRINTF
#    define AVS_F_PRINTF(...)
#endif

#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5))
#    define AVS_DEPRECATED(Message) __attribute__((deprecated(Message)))
#elif (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
#    define AVS_DEPRECATED(Message) __attribute__((deprecated))
#else
#    define AVS_DEPRECATED(Message)
#endif

#define AVS_CONTAINER_OF(ptr, type, member) \
    ((type *) (void *) ((char *) (intptr_t) (ptr) -offsetof(type, member)))

#define AVS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define AVS_MAX(a, b) ((a) < (b) ? (b) : (a))
#define AVS_ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

/*
 * Definition of an assert with hard-coded string literal message that does not
 * trigger compiler warnings.
 */
#define AVS_ASSERT(cond, msg) assert((cond) && (bool) "" msg)

/*
 * Marks an execution path as breaking some invariants, which should never
 * happen in correct code.
 */
#define AVS_UNREACHABLE(msg) AVS_ASSERT(0, msg)

#define AVS_PRAGMA(x) _Pragma(#x)

#ifdef AVS_COMMONS_WITH_POISONING
#    define AVS_POISON(identifier) AVS_PRAGMA(GCC poison identifier)
#else
#    define AVS_POISON(identifier)
#endif

#endif /* AVS_COMMONS_DEFS_H */
