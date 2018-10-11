/*
 * Copyright 2017-2018 AVSystem <avsystem@avsystem.com>
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

#ifndef AVS_COMMONS_SCHED_H
#define AVS_COMMONS_SCHED_H

#include <avsystem/commons/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @file sched.h
 */

typedef struct avs_sched_job_struct avs_sched_job_t;

typedef avs_sched_job_t *avs_sched_handle_t;

typedef struct avs_sched_struct avs_sched_t;

typedef void avs_sched_clb_t(avs_sched_t *sched, const void *data);

avs_sched_t *avs_sched_new(const char *name, void *data);

void avs_sched_cleanup(avs_sched_t **sched_ptr);

void *avs_sched_data(avs_sched_t *sched);

avs_time_monotonic_t avs_sched_time_of_next(avs_sched_t *sched);

static inline avs_time_duration_t avs_sched_time_to_next(avs_sched_t *sched) {
    avs_time_duration_t result = avs_time_monotonic_diff(
            avs_sched_time_of_next(sched), avs_time_monotonic_now());
    return avs_time_duration_less(result, AVS_TIME_DURATION_ZERO)
            ? AVS_TIME_DURATION_ZERO : result;
}

int avs_sched_wait_until_next(avs_sched_t *sched,
                              avs_time_monotonic_t deadline);

static inline int avs_sched_wait_for_next(avs_sched_t *sched,
                                          avs_time_duration_t timeout) {
    return avs_sched_wait_until_next(
            sched,
            avs_time_monotonic_add(avs_time_monotonic_now(), timeout));
}

int avs_sched_run(avs_sched_t *sched);

int avs_sched_at_impl__(avs_sched_t *sched,
                        avs_sched_handle_t *out_handle,
                        avs_time_monotonic_t instant,
                        const char *log_file,
                        unsigned log_line,
                        const char *log_name,
                        avs_sched_clb_t *clb,
                        const void *clb_data,
                        size_t clb_data_size);

#ifndef AVS_LOG_WITH_TRACE
#   define AVS_SCHED_LOG_ARGS__(...) (NULL), 0, (NULL)
#elif !defined(AVS_SCHED_WITH_ARGS_LOG)
#   define AVS_SCHED_LOG_ARGS__(Clb, ClbArgs) __FILE__, __LINE__, AVS_QUOTE(Clb)
#else // !defined(AVS_SCHED_WITH_ARGS_LOG)
#   define AVS_SCHED_LOG_ARGS__(Clb, ClbArgs) \
        __FILE__, __LINE__, AVS_QUOTE(Clb) AVS_QUOTE(ClbArgs)
#endif // AVS_LOG_WITH_TRACE // !defined(AVS_SCHED_WITH_ARGS_LOG)

#define AVS_SCHED_AT(Sched, OutHandle, Instant, Clb, ...) \
        avs_sched_at_impl__((Sched), (OutHandle), (Instant), \
                            AVS_SCHED_LOG_ARGS__(Clb, (__VA_ARGS__)), \
                            (Clb), __VA_ARGS__)

#define AVS_SCHED_DELAYED(Sched, OutHandle, Delay, ...) \
        AVS_SCHED_AT(Sched, OutHandle, \
                     avs_time_monotonic_add(avs_time_monotonic_now(), Delay), \
                     __VA_ARGS__)

#define AVS_SCHED_NOW(Sched, OutHandle, ...) \
        AVS_SCHED_AT(Sched, OutHandle, avs_time_monotonic_now(), __VA_ARGS__)

avs_time_monotonic_t avs_sched_time(avs_sched_handle_t *handle_ptr);

int avs_sched_del(avs_sched_handle_t *handle_ptr);

int avs_sched_release(avs_sched_handle_t *handle_ptr);

int avs_sched_is_descendant(avs_sched_t *ancestor,
                            avs_sched_t *maybe_descendant);

int avs_sched_register_child(avs_sched_t *parent, avs_sched_t *child);

int avs_sched_unregister_child(avs_sched_t *parent, avs_sched_t *child);

int avs_sched_leap_time(avs_sched_t *sched, avs_time_duration_t diff);

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_SCHED_H */
