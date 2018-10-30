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

#include <avsystem/commons/defs.h>
#include <avsystem/commons/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @file sched.h
 */

/**
 * Internal structure that describes a scheduled job.
 */
typedef struct avs_sched_job_struct avs_sched_job_t;

/**
 * Handle to a scheduled job. Please see documentation of @ref AVS_SCHED_AT,
 * @ref avs_sched_del and @ref avs_sched_detach for more information.
 *
 * NOTE: Attempting to modify the value of an <c>avs_sched_handle_t</c> variable
 * in any other way than by calling functions from this module, or moving any
 * data containing <c>avs_sched_handle_t</c>, may result in undefined behaviour.
 */
typedef avs_sched_job_t *avs_sched_handle_t;

/**
 * Object type of a scheduler.
 */
typedef struct avs_sched_struct avs_sched_t;

/**
 * Type of a function callback that can be scheduled as a job
 *
 * @param sched Scheduler object for which the job is executed.
 *
 * @param data  Pointer to a copy of data passed as <c>ClbData</c> to
 *              @ref AVS_SCHED_AT, @ref AVS_SCHED_DELAYED or @ref AVS_SCHED_NOW
 */
typedef void avs_sched_clb_t(avs_sched_t *sched, const void *data);

/**
 * Creates a new scheduler object.
 *
 * @param name The name of the scheduler that will be used in log messages.
 *             If NULL, <c>"(unknown)"</c> will be used instead.
 *
 * @param data An opaque pointer that will be possible to retrieve from the
 *             scheduler using @ref avs_sched_data . The scheduler will not
 *             attempt to access or manipulate that pointer in any other way.
 *
 * @returns Created scheduler object, or NULL if there is a fatal error
 *          (not enough memory, or a problem with creation of synchronization
 *          primitives).
 */
avs_sched_t *avs_sched_new(const char *name, void *data);

/**
 * Destroys the scheduler and releases all resources related to it.
 *
 * Before the scheduler is destroyed, all jobs scheduled before or at current
 * time are executed. During execution of these jobs, any attempts to schedule
 * new jobs on this scheduler will fail.
 *
 * All remaining jobs will be aborted, and their handle variables reset to
 * <c>NULL</c>.
 *
 * NOTE: Attempting to clean up a scheduler that is concurrently manipulated in
 * any way from another thread is undefined behaviour.
 *
 * @param sched_ptr Pointer to a variable that holds the scheduler to destroy.
 *                  It will be reset to <c>NULL</c> afterwards.
 */
void avs_sched_cleanup(avs_sched_t **sched_ptr);

/**
 * Retrieves the value passed as the <c>data</c> argument when creating the
 * scheduler using @ref avs_sched_new .
 *
 * NOTE: Passing <c>NULL</c> as @p sched results in undefined behaviour.
 *
 * @param sched Scheduler object to access.
 *
 * @returns The opaque pointer passed when creating the scheduler.
 */
void *avs_sched_data(avs_sched_t *sched);

/**
 * Retrieves the time at which the earliest currently scheduled job for the
 * specified scheduler is scheduled at. In other words, the time at which the
 * next call to @ref avs_sched_run is necessary.
 *
 * NOTE: Calling this function when any other thread is currently executing
 * @ref avs_sched_run results in undefined behaviour.
 *
 * @param sched Scheduler object to access.
 *
 * @returns Point in time in the system monotonic clock's domain, at which the
 *          earliest scheduled job is to be executed at. If there are no
 *          scheduled jobs, @ref AVS_TIME_MONOTONIC_INVALID is returned.
 *
 * NOTE: The returned time may be in the past, if the application did not run
 * @ref avs_sched_run on time.
 */
avs_time_monotonic_t avs_sched_time_of_next(avs_sched_t *sched);

/**
 * Retrieves the time remaining to the earliest currently scheduled job for the
 * specified scheduler. In other words, the time remaining until the next
 * necessary call to @ref avs_sched_run .
 *
 * NOTE: Calling this function when any other thread is currently executing
 * @ref avs_sched_run results in undefined behaviour.
 *
 * @param sched Scheduler object to access.
 *
 * @returns Time remaining to the earliest scheduled job. If there are no
 *          scheduled jobs, @ref AVS_TIME_DURATION_INVALID is returned.
 *
 * NOTE: The returned time will never be negative. If any scheduled jobs has
 * been missed, @ref AVS_TIME_DURATION_ZERO is returned instead.
 */
static inline avs_time_duration_t avs_sched_time_to_next(avs_sched_t *sched) {
    avs_time_duration_t result = avs_time_monotonic_diff(
            avs_sched_time_of_next(sched), avs_time_monotonic_now());
    return avs_time_duration_less(result, AVS_TIME_DURATION_ZERO)
            ? AVS_TIME_DURATION_ZERO : result;
}

/**
 * Waits until it is time to run a job (call @ref avs_sched_run) on the
 * specified scheduler.
 *
 * This is very similar to sleeping for the time returned by
 * @ref avs_sched_time_to_next . The difference is that in multi-threaded
 * applications, this call will take into account any manipulations on the
 * scheduler (adding and removing of jobs and descendant schedulers) done from
 * other threads. For example, if the function is called at 8:00 AM, the next
 * job is scheduled at 8:05 AM, but at 8:01 AM another thread schedules a job to
 * execute "now", this function will wake up and return at 8:01 AM.
 *
 * NOTE: The function currently only works if the scheduler module has been
 * compiled with thread safety enabled. Otherwise it will always return an error
 * immediately without any actual waiting.
 *
 * @param sched    Scheduler object to access.
 *
 * @param deadline If valid, specifies the latest point in time that this
 *                 function is allowed to return on. If there are no jobs
 *                 scheduled for before <c>deadline</c>, the function will
 *                 return at <c>deadline</c>. Using
 *                 @ref AVS_TIME_MONOTONIC_INVALID will result in a wait until
 *                 there actually is a scheduled job to execute, without any
 *                 other break conditions.
 *
 * @returns
 * - 0 when there is a scheduled job to execute.
 * - A positive value if @p deadline passes without any jobs to execute.
 * - A negative value in case of error when using synchronization primitives.
 */
int avs_sched_wait_until_next(avs_sched_t *sched,
                              avs_time_monotonic_t deadline);

/**
 * A variant of @ref avs_sched_wait_until_next that uses a relative timeout
 * instead of an absolute deadline.
 *
 * @param sched   Scheduler object to access.
 *
 * @param timeout If valid, specifies the longest duration of time that this
 *                function is allowed to execute for. If there are no jobs
 *                scheduled for before <c>timeout</c> elapses, the function will
 *                return. @ref AVS_TIME_DURATION_INVALID will result in a wait
 *                until there actually is a scheduled job to execute, without
 *                any other break conditions.
 *
 * @returns
 * - 0 when there is a scheduled job to execute.
 * - A positive value if @p deadline passes without any jobs to execute.
 * - A negative value in case of error when using synchronization primitives.
 */
static inline int avs_sched_wait_for_next(avs_sched_t *sched,
                                          avs_time_duration_t timeout) {
    return avs_sched_wait_until_next(
            sched,
            avs_time_monotonic_add(avs_time_monotonic_now(), timeout));
}

/**
 * Executes jobs scheduled for execution before or at the current point in time.
 *
 * Specifically, this function will execute any jobs scheduled for before or at
 * the time of entry to this function. If any of the executed jobs schedule more
 * jobs for "now", they will <em>not</em> be executed.
 *
 * @param sched Scheduler object to access.
 */
void avs_sched_run(avs_sched_t *sched);

/**
 * @name Internal functions
 *
 * These functions are not meant to be called directly.
 */
/**@{*/
typedef enum {
    AVS_SCHED_IMPL_RESCHEDULE_POLICY_ABORT,
    AVS_SCHED_IMPL_RESCHEDULE_POLICY_ERROR,
    AVS_SCHED_IMPL_RESCHEDULE_POLICY_REPLACE,
    AVS_SCHED_IMPL_RESCHEDULE_POLICY_IGNORE
} avs_sched_impl_reschedule_policy_t;

typedef struct {
    const char *log_file;
    unsigned log_line;
    const char *log_name;
    bool use_absolute_monotonic_time;
    avs_time_duration_t delay;
    avs_sched_impl_reschedule_policy_t reschedule_policy;
} avs_sched_impl_additional_args_t;

int avs_sched_impl__(avs_sched_t *sched,
                     avs_sched_handle_t *out_handle,
                     avs_sched_clb_t *clb,
                     const void *clb_data,
                     size_t clb_data_size,
                     avs_sched_impl_additional_args_t args);

#ifdef __cplusplus
#   define AVS_SCHED_INIT_FIELD__(Field) avs_sched_impl_result__.Field
#else // __cplusplus
#   define AVS_SCHED_INIT_FIELD__(Field) .Field
#endif // __cplusplus

#ifndef AVS_LOG_WITH_TRACE
#   define AVS_SCHED_LOG_ARGS__(...) \
        AVS_SCHED_INIT_FIELD__(log_file) = (NULL), \
        AVS_SCHED_INIT_FIELD__(log_line) = 0, \
        AVS_SCHED_INIT_FIELD__(log_name) = (NULL)
#elif !defined(AVS_SCHED_WITH_ARGS_LOG)
#   define AVS_SCHED_LOG_ARGS__(Clb, ClbArgs) \
        AVS_SCHED_INIT_FIELD__(log_file) = __FILE__, \
        AVS_SCHED_INIT_FIELD__(log_line) = __LINE__, \
        AVS_SCHED_INIT_FIELD__(log_name) = AVS_QUOTE(Clb)
#else // !defined(AVS_SCHED_WITH_ARGS_LOG)
#   define AVS_SCHED_LOG_ARGS__(Clb, ClbArgs) \
        AVS_SCHED_INIT_FIELD__(log_file) = __FILE__, \
        AVS_SCHED_INIT_FIELD__(log_line) = __LINE__, \
        AVS_SCHED_INIT_FIELD__(log_name) = AVS_QUOTE(Clb) AVS_QUOTE(ClbArgs)
#endif // AVS_LOG_WITH_TRACE // !defined(AVS_SCHED_WITH_ARGS_LOG)

#define AVS_SCHED_IMPL_ARG_NOW \
        /* AVS_SCHED_INIT_FIELD__(use_absolute_monotonic_time) = */ false, \
        AVS_SCHED_INIT_FIELD__(delay) = AVS_TIME_DURATION_ZERO

#define AVS_SCHED_IMPL_ARG_DELAYED(Delay) \
        /* AVS_SCHED_INIT_FIELD__(use_absolute_monotonic_time) = */ false, \
        AVS_SCHED_INIT_FIELD__(delay) = (Delay)

#define AVS_SCHED_IMPL_ARG_AT(Instant) \
        /* AVS_SCHED_INIT_FIELD__(use_absolute_monotonic_time) = */ true, \
        AVS_SCHED_INIT_FIELD__(delay) = (Instant).since_monotonic_epoch

#define AVS_SCHED_IMPL_ARG_RESCHEDULE_POLICY(Policy) \
        AVS_SCHED_INIT_FIELD__(reschedule_policy) = \
                AVS_SCHED_IMPL_RESCHEDULE_POLICY_ ## Policy

#define AVS_SCHED_IMPL_PREPROCESS_ARGS_1__(Arg) AVS_SCHED_IMPL_ARG_ ## Arg

#define AVS_SCHED_IMPL_PREPROCESS_ARGS_2__(Arg1, Arg2) \
        AVS_SCHED_IMPL_PREPROCESS_ARGS_1__(Arg1), \
        AVS_SCHED_IMPL_PREPROCESS_ARGS_1__(Arg2)

// no more than 2 arguments are supported or necessary for now

#define AVS_SCHED_IMPL_PREPROCESS_ARGS__(...) \
        AVS_CONCAT(AVS_SCHED_IMPL_PREPROCESS_ARGS_, \
                   AVS_VARARG_LENGTH(__VA_ARGS__), __)(__VA_ARGS__)

#ifdef __cplusplus
#   define AVS_SCHED_IMPL_ADDITIONAL_ARGS__(Clb, ClbArgs, ...) \
        [&]() { \
            avs_sched_impl_additional_args_t avs_sched_impl_result__{}; \
            AVS_SCHED_LOG_ARGS__(Clb, ClbArgs); \
            avs_sched_impl_result__.use_absolute_monotonic_time = \
                    AVS_SCHED_IMPL_PREPROCESS_ARGS__(__VA_ARGS__); \
            return avs_sched_impl_result__; \
        }()
#else // __cplusplus
#   define AVS_SCHED_IMPL_ADDITIONAL_ARGS__(Clb, ClbArgs, ...) \
        (const avs_sched_impl_additional_args_t) { \
            AVS_SCHED_LOG_ARGS__(Clb, ClbArgs), \
            .use_absolute_monotonic_time = \
                    AVS_SCHED_IMPL_PREPROCESS_ARGS__(__VA_ARGS__) \
        }
#endif // __cplusplus
/*@}*/

/**
 * Schedules a job.
 *
 * @param[in]  Sched       Scheduler object to access (<c>avs_sched_t *</c>).
 *
 * @param[out] OutHandle   If not <c>NULL</c>, pointer to a variable that will
 *                         be set to a handle to the scheduled job
 *                         (<c>avs_sched_handle_t *</c>). See the note below for
 *                         more information.
 *
 * @param[in]  Clb         Function to call when executing the job
 *                         (<c>avs_sched_clb_t *</c>).
 *
 * @param[in]  ClbData     Pointer to data that will be passed to @p Clb
 *                         (<c>const void *</c>). The data will be copied and
 *                         stored inside the job structure.
 *
 * @param[in]  ClbDataSize Number of bytes at @p ClbData that will be stored in
 *                         the job structure (<c>size_t</c>).
 *
 * @param[in]  ...         One or more attributes. Currently supported are:
 *                         - (mandatory, MUST be the first attribute) Scheduled
 *                           job time. One of:
 *                           - <c>NOW</c> - execute "now" (at earliest possible
 *                             time)
 *                           - <c>DELAYED(&lt;avs_time_duration_t delay&gt;)</c> -
 *                             execute after a specified duration of time
 *                             relative to "now"
 *                           - <c>AT(&lt;avs_time_monotonic_t instant&gt;)</c> -
 *                             execute at a specific point in time in the system
 *                             monotonic clock's domain
 *
 *                         - Reschedule policy. Decides how to proceed when
 *                           <c>*OutHandle</c> is not <c>NULL</c>. One of:
 *                           - <c>RESCHEDULE_POLICY(ABORT)</c> (default) - if
 *                             <c>avs_commons</c> have been compiled in debug
 *                             mode, abort execution. Otherwise, identical to
 *                             the <c>ERROR</c> policy.
 *                           - <c>RESCHEDULE_POLICY(ERROR)</c> - do not schedule
 *                             any new jobs and return an error.
 *                           - <c>RESCHEDULE_POLICY(REPLACE)</c> - unschedule
 *                             the previously scheduled job and schedule new
 *                             one.
 *                           - <c>RESCHEDULE_POLICY(IGNORE)</c> - do not
 *                             schedule any new jobs and return success.
 *
 * If <c>AVS_LOG_WITH_TRACE</c> is defined at time of inclusion of this header,
 * this macro also implicitly passes the filename and line number of the source
 * code where it is called, as well as a stringified value of the @p Clb
 * argument. They might be displayed in scheduler's log messages. If
 * <c>AVS_SCHED_WITH_ARGS_LOG</c> is defined as well, the stringified values of
 * <c>ClbData</c> and <c>ClbDataSize</c> are passed as well.
 *
 * The following pseudo-code illustrates the way @p Clb is called:
 *
 * <code>
 * char buf[...]; // a buffer with alignment sufficient for any known data type
 * size_t buf_size;
 *
 * // at schedule time:
 * memcpy(buf, ClbData, ClbDataSize);
 * buf_size = ClbDataSize;
 *
 * // at execution time:
 * Clb(&buf[0]);
 * </code>
 *
 * NOTE: @p OutHandle is an optional parameter where job handle will be stored
 * during the time it remains a scheduled job. When the job is fetched for
 * execution, the scheduler sets <c>*OutHandle</c> to <c>NULL</c>, indicating
 * that it is no longer a valid job handle. Therefore, one has to carefully
 * manage @p OutHandle lifetime or otherwise the behaviour will be undefined.
 *
 * @returns
 * - 0 on success
 * - negative value on one of the following failure conditions:
 *   - @p Clb is <c>NULL</c>
 *   - specified time for job execution is an invalid time value
 *   - not enough memory available
 */
#define AVS_SCHED(Sched, OutHandle, Clb, ClbData, ClbDataSize, ...) \
        avs_sched_impl__( \
                (Sched), (OutHandle), (Clb), (ClbData), (ClbDataSize), \
                AVS_SCHED_IMPL_ADDITIONAL_ARGS__(Clb, (ClbData, ClbDataSize), \
                                                 __VA_ARGS__))

#define AVS_SCHED_AT(Sched, OutHandle, Instant, Clb, ClbData, ClbDataSize) \
        AVS_SCHED(Sched, OutHandle, Clb, ClbData, ClbDataSize, AT(Instant))

#define AVS_SCHED_DELAYED(Sched, OutHandle, Delay, Clb, ClbData, ClbDataSize) \
        AVS_SCHED(Sched, OutHandle, Clb, ClbData, ClbDataSize, DELAYED(Delay))

#define AVS_SCHED_NOW(Sched, OutHandle, Clb, ClbData, ClbDataSize) \
        AVS_SCHED(Sched, OutHandle, Clb, ClbData, ClbDataSize, NOW)

/**
 * Returns a point in time at which execution of a specified job is scheduled.
 *
 * @param handle_ptr Pointer to a job handle variable (as passed earlier as
 *                   <c>OutHandle</c> to @ref AVS_SCHED_AT,
 *                   @ref AVS_SCHED_DELAYED or @ref AVS_SCHED_NOW) to check the
 *                   scheduled time of.
 *
 * @returns
 * - Point in time in system's monotonic clock domain at which the job referred
 *   to by @p handle_ptr is scheduled to be executed, if it refers to a valid
 *   job waiting for execution.
 * - @ref AVS_TIME_MONOTONIC_INVALID if either <c>handle_ptr</c> or
 *   <c>*handle_ptr</c> is <c>NULL</c>.
 */
avs_time_monotonic_t avs_sched_time(avs_sched_handle_t *handle_ptr);

/**
 * Unschedules a job.
 *
 * @param handle_ptr Pointer to a job handle variable (as passed earlier as
 *                   <c>OutHandle</c> to @ref AVS_SCHED_AT,
 *                   @ref AVS_SCHED_DELAYED or @ref AVS_SCHED_NOW) to check the
 *                   scheduled time of.
 *
 * NOTE: On return from this function, <c>*handle_ptr</c> will be set to
 * <c>NULL</c>.
 */
void avs_sched_del(avs_sched_handle_t *handle_ptr);

/**
 * Detaches a handle variable from a scheduled job.
 *
 * The job will still be scheduled for execution, but it will not be possible to
 * refer to it by its handle any more.
 *
 * @param handle_ptr Pointer to a job handle variable (as passed earlier as
 *                   <c>OutHandle</c> to @ref AVS_SCHED_AT,
 *                   @ref AVS_SCHED_DELAYED or @ref AVS_SCHED_NOW) to check the
 *                   scheduled time of.
 *
 * NOTE: On return from this function, <c>*handle_ptr</c> will be set to
 * <c>NULL</c>.
 */
void avs_sched_detach(avs_sched_handle_t *handle_ptr);

/**
 * Moves all the jobs scheduled on a given scheduler by a specified amount of
 * time.
 *
 * The intended use case for this function is to compensate for a drift between
 * wall time and the system monotonic clock when there is a need to take that
 * difference into account - e.g. when rescheduling jobs semantically dependent
 * on wall time after a system clock reset or wakeup from some kind of
 * power-saving feature.
 *
 * @param sched Scheduler object to access (<c>avs_sched_t *</c>).
 *
 * @param diff  Amount of time to move the jobs by.
 *
 * @returns
 * - 0 on success
 * - negative value if @p diff is not a valid time value
 */
int avs_sched_leap_time(avs_sched_t *sched, avs_time_duration_t diff);

#ifdef	__cplusplus
}
#endif

#endif	/* AVS_COMMONS_SCHED_H */
