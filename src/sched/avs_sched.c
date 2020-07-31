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

#include <avs_commons_init.h>

#ifdef AVS_COMMONS_WITH_AVS_SCHED

#    include <assert.h>
#    include <inttypes.h>
#    include <stdio.h>
#    include <string.h>

#    include <avsystem/commons/avs_list.h>
#    include <avsystem/commons/avs_sched.h>
#    include <avsystem/commons/avs_utils.h>

#    ifdef AVS_COMMONS_SCHED_THREAD_SAFE
#        include <avsystem/commons/avs_condvar.h>
#        include <avsystem/commons/avs_init_once.h>
#        include <avsystem/commons/avs_mutex.h>
#    else // AVS_COMMONS_SCHED_THREAD_SAFE
#        define avs_condvar_create(...) 0
#        define avs_condvar_cleanup(...) ((void) 0)
#        define avs_condvar_notify_all(...) ((void) 0)
#        define avs_mutex_create(...) 0
#        define avs_mutex_cleanup(...) ((void) 0)
#        define avs_mutex_unlock(...) ((void) 0)
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE

#    define MODULE_NAME avs_sched
#    include <avs_x_log_config.h>

VISIBILITY_SOURCE_BEGIN

struct avs_sched_job_struct {
    /** The scheduler for which the job is scheduled. */
    avs_sched_t *sched;

    /** Pointer to a handle which may be used to manage the job. */
    avs_sched_handle_t *handle_ptr;

    /** Instant in time at which the job is scheduled. */
    avs_time_monotonic_t instant;

#    ifdef AVS_COMMONS_WITH_INTERNAL_LOGS
    struct {
        /** File from which AVS_SCHED*() was called. */
        const char *file;
        /** Line from which AVS_SCHED*() was called. */
        unsigned line;
        /** Stringified value of what was passed as the callback function. */
        const char *name;
    } log_info;
#    endif // AVS_COMMONS_WITH_INTERNAL_LOGS

    /** Callback function to execute. */
    avs_sched_clb_t *clb;

    /** Data to pass to the callback function. Note that the size of this data
     * is not stored anywhere in the structure. */
    avs_max_align_t clb_data[];
};

struct avs_sched_struct {
#    ifdef AVS_COMMONS_WITH_INTERNAL_LOGS
    /** Name of the scheduler. */
    const char *name;
#    endif // AVS_COMMONS_WITH_INTERNAL_LOGS

    /** Opaque data, retrievable using @ref avs_sched_data . */
    void *data;

#    ifdef AVS_COMMONS_SCHED_THREAD_SAFE
    /**
     * Mutex that guards access to the jobs list.
     */
    avs_mutex_t *mutex;

    /**
     * Condition variable that can be used to wake up the
     * @ref avs_sched_wait_until_next call.
     */
    avs_condvar_t *task_condvar;
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE

    /** Scheduled jobs. */
    AVS_LIST(avs_sched_job_t) jobs;

    /**
     * A flag that prevents scheduling new jobs while the scheduler is shutting
     * down.
     */
    bool shutting_down;
};

#    ifdef AVS_COMMONS_SCHED_THREAD_SAFE
/**
 * The global mutex that guards accesses to all @ref avs_sched_handle_t
 * variables.
 *
 * That could be guarded by the normal per-scheduler mutexes, but that would
 * require passing the scheduler to functions such as @ref avs_sched_del .
 */
static avs_mutex_t *g_handle_access_mutex;
static volatile avs_init_once_handle_t g_init_handle;

static int init_globals(void *dummy) {
    (void) dummy;
    return avs_mutex_create(&g_handle_access_mutex);
}

static void nonfailing_mutex_lock(avs_mutex_t *mutex) {
    if (avs_mutex_lock(mutex)) {
        AVS_UNREACHABLE("could not lock mutex");
    }
}
#    else // AVS_COMMONS_SCHED_THREAD_SAFE
#        define nonfailing_mutex_lock(...) ((void) 0)
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE

void _avs_sched_cleanup_global_state(void);
void _avs_sched_cleanup_global_state(void) {
#    ifdef AVS_COMMONS_SCHED_THREAD_SAFE
    avs_mutex_cleanup(&g_handle_access_mutex);
    g_init_handle = NULL;
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE
}

#    define SCHED_LOG(Sched, Level, ...)                          \
        LOG(Level, "Scheduler \"%s\": " AVS_VARARG0(__VA_ARGS__), \
            (Sched)->name AVS_VARARG_REST(__VA_ARGS__))

#    ifdef AVS_COMMONS_WITH_INTERNAL_LOGS

#        define JOB_LOG_ID_MAX_LENGTH (AVS_COMMONS_LOG_MAX_LINE_LENGTH / 2)

static const char *job_log_id_impl(char buf[static JOB_LOG_ID_MAX_LENGTH],
                                   const char *file,
                                   unsigned line,
                                   const char *name) {
    char *ptr = buf;
    char *limit = buf + JOB_LOG_ID_MAX_LENGTH;
    if (name) {
        int result = avs_simple_snprintf(ptr, (size_t) (limit - ptr), " \"%s\"",
                                         name);
        if (result < 0) {
            return buf;
        } else {
            ptr += result;
        }
    }
    if (file && limit - ptr >= (ptrdiff_t) sizeof(" ()")) {
        size_t snprintf_size = (size_t) (limit - ptr - 1);
        int result = snprintf(ptr, snprintf_size, " (%s:%u", file, line);
        if (result < 0) {
            return buf;
        } else if ((size_t) result >= snprintf_size) {
            ptr = limit - 2;
        } else {
            ptr += result;
        }
        *ptr++ = ')';
        *ptr = '\0';
    }
    return buf;
}

#        define JOB_LOG_ID_EXPLICIT(File, Line, Name)                        \
            job_log_id_impl(&(char[JOB_LOG_ID_MAX_LENGTH]){ "" }[0], (File), \
                            (Line), (Name))

#        define JOB_LOG_ID(Job)                                             \
            JOB_LOG_ID_EXPLICIT((Job)->log_info.file, (Job)->log_info.line, \
                                (Job)->log_info.name)

#    endif // AVS_COMMONS_WITH_INTERNAL_LOGS

avs_sched_t *avs_sched_new(const char *name, void *data) {
#    ifdef AVS_COMMONS_SCHED_THREAD_SAFE
    if (avs_init_once(&g_init_handle, init_globals, NULL)) {
        LOG(ERROR, _("Could not initialize globals"));
        return NULL;
    }
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE
    (void) name;
    avs_sched_t *sched = (avs_sched_t *) avs_calloc(1, sizeof(avs_sched_t));
    if (!sched) {
        LOG(ERROR, _("Out of memory"));
        return NULL;
    }
    if (avs_mutex_create(&sched->mutex)) {
        LOG(ERROR, _("Could not create mutex"));
        avs_free(sched);
        return NULL;
    }
    if (avs_condvar_create(&sched->task_condvar)) {
        LOG(ERROR,
            _("Could not create condition variable for task notification"));
        avs_mutex_cleanup(&sched->mutex);
        avs_free(sched);
        return NULL;
    }
    sched->data = data;
    LOG(DEBUG, _("Scheduler \"") "%s" _("\" created, data == ") "%p",
        (sched->name = (name ? name : "(unknown)")), data);
    return sched;
}

void avs_sched_cleanup(avs_sched_t **sched_ptr) {
    if (!sched_ptr || !*sched_ptr) {
        return;
    }

    SCHED_LOG(*sched_ptr, DEBUG, _("shutting down"));
    (*sched_ptr)->shutting_down = true;

    // execute any tasks remaining for now
    avs_sched_run(*sched_ptr);

    nonfailing_mutex_lock(g_handle_access_mutex);
    AVS_LIST_CLEAR(&(*sched_ptr)->jobs) {
        if ((*sched_ptr)->jobs->handle_ptr) {
            *(*sched_ptr)->jobs->handle_ptr = NULL;
        }
    }
    avs_mutex_unlock(g_handle_access_mutex);

    avs_condvar_cleanup(&(*sched_ptr)->task_condvar);
    avs_mutex_cleanup(&(*sched_ptr)->mutex);

    SCHED_LOG(*sched_ptr, DEBUG, _("shut down"));
    avs_free(*sched_ptr);
    *sched_ptr = NULL;
}

void *avs_sched_data(avs_sched_t *sched) {
    assert(sched);
    return sched->data;
}

static avs_time_monotonic_t sched_time_of_next_locked(avs_sched_t *sched) {
    assert(sched);
    if (sched->jobs) {
        return sched->jobs->instant;
    }
    return AVS_TIME_MONOTONIC_INVALID;
}

avs_time_monotonic_t avs_sched_time_of_next(avs_sched_t *sched) {
    assert(sched);
    nonfailing_mutex_lock(sched->mutex);
    avs_time_monotonic_t result = sched_time_of_next_locked(sched);
    avs_mutex_unlock(sched->mutex);
    return result;
}

int avs_sched_wait_until_next(avs_sched_t *sched,
                              avs_time_monotonic_t deadline) {
#    ifdef AVS_COMMONS_SCHED_THREAD_SAFE
    nonfailing_mutex_lock(sched->mutex);
    avs_time_monotonic_t time_of_next;
    int result = -1;
    do {
        time_of_next = sched_time_of_next_locked(sched);
        avs_time_monotonic_t local_deadline = deadline;
        if (avs_time_monotonic_valid(time_of_next)
                && !avs_time_monotonic_before(deadline, time_of_next)) {
            local_deadline = time_of_next;
        }
        result = avs_condvar_wait(sched->task_condvar, sched->mutex,
                                  local_deadline);
    } while (!result);
    if (result < 0) {
        SCHED_LOG(sched, ERROR, _("could not wait on condition variable"));
    } else {
        time_of_next = sched_time_of_next_locked(sched);
        result = ((avs_time_monotonic_valid(time_of_next)
                   && !avs_time_monotonic_before(avs_time_monotonic_now(),
                                                 time_of_next))
                          ? 0
                          : AVS_CONDVAR_TIMEOUT);
    }
    avs_mutex_unlock(sched->mutex);
    return result;
#    else  // AVS_COMMONS_SCHED_THREAD_SAFE
    (void) deadline;
    (void) sched;
    SCHED_LOG(
            sched, ERROR,
            _("avs_sched_wait_until_next() is not supported because avs_sched ")
                    _("was compiled with thread safety disabled"));
    return -1;
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE
}

static AVS_LIST(avs_sched_job_t) fetch_job(avs_sched_t *sched,
                                           avs_time_monotonic_t deadline) {
    AVS_LIST(avs_sched_job_t) result = NULL;
    nonfailing_mutex_lock(sched->mutex);
    if (sched->jobs
            && avs_time_monotonic_before(sched->jobs->instant, deadline)) {
        if (sched->jobs->handle_ptr) {
            nonfailing_mutex_lock(g_handle_access_mutex);
            assert(*sched->jobs->handle_ptr == sched->jobs);
            *sched->jobs->handle_ptr = NULL;
            avs_mutex_unlock(g_handle_access_mutex);
            sched->jobs->handle_ptr = NULL;
        }
        result = AVS_LIST_DETACH(&sched->jobs);
    }
    avs_mutex_unlock(sched->mutex);
    return result;
}

static void execute_job(avs_sched_t *sched, AVS_LIST(avs_sched_job_t) job) {
    // make sure that the task is detached
    assert(!AVS_LIST_NEXT(job));

    SCHED_LOG(sched, TRACE, _("executing job") "%s", JOB_LOG_ID(job));

    job->clb(sched, job->clb_data);
    AVS_LIST_DELETE(&job);
}

void avs_sched_run(avs_sched_t *sched) {
    assert(sched);
    avs_time_monotonic_t now = avs_time_monotonic_now();

    uint32_t tasks_executed = 0;
    AVS_LIST(avs_sched_job_t) job = NULL;
    while ((job = fetch_job(sched, now))) {
        assert(job->sched == sched);
        execute_job(sched, job);
        ++tasks_executed;
    }

    SCHED_LOG(sched, TRACE, "%" PRIu32 _(" jobs executed"), tasks_executed);

#    ifdef AVS_COMMONS_WITH_INTERNAL_TRACE
    avs_time_monotonic_t next = avs_sched_time_of_next(sched);
    avs_time_duration_t remaining = avs_time_monotonic_diff(next, now);
    if (!avs_time_duration_valid(remaining)) {
        SCHED_LOG(sched, TRACE, _("no more jobs"));
    } else {
        SCHED_LOG(sched, TRACE,
                  _("next job scheduled at ") "%s" _(" (+") "%s" _(")"),
                  AVS_TIME_DURATION_AS_STRING(next.since_monotonic_epoch),
                  AVS_TIME_DURATION_AS_STRING(remaining));
    }
#    endif // AVS_COMMONS_WITH_INTERNAL_TRACE
}

static void schedule_job(avs_sched_t *sched, avs_sched_job_t *job) {
    AVS_LIST(avs_sched_job_t) *insert_ptr = &sched->jobs;
    while (*insert_ptr
           && !avs_time_monotonic_before(job->instant,
                                         (*insert_ptr)->instant)) {
        AVS_LIST_ADVANCE_PTR(&insert_ptr);
    }
    AVS_LIST_INSERT(insert_ptr, job);
}

static int sched_at_locked(avs_sched_t *sched,
                           avs_sched_handle_t *out_handle,
                           avs_time_monotonic_t instant,
                           const char *log_file,
                           unsigned log_line,
                           const char *log_name,
                           avs_sched_clb_t *clb,
                           const void *clb_data,
                           size_t clb_data_size) {
    (void) log_file;
    (void) log_line;
    (void) log_name;
    assert(sched);
    assert(clb);
    assert(avs_time_monotonic_valid(instant));
    if (sched->shutting_down) {
        SCHED_LOG(sched, ERROR,
                  _("scheduler already shut down when attempting ")
                          _("to schedule") "%s",
                  JOB_LOG_ID_EXPLICIT(log_file, log_line, log_name));
        return -1;
    }

    AVS_LIST(avs_sched_job_t) job = (avs_sched_job_t *) AVS_LIST_NEW_BUFFER(
            sizeof(avs_sched_job_t) + clb_data_size);
    if (!job) {
        SCHED_LOG(sched, ERROR, _("could not allocate scheduler task"));
        return -1;
    }

    job->sched = sched;
    job->instant = instant;
#    ifdef AVS_COMMONS_WITH_INTERNAL_LOGS
    job->log_info.file = log_file;
    job->log_info.line = log_line;
    job->log_info.name = log_name;
#    endif // AVS_COMMONS_WITH_INTERNAL_LOGS
    job->clb = clb;
    if (clb_data_size) {
        memcpy(job->clb_data, clb_data, clb_data_size);
    }

    if (out_handle) {
        job->handle_ptr = out_handle;
        nonfailing_mutex_lock(g_handle_access_mutex);
        if (*out_handle) {
            AVS_ASSERT((*out_handle)->sched == sched,
                       "Replacing handles used by a different scheduler is "
                       "not supported");
            AVS_LIST(avs_sched_job_t) *job_ptr =
                    (AVS_LIST(avs_sched_job_t) *) AVS_LIST_FIND_PTR(
                            &sched->jobs, *out_handle);
            AVS_ASSERT(job_ptr, "dangling handle detected");
            SCHED_LOG(sched, TRACE,
                      _("cancelling job") "%s" _(
                              " due to reschedule policy for job") "%s",
                      JOB_LOG_ID(*job_ptr),
                      JOB_LOG_ID_EXPLICIT(log_file, log_line, log_name));
            AVS_LIST_DELETE(job_ptr);
        }
        *out_handle = job;
        avs_mutex_unlock(g_handle_access_mutex);
    }

    schedule_job(sched, job);
#    ifdef AVS_COMMONS_WITH_INTERNAL_TRACE
    avs_time_duration_t remaining =
            avs_time_monotonic_diff(instant, avs_time_monotonic_now());
    SCHED_LOG(sched, TRACE,
              _("scheduled job") "%s" _(" at ") "%s" _(" (+") "%s" _(")"),
              JOB_LOG_ID(job),
              AVS_TIME_DURATION_AS_STRING(instant.since_monotonic_epoch),
              AVS_TIME_DURATION_AS_STRING(remaining));
#    endif // AVS_COMMONS_WITH_INTERNAL_TRACE
    return 0;
}

int avs_sched_at_impl__(avs_sched_t *sched,
                        avs_sched_handle_t *out_handle,
                        avs_time_monotonic_t instant,
                        const char *log_file,
                        unsigned log_line,
                        const char *log_name,
                        avs_sched_clb_t *clb,
                        const void *clb_data,
                        size_t clb_data_size) {
    assert(sched);
    if (!clb) {
        SCHED_LOG(sched, ERROR,
                  _("attempted to schedule a null callback pointer") "%s",
                  JOB_LOG_ID_EXPLICIT(log_file, log_line, log_name));
        return -1;
    }
    if (!avs_time_monotonic_valid(instant)) {
        SCHED_LOG(sched, ERROR,
                  _("attempted to schedule job") "%s" _(
                          " at an invalid time point"),
                  JOB_LOG_ID_EXPLICIT(log_file, log_line, log_name));
        return -1;
    }

    int result = -1;
    nonfailing_mutex_lock(sched->mutex);
    if (!(result = sched_at_locked(sched, out_handle, instant, log_file,
                                   log_line, log_name, clb, clb_data,
                                   clb_data_size))) {
        avs_condvar_notify_all(sched->task_condvar);
    }
    avs_mutex_unlock(sched->mutex);
    return result;
}

avs_time_monotonic_t avs_sched_time(avs_sched_handle_t *handle_ptr) {
    avs_time_monotonic_t result = AVS_TIME_MONOTONIC_INVALID;
    nonfailing_mutex_lock(g_handle_access_mutex);
    if (handle_ptr && *handle_ptr) {
        result = (*handle_ptr)->instant;
    }
    avs_mutex_unlock(g_handle_access_mutex);
    return result;
}

void avs_sched_del(avs_sched_handle_t *handle_ptr) {
    if (!handle_ptr) {
        return;
    }
    avs_sched_t *sched = NULL;
    avs_sched_job_t *job = NULL;
    nonfailing_mutex_lock(g_handle_access_mutex);
    if (*handle_ptr) {
        AVS_ASSERT(handle_ptr == (*handle_ptr)->handle_ptr,
                   "accessing job via non-original handle");
        job = *handle_ptr;
        sched = (*handle_ptr)->sched;
    }
    avs_mutex_unlock(g_handle_access_mutex);
    if (!job) {
        return;
    }

    assert(sched);
    nonfailing_mutex_lock(sched->mutex);
    AVS_LIST(avs_sched_job_t) *job_ptr =
            (AVS_LIST(avs_sched_job_t) *) AVS_LIST_FIND_PTR(&sched->jobs, job);
    if (!job_ptr) {
#    ifndef AVS_COMMONS_SCHED_THREAD_SAFE
        AVS_ASSERT(job_ptr, "dangling handle detected");
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE
           // Job might have been removed by another thread, don't do anything
    } else {
        SCHED_LOG(sched, TRACE, _("cancelling job") "%s", JOB_LOG_ID(job));
        nonfailing_mutex_lock(g_handle_access_mutex);
        assert(*job->handle_ptr == job);
        *job->handle_ptr = NULL;
        avs_mutex_unlock(g_handle_access_mutex);

        AVS_LIST_DELETE(job_ptr);
    }
    avs_mutex_unlock(sched->mutex);
}

void avs_sched_detach(avs_sched_handle_t *handle_ptr) {
    if (!handle_ptr) {
        return;
    }
    avs_sched_t *sched = NULL;
    avs_sched_job_t *job = NULL;
    nonfailing_mutex_lock(g_handle_access_mutex);
    if (*handle_ptr) {
        AVS_ASSERT(handle_ptr == (*handle_ptr)->handle_ptr,
                   "accessing job via non-original handle");
        job = *handle_ptr;
        sched = (*handle_ptr)->sched;
    }
    avs_mutex_unlock(g_handle_access_mutex);
    if (!job) {
        return;
    }

    assert(sched);
    nonfailing_mutex_lock(sched->mutex);
    AVS_LIST(avs_sched_job_t) *job_ptr =
            (AVS_LIST(avs_sched_job_t) *) AVS_LIST_FIND_PTR(&sched->jobs, job);
    if (!job_ptr) {
#    ifndef AVS_COMMONS_SCHED_THREAD_SAFE
        AVS_ASSERT(job_ptr, "dangling handle detected");
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE
           // Job might have been removed by another thread, don't do anything
    } else {
        nonfailing_mutex_lock(g_handle_access_mutex);
        assert(*job->handle_ptr == job);
        *job->handle_ptr = NULL;
        avs_mutex_unlock(g_handle_access_mutex);

        job->handle_ptr = NULL;
    }
    avs_mutex_unlock(sched->mutex);
}

int avs_sched_leap_time(avs_sched_t *sched, avs_time_duration_t diff) {
    if (avs_time_duration_valid(diff)) {
        SCHED_LOG(sched, ERROR,
                  _("attempted to leap an invalid amount of time"));
        return -1;
    }
    assert(sched);
    nonfailing_mutex_lock(sched->mutex);

    SCHED_LOG(sched, INFO, _("moving all jobs by ") "%s" _(" s"),
              AVS_TIME_DURATION_AS_STRING(diff));

    AVS_LIST(avs_sched_job_t) job;
    AVS_LIST_FOREACH(job, sched->jobs) {
        job->instant = avs_time_monotonic_add(job->instant, diff);
    }
    avs_condvar_notify_all(sched->task_condvar);

    avs_mutex_unlock(sched->mutex);
    return 0;
}

int avs_resched_at_impl__(avs_sched_handle_t *handle_ptr,
                          avs_time_monotonic_t instant) {
    if (!handle_ptr) {
        return -1;
    }
    if (!avs_time_monotonic_valid(instant)) {
        LOG(ERROR, _("attempted to reschedule job at an invalid time point"));
        return -1;
    }

    avs_sched_t *sched = NULL;
    avs_sched_job_t *job = NULL;
    nonfailing_mutex_lock(g_handle_access_mutex);
    if (*handle_ptr) {
        AVS_ASSERT(handle_ptr == (*handle_ptr)->handle_ptr,
                   "accessing job via non-original handle");
        sched = (*handle_ptr)->sched;
        job = *handle_ptr;
    }
    avs_mutex_unlock(g_handle_access_mutex);
    if (!job) {
        return -1;
    }

    int retval = 0;
    assert(sched);
    nonfailing_mutex_lock(sched->mutex);
    AVS_LIST(avs_sched_job_t) *job_ptr =
            (AVS_LIST(avs_sched_job_t) *) AVS_LIST_FIND_PTR(&sched->jobs, job);
    if (job_ptr) {
        SCHED_LOG(sched, TRACE, _("rescheduling job") "%s",
                  JOB_LOG_ID(*job_ptr));

        avs_sched_job_t *detached_job = AVS_LIST_DETACH(job_ptr);
        detached_job->instant = instant;

        schedule_job(sched, detached_job);
        avs_condvar_notify_all(sched->task_condvar);
    } else {
#    ifndef AVS_COMMONS_SCHED_THREAD_SAFE
        AVS_ASSERT(job_ptr, "dangling handle detected");
#    endif // AVS_COMMONS_SCHED_THREAD_SAFE
        retval = -1;
    }

    avs_mutex_unlock(sched->mutex);
    return retval;
}

#endif // AVS_COMMONS_WITH_AVS_SCHED
