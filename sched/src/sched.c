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

#include <avs_commons_config.h>

#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include <avsystem/commons/list.h>
#include <avsystem/commons/sched.h>
#include <avsystem/commons/utils.h>

#ifdef WITH_SCHEDULER_THREAD_SAFE
#   include <avsystem/commons/condvar.h>
#   include <avsystem/commons/init_once.h>
#   include <avsystem/commons/mutex.h>
#else // WITH_SCHEDULER_THREAD_SAFE
#   define avs_condvar_create(...) 0
#   define avs_condvar_cleanup(...) ((void) 0)
#   define avs_condvar_notify_all(...) ((void) 0)
#   define avs_mutex_create(...) 0
#   define avs_mutex_cleanup(...) ((void) 0)
#   define avs_mutex_lock(...) 0
#   define avs_mutex_unlock(...) ((void) 0)
#endif // WITH_SCHEDULER_THREAD_SAFE

#define MODULE_NAME avs_sched
#include <x_log_config.h>

VISIBILITY_SOURCE_BEGIN

struct avs_sched_job_struct {
    avs_sched_t *sched;
    avs_sched_handle_t *handle_ptr;
    avs_time_monotonic_t instant;
#ifdef WITH_INTERNAL_LOGS
    struct {
        const char *file;
        unsigned line;
        const char *name;
    } log_info;
#endif // WITH_INTERNAL_LOGS
    avs_sched_clb_t *clb;
    avs_max_align_t clb_data[];
};

struct avs_sched_struct {
#ifdef WITH_INTERNAL_LOGS
    const char *name;
#endif // WITH_INTERNAL_LOGS
    void *data;
#ifdef WITH_SCHEDULER_THREAD_SAFE
    avs_mutex_t *mutex;
    avs_condvar_t *task_condvar;
    AVS_LIST(avs_condvar_t *) ancestor_task_condvars;
#endif // WITH_SCHEDULER_THREAD_SAFE
    AVS_LIST(avs_sched_job_t) jobs;
    AVS_LIST(avs_sched_t *) children;
    AVS_LIST(avs_sched_t *) children_executed;
    bool shut_down;
};

#ifdef WITH_SCHEDULER_THREAD_SAFE
static volatile avs_init_once_handle_t g_init_handle;
static avs_mutex_t *g_handle_access_mutex;
#endif // WITH_SCHEDULER_THREAD_SAFE

#define SCHED_LOG(Sched, Level, ...) \
        LOG(Level, "Scheduler \"%s\": " AVS_VARARG0(__VA_ARGS__), \
            (Sched)->name AVS_VARARG_REST(__VA_ARGS__))

static int handle_ptr_exchange_value(avs_sched_handle_t *handle_ptr,
                                     avs_sched_job_t **out_previous_value,
                                     avs_sched_job_t *new_value) {
    if (avs_mutex_lock(g_handle_access_mutex)) {
        LOG(ERROR, "could not lock handle access mutex");
        return -1;
    }
    if (out_previous_value) {
        *out_previous_value = *handle_ptr;
    }
    *handle_ptr = new_value;
    avs_mutex_unlock(g_handle_access_mutex);
    return 0;
}

static int handle_ptr_access(avs_sched_handle_t *handle_ptr,
                             void (*access_clb)(avs_sched_job_t *, void *),
                             void *access_clb_arg) {
    if (avs_mutex_lock(g_handle_access_mutex)) {
        LOG(ERROR, "could not lock handle access mutex");
        return -1;
    }
    access_clb(*handle_ptr, access_clb_arg);
    avs_mutex_unlock(g_handle_access_mutex);
    return 0;
}

#ifdef WITH_INTERNAL_LOGS

#   define JOB_LOG_ID_MAX_LENGTH (AVS_LOG_MAX_LINE_LENGTH / 2)

static const char *
job_log_id_impl(char buf[static JOB_LOG_ID_MAX_LENGTH],
                const char *file,
                unsigned line,
                const char *name) {
    char *ptr = buf;
    char *limit = buf + JOB_LOG_ID_MAX_LENGTH;
    if (name) {
        int result = avs_simple_snprintf(ptr, (size_t) (limit - ptr),
                                         " \"%s\"", name);
        if (result < 0) {
            goto finish;
        } else {
            ptr += result;
        }
    }
    if (file && limit - ptr >= 4) {
        int result = avs_simple_snprintf(ptr, (size_t) (limit - ptr - 1),
                                         " (%s:%u", file, line);
        if (result < 0) {
            ptr = limit - 2;
        } else {
            ptr += result;
        }
        *ptr++ = ')';
        *ptr = '\0';
    }
finish:
    return buf;
}

#   define JOB_LOG_ID_EXPLICIT(File, Line, Name) \
        job_log_id_impl(&(char[JOB_LOG_ID_MAX_LENGTH]) { "" }[0], \
                        (File), (Line), (Name))

#   define JOB_LOG_ID(Job) \
        JOB_LOG_ID_EXPLICIT((Job)->log_info.file, (Job)->log_info.line, \
                            (Job)->log_info.name)

#   define TIME_STR_MAX_LENGTH 32

static const char *time_str_impl(char buf[static TIME_STR_MAX_LENGTH],
                                 avs_time_duration_t time) {
    if (avs_time_duration_valid(time)) {
        if (time.seconds < 0 && time.nanoseconds > 0) {
            ++time.seconds;
            time.nanoseconds = 1000000000 - time.nanoseconds;
        }
        avs_simple_snprintf(buf, TIME_STR_MAX_LENGTH, "%" PRId64 ".%09" PRId32,
                            time.seconds, time.nanoseconds);
    } else {
        avs_simple_snprintf(buf, TIME_STR_MAX_LENGTH, "TIME_INVALID");
    }
    return buf;
}

#   define TIME_STR(Time) \
        time_str_impl(&(char[TIME_STR_MAX_LENGTH]) { "" }[0], (Time))

#endif // WITH_INTERNAL_LOGS

#ifdef WITH_SCHEDULER_THREAD_SAFE
static int init_globals(void *dummy) {
    (void) dummy;
    return avs_mutex_create(&g_handle_access_mutex);
}
#endif // WITH_SCHEDULER_THREAD_SAFE

avs_sched_t *avs_sched_new(const char *name, void *data) {
#ifdef WITH_SCHEDULER_THREAD_SAFE
    if (avs_init_once(&g_init_handle, init_globals, NULL)) {
        LOG(ERROR, "Could not initialize globals");
        return NULL;
    }
#endif // WITH_SCHEDULER_THREAD_SAFE
    (void) name;
    avs_sched_t *sched = (avs_sched_t *) avs_calloc(1, sizeof(avs_sched_t));
    if (!sched) {
        LOG(ERROR, "Out of memory");
        return NULL;
    }
    if (avs_mutex_create(&sched->mutex)) {
        LOG(ERROR, "Could not create mutex");
        avs_free(sched);
        return NULL;
    }
    if (avs_condvar_create(&sched->task_condvar)) {
        LOG(ERROR, "Could not create condition variable for task notification");
        avs_mutex_cleanup(&sched->mutex);
        avs_free(sched);
        return NULL;
    }
    sched->data = data;
    LOG(DEBUG, "Scheduler \"%s\" created, data == %p",
        (sched->name = (name ? name : "(unknown)")), data);
    return sched;
}

#ifdef WITH_SCHEDULER_THREAD_SAFE
static int remove_ancestor_condvar_locking(avs_sched_t *sched,
                                           avs_condvar_t *ancestor_condvar);

static void remove_ancestor_condvar_locked(avs_sched_t *sched,
                                           avs_condvar_t *ancestor_condvar) {
    assert(sched);
    AVS_LIST(avs_condvar_t *) *element_ptr;
    AVS_LIST_FOREACH_PTR(element_ptr, &sched->ancestor_task_condvars) {
        if (**element_ptr == ancestor_condvar) {
            AVS_LIST_DELETE(element_ptr);
            AVS_LIST(avs_sched_t *) child;
            AVS_LIST_FOREACH(child, sched->children) {
                remove_ancestor_condvar_locking(*child, ancestor_condvar);
            }
            break;
        }
    }
}

static int remove_ancestor_condvar_locking(avs_sched_t *sched,
                                           avs_condvar_t *ancestor_condvar) {
    if (avs_mutex_lock(sched->mutex)) {
        SCHED_LOG(sched, ERROR, "could not lock mutex");
        return -1;
    } else {
        remove_ancestor_condvar_locked(sched, ancestor_condvar);
        avs_mutex_unlock(sched->mutex);
        return 0;
    }
}
#else // WITH_SCHEDULER_THREAD_SAFE
#define remove_ancestor_condvar_locked(...) ((void) 0)
#define remove_ancestor_condvar_locking(...) ((void) 0)
#endif // WITH_SCHEDULER_THREAD_SAFE

void avs_sched_cleanup(avs_sched_t **sched_ptr) {
    if (!sched_ptr || !*sched_ptr) {
        return;
    }

    SCHED_LOG(*sched_ptr, DEBUG, "shutting down");
    (*sched_ptr)->shut_down = true;

    AVS_ASSERT(!(*sched_ptr)->children_executed,
               "Attempting to clean up scheduler that is being run");
    AVS_LIST_CLEAR(&(*sched_ptr)->children) {
        remove_ancestor_condvar_locking(*(*sched_ptr)->children,
                                        (*sched_ptr)->task_condvar);
    }

    // execute any tasks remaining for now
    avs_sched_run(*sched_ptr);

    int mutex_lock_result = avs_mutex_lock(g_handle_access_mutex);
    AVS_LIST_CLEAR(&(*sched_ptr)->jobs) {
        if ((*sched_ptr)->jobs->handle_ptr) {
            *(*sched_ptr)->jobs->handle_ptr = NULL;
        }
    }
    if (!mutex_lock_result) {
        avs_mutex_unlock(g_handle_access_mutex);
    }

    avs_condvar_cleanup(&(*sched_ptr)->task_condvar);
    avs_mutex_cleanup(&(*sched_ptr)->mutex);

    SCHED_LOG(*sched_ptr, DEBUG, "shut down");
    avs_free(*sched_ptr);
    *sched_ptr = NULL;
}

void *avs_sched_data(avs_sched_t *sched) {
    assert(sched);
    return sched->data;
}

static avs_time_monotonic_t sched_time_of_next_locked(avs_sched_t *sched) {
    assert(sched);
    avs_time_monotonic_t result = AVS_TIME_MONOTONIC_INVALID;

    if (sched->jobs) {
        result = sched->jobs->instant;
    }

    AVS_ASSERT(!sched->children_executed,
               "Called avs_sched_time_of_next() "
               "while children schedulers are executed");

    AVS_LIST(avs_sched_t *) child;
    AVS_LIST_FOREACH(child, sched->children) {
        assert(*child);
        avs_time_monotonic_t child_result = avs_sched_time_of_next(*child);
        if (!avs_time_monotonic_valid(result)
                || avs_time_monotonic_before(child_result, result)) {
            result = child_result;
        }
    }

    return result;
}

avs_time_monotonic_t avs_sched_time_of_next(avs_sched_t *sched) {
    assert(sched);
    avs_time_monotonic_t result = AVS_TIME_MONOTONIC_INVALID;
    if (avs_mutex_lock(sched->mutex)) {
        SCHED_LOG(sched, ERROR, "could not lock mutex");
    } else {
        result = sched_time_of_next_locked(sched);
        avs_mutex_unlock(sched->mutex);
    }
    return result;
}

int avs_sched_wait_until_next(avs_sched_t *sched,
                              avs_time_monotonic_t deadline) {
    int result = -1;
    (void) deadline;
#ifdef WITH_SCHEDULER_THREAD_SAFE
    if (avs_mutex_lock(sched->mutex)) {
        SCHED_LOG(sched, ERROR, "could not lock mutex");
        return -1;
    }
    avs_time_monotonic_t time_of_next;
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
    if (result >= 0) {
        time_of_next = sched_time_of_next_locked(sched);
        result = ((avs_time_monotonic_valid(time_of_next)
                        && !avs_time_monotonic_before(avs_time_monotonic_now(),
                                                      time_of_next))
                ? 0 : AVS_CONDVAR_TIMEOUT);
    }
    avs_mutex_unlock(sched->mutex);
#endif // WITH_SCHEDULER_THREAD_SAFE
    if (result < 0) {
        SCHED_LOG(sched, ERROR, "could not wait on condition variable");
    }
    return result;
}

static AVS_LIST(avs_sched_job_t)
fetch_job_locked(avs_sched_t *sched, avs_time_monotonic_t deadline) {
    if (sched->jobs
            && avs_time_monotonic_before(sched->jobs->instant,
                                         deadline)) {
        if (sched->jobs->handle_ptr) {
            avs_sched_job_t *value;
            if (handle_ptr_exchange_value(sched->jobs->handle_ptr,
                                          &value, NULL)) {
                return NULL;
            }
            assert(value == sched->jobs);
            sched->jobs->handle_ptr = NULL;
        }
        return AVS_LIST_DETACH(&sched->jobs);
    }
    return NULL;
}

static AVS_LIST(avs_sched_job_t)
fetch_job_locking(avs_sched_t *sched, avs_time_monotonic_t deadline) {
    AVS_LIST(avs_sched_job_t) result = NULL;
    if (avs_mutex_lock(sched->mutex)) {
        SCHED_LOG(sched, ERROR, "could not lock mutex");
    } else {
        result = fetch_job_locked(sched, deadline);
        avs_mutex_unlock(sched->mutex);
    }
    return result;
}

static void execute_job(avs_sched_t *sched, AVS_LIST(avs_sched_job_t) job) {
    // make sure that the task is detached
    assert(!AVS_LIST_NEXT(job));

    SCHED_LOG(sched, TRACE, "executing job%s", JOB_LOG_ID(job));

    job->clb(sched, job->clb_data);
    AVS_LIST_DELETE(&job);
}

static avs_sched_t *fetch_child_locked(avs_sched_t *sched) {
    if (sched->children) {
        return *AVS_LIST_INSERT(&sched->children_executed,
                                AVS_LIST_DETACH(&sched->children));
    }
    return NULL;
}

static avs_sched_t *fetch_child_locking(avs_sched_t *sched) {
    avs_sched_t *result = NULL;
    if (avs_mutex_lock(sched->mutex)) {
        SCHED_LOG(sched, ERROR, "could not lock mutex");
    } else {
        result = fetch_child_locked(sched);
        avs_mutex_unlock(sched->mutex);
    }
    return result;
}

static void reorganize_children_locked(avs_sched_t *sched) {
    // fetch_child_*() loop reverses the order when moving from children
    // to children_executed, so reverse the order once again
    while (sched->children_executed) {
        AVS_LIST_INSERT(&sched->children,
                        AVS_LIST_DETACH(&sched->children_executed));
    }
}

static int reorganize_children_locking(avs_sched_t *sched) {
    if (avs_mutex_lock(sched->mutex)) {
        SCHED_LOG(sched, ERROR, "could not lock mutex");
        return -1;
    } else {
        reorganize_children_locked(sched);
        avs_mutex_unlock(sched->mutex);
        return 0;
    }
}

int avs_sched_run(avs_sched_t *sched) {
    int result = 0;
    assert(sched);
    avs_time_monotonic_t now = avs_time_monotonic_now();

    uint64_t tasks_executed = 0;
    AVS_LIST(avs_sched_job_t) job = NULL;
    while ((job = fetch_job_locking(sched, now))) {
        assert(job->sched == sched);
        execute_job(sched, job);
        ++tasks_executed;
    }

    if (tasks_executed) {
        SCHED_LOG(sched, TRACE, "%" PRIu64 " jobs executed", tasks_executed);
    } else {
        bool we_have_children = false;
        avs_sched_t *child = NULL;
        while ((child = fetch_child_locking(sched))) {
            if (!we_have_children) {
                we_have_children = true;
                SCHED_LOG(sched, TRACE, "no local jobs to execute, "
                                        "processing child schedulers");
            }
            avs_sched_run(child);
        }
        if (we_have_children) {
            result = reorganize_children_locking(sched);
        } else {
            SCHED_LOG(sched, TRACE, "no jobs to execute");
        }
    }

#ifdef WITH_INTERNAL_TRACE
    avs_time_monotonic_t next = avs_sched_time_of_next(sched);
    avs_time_duration_t remaining = avs_time_monotonic_diff(next, now);
    if (!avs_time_duration_valid(remaining)) {
        SCHED_LOG(sched, TRACE, "no more jobs");
    } else {
        SCHED_LOG(sched, TRACE, "next job scheduled at %s (+%s)",
                  TIME_STR(next.since_monotonic_epoch), TIME_STR(remaining));
    }
#endif // WITH_INTERNAL_TRACE
    return result;
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
    if (sched->shut_down) {
        SCHED_LOG(sched, ERROR, "scheduler already shut down when attempting "
                                "to schedule%s",
                  JOB_LOG_ID_EXPLICIT(log_file, log_line, log_name));
        return -1;
    }

    AVS_LIST(avs_sched_job_t) job = (avs_sched_job_t *)
            AVS_LIST_NEW_BUFFER(sizeof(avs_sched_job_t) + clb_data_size);
    if (!job) {
        SCHED_LOG(sched, ERROR, "could not allocate scheduler task");
        return -1;
    }

    job->sched = sched;
    job->instant = instant;
#ifdef WITH_INTERNAL_LOGS
    job->log_info.file = log_file;
    job->log_info.line = log_line;
    job->log_info.name = log_name;
#endif // WITH_INTERNAL_LOGS
    job->clb = clb;
    if (clb_data_size) {
        memcpy(job->clb_data, clb_data, clb_data_size);
    }

    AVS_LIST(avs_sched_job_t) *insert_ptr = NULL;
    AVS_LIST_FOREACH_PTR(insert_ptr, &sched->jobs) {
        if (avs_time_monotonic_before(instant, (*insert_ptr)->instant)) {
            break;
        }
    }
    if (out_handle) {
        job->handle_ptr = out_handle;
        avs_sched_job_t *previous_value;
        if (handle_ptr_exchange_value(out_handle,
                                      &previous_value, job)) {
            AVS_LIST_DELETE(&job);
            return -1;
        }
        AVS_ASSERT(!previous_value, "Dangerous non-initialized out_handle");
    }
    AVS_LIST_INSERT(insert_ptr, job);
#ifdef WITH_INTERNAL_TRACE
    avs_time_duration_t remaining =
            avs_time_monotonic_diff(instant, avs_time_monotonic_now());
    SCHED_LOG(sched, TRACE, "scheduled job%s at %s (+%s)", JOB_LOG_ID(job),
              TIME_STR(instant.since_monotonic_epoch), TIME_STR(remaining));
#endif // WITH_INTERNAL_TRACE
    return 0;
}

#ifdef WITH_SCHEDULER_THREAD_SAFE
static void notify_task_changes_locked(avs_sched_t *sched) {
    avs_condvar_notify_all(sched->task_condvar);
    AVS_LIST(avs_condvar_t *) ancestor_task_condvar;
    AVS_LIST_FOREACH(ancestor_task_condvar, sched->ancestor_task_condvars) {
        avs_condvar_notify_all(*ancestor_task_condvar);
    }
}
#else // WITH_SCHEDULER_THREAD_SAFE
#   define notify_task_changes_locked(...) ((void) 0)
#endif // WITH_SCHEDULER_THREAD_SAFE

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
    AVS_ASSERT((!out_handle || !*out_handle),
               "Dangerous non-initialized out_handle");
    if (!clb) {
        SCHED_LOG(sched, ERROR,
                  "attempted to schedule a null callback pointer%s",
                  JOB_LOG_ID_EXPLICIT(log_file, log_line, log_name));
        return -1;
    }
    if (!avs_time_monotonic_valid(instant)) {
        SCHED_LOG(sched, ERROR,
                  "attempted to schedule job%s at an invalid time point",
                  JOB_LOG_ID_EXPLICIT(log_file, log_line, log_name));
        return -1;
    }

    int result = -1;
    if (avs_mutex_lock(sched->mutex)) {
        SCHED_LOG(sched, ERROR, "could not lock mutex");
    } else {
        if (!(result = sched_at_locked(sched, out_handle, instant,
                                       log_file, log_line, log_name,
                                       clb, clb_data, clb_data_size))) {
            notify_task_changes_locked(sched);
        }
        avs_mutex_unlock(sched->mutex);
    }
    return result;
}

static void get_job_instant(avs_sched_job_t *job, void *out_time_ptr_) {
    if (job) {
        *(avs_time_monotonic_t *) out_time_ptr_ = job->instant;
    }
}

avs_time_monotonic_t avs_sched_time(avs_sched_handle_t *handle_ptr) {
    avs_time_monotonic_t result = AVS_TIME_MONOTONIC_INVALID;
    if (handle_ptr) {
        handle_ptr_access(handle_ptr, get_job_instant, &result);
    }
    return result;
}

typedef struct {
    avs_sched_handle_t *const handle_ptr;
    avs_sched_job_t *job;
    avs_sched_t *sched;
} handle_ops_init_data_t;

static void fill_handle_ops_init_data(avs_sched_job_t *job, void *out_ptr) {
    if (job) {
        handle_ops_init_data_t *out_data = (handle_ops_init_data_t *) out_ptr;
        AVS_ASSERT(out_data->handle_ptr == job->handle_ptr,
                   "accessing job via non-original handle");
        out_data->job = job;
        out_data->sched = job->sched;
    }
}

static int sched_del_locked(avs_sched_t *sched, avs_sched_job_t *job) {
    assert(job);
    assert(job->handle_ptr);
    SCHED_LOG(sched, TRACE, "cancelling job%s", JOB_LOG_ID(job));

    AVS_LIST(avs_sched_job_t) *job_ptr = (AVS_LIST(avs_sched_job_t) *)
            AVS_LIST_FIND_PTR(&sched->jobs, job);
    if (!job_ptr) {
#ifndef WITH_SCHEDULER_THREAD_SAFE
        AVS_ASSERT(job_ptr, "dangling handle detected");
#endif // WITH_SCHEDULER_THREAD_SAFE
        // Job might have been removed by another thread, don't do anything
        return 0;
    }

    avs_sched_job_t *previous_value;
    if (handle_ptr_exchange_value(job->handle_ptr,
                                  &previous_value, NULL)) {
        return -1;
    }
    assert(previous_value == job);

    AVS_LIST_DELETE(job_ptr);
    return 0;
}

int avs_sched_del(avs_sched_handle_t *handle_ptr) {
    if (!handle_ptr) {
        return 0;
    }
    handle_ops_init_data_t data = {
        .handle_ptr = handle_ptr
    };
    if (handle_ptr_access(handle_ptr,
                          fill_handle_ops_init_data, &data)) {
        return -1;
    }
    if (!data.job) {
        return 0;
    }
    assert(data.sched);
    int result = -1;
    if (avs_mutex_lock(data.sched->mutex)) {
        SCHED_LOG(data.sched, ERROR, "could not lock mutex");
    } else {
        result = sched_del_locked(data.sched, data.job);
        avs_mutex_unlock(data.sched->mutex);
    }
    return result;
}

static int sched_release_locked(avs_sched_t *sched, avs_sched_job_t *job) {
    AVS_LIST(avs_sched_job_t) *job_ptr = (AVS_LIST(avs_sched_job_t) *)
            AVS_LIST_FIND_PTR(&sched->jobs, job);
    if (!job_ptr) {
#ifndef WITH_SCHEDULER_THREAD_SAFE
        AVS_ASSERT(job_ptr, "dangling handle detected");
#endif // WITH_SCHEDULER_THREAD_SAFE
        // Job might have been removed by another thread, don't do anything
        return 0;
    }

    avs_sched_job_t *value;
    if (handle_ptr_exchange_value(job->handle_ptr, &value, NULL)) {
        return -1;
    }
    assert(value == job);
    job->handle_ptr = NULL;
    return 0;
}

int avs_sched_release(avs_sched_handle_t *handle_ptr) {
    if (!handle_ptr) {
        return 0;
    }
    handle_ops_init_data_t data = {
        .handle_ptr = handle_ptr
    };
    if (handle_ptr_access(handle_ptr,
                          fill_handle_ops_init_data, &data)) {
        return -1;
    }
    if (!data.job) {
        return 0;
    }
    assert(data.sched);
    int result = -1;
    if (avs_mutex_lock(data.sched->mutex)) {
        SCHED_LOG(data.sched, ERROR, "could not lock mutex");
    } else {
        result = sched_release_locked(data.sched, data.job);
        avs_mutex_unlock(data.sched->mutex);
    }
    return result;
}

static AVS_LIST(avs_sched_t *) *
traverse_descendants_locked(avs_sched_t *ancestor,
                            avs_sched_t *maybe_descendant) {
    AVS_LIST(avs_sched_t *) *child_ptr;
    AVS_LIST_FOREACH_PTR(child_ptr, &ancestor->children) {
        if (**child_ptr == maybe_descendant
                || avs_sched_is_descendant(**child_ptr, maybe_descendant)) {
            break;
        }
    }
    AVS_LIST_FOREACH_PTR(child_ptr, &ancestor->children_executed) {
        if (**child_ptr == maybe_descendant
                || avs_sched_is_descendant(**child_ptr, maybe_descendant)) {
            break;
        }
    }
    return child_ptr;
}

static bool is_descendant_locked(avs_sched_t *ancestor,
                                 avs_sched_t *maybe_descendant) {
    assert(ancestor);
    assert(maybe_descendant);
    return *traverse_descendants_locked(ancestor, maybe_descendant);
}

int avs_sched_is_descendant(avs_sched_t *ancestor,
                            avs_sched_t *maybe_descendant) {
    assert(ancestor);
    assert(maybe_descendant);
    int result = -1;
    if (avs_mutex_lock(ancestor->mutex)) {
        SCHED_LOG(ancestor, ERROR, "could not lock mutex");
    } else {
        result = (is_descendant_locked(ancestor, maybe_descendant) ? 1 : 0);
        avs_mutex_unlock(ancestor->mutex);
    }
    return result;
}

int avs_sched_register_child(avs_sched_t *parent, avs_sched_t *child) {
    assert(parent);
    assert(child);
    AVS_ASSERT(!avs_sched_is_descendant(child, parent),
               "Cycle found in the scheduler family tree");

    if (avs_mutex_lock(parent->mutex)) {
        SCHED_LOG(parent, ERROR, "could not lock mutex");
        return -1;
    }

    int result = -1;
    AVS_LIST(avs_sched_t *) *append_ptr =
            traverse_descendants_locked(parent, child);
    if (*append_ptr) {
        LOG(ERROR,
            "Scheduler \"%s\" is already a descendant of scheduler \"%s\"",
            child->name, parent->name);
    } else {
        if (avs_mutex_lock(child->mutex)) {
            SCHED_LOG(child, ERROR, "could not lock mutex");
            goto unlock_parent;
        }
        LOG(TRACE,
            "Registering scheduler \"%s\" as a child of scheduler \"%s\"",
            child->name, parent->name);
        AVS_LIST(avs_sched_t *) entry = AVS_LIST_NEW_ELEMENT(avs_sched_t *);
#ifdef WITH_SCHEDULER_THREAD_SAFE
        AVS_LIST(avs_condvar_t *) ancestor_condvar_entry =
                AVS_LIST_NEW_ELEMENT(avs_condvar_t *);
#else // WITH_SCHEDULER_THREAD_SAFE
        static const bool ancestor_condvar_entry = true;
#endif // WITH_SCHEDULER_THREAD_SAFE
        if (!entry || !ancestor_condvar_entry) {
            LOG(ERROR, "Out of memory while trying to add scheduler \"%s\" as "
                       "a child of scheduler \"%s\"",
                child->name, parent->name);
            AVS_LIST_DELETE(&entry);
            AVS_LIST_DELETE(&ancestor_condvar_entry);
        } else {
            *entry = child;
            AVS_LIST_INSERT(append_ptr, entry);
#ifdef WITH_SCHEDULER_THREAD_SAFE
            *ancestor_condvar_entry = parent->task_condvar;
            AVS_LIST_INSERT(&child->ancestor_task_condvars,
                            ancestor_condvar_entry);
#endif // WITH_SCHEDULER_THREAD_SAFE
            result = 0;
        }
    }

    avs_mutex_unlock(child->mutex);
unlock_parent:
    if (!result) {
        notify_task_changes_locked(parent);
    }
    avs_mutex_unlock(parent->mutex);
    return result;
}

int avs_sched_unregister_child(avs_sched_t *parent, avs_sched_t *child) {
    assert(parent);
    assert(child);
    if (avs_mutex_lock(parent->mutex)) {
        SCHED_LOG(parent, ERROR, "could not lock mutex");
        return -1;
    }

    int result = -1;
    AVS_LIST(avs_sched_t *) *child_ptr = NULL;
    AVS_LIST_FOREACH_PTR(child_ptr, &parent->children) {
        if (**child_ptr == child) {
            break;
        }
    }

    if (!*child_ptr) {
        AVS_LIST_FOREACH_PTR(child_ptr, &parent->children_executed) {
            if (**child_ptr == child) {
                break;
            }
        }
    }

    if (!*child_ptr) {
        LOG(ERROR,
            "Scheduler \"%s\" is not a (direct) child of scheduler \"%s\"",
            child->name, parent->name);
    } else {
        LOG(TRACE,
            "Unregistering scheduler \"%s\" as a child of scheduler \"%s\"",
            child->name, parent->name);
        if (avs_mutex_lock(child->mutex)) {
            SCHED_LOG(child, ERROR, "could not lock mutex");
        } else {
            remove_ancestor_condvar_locked(child, parent->task_condvar);
            AVS_LIST_DELETE(child_ptr);
            avs_mutex_unlock(child->mutex);
            result = 0;
        }
    }
    avs_mutex_unlock(parent->mutex);
    return result;
}

static int sched_leap_time_locking(avs_sched_t *sched,
                                   avs_time_duration_t diff,
                                   bool notify_ancestors);

static int leap_time_locked(avs_sched_t *sched, avs_time_duration_t diff) {
    assert(sched);
    AVS_ASSERT(!sched->children_executed,
               "Called avs_sched_time_of_next() "
               "while children schedulers are executed");

    SCHED_LOG(sched, INFO, "moving all jobs by %s s", TIME_STR(diff));

    AVS_LIST(avs_sched_job_t) job;
    AVS_LIST_FOREACH(job, sched->jobs) {
        job->instant = avs_time_monotonic_add(job->instant, diff);
    }

    AVS_LIST(avs_sched_t *) child;
    AVS_LIST_FOREACH(child, sched->children) {
        int result = sched_leap_time_locking(*child, diff, false);
        if (result) {
            return result;
        }
    }
    return 0;
}

static int sched_leap_time_locking(avs_sched_t *sched,
                                   avs_time_duration_t diff,
                                   bool notify_ancestors) {
    assert(sched);
    int result = -1;
    if (avs_mutex_lock(sched->mutex)) {
        SCHED_LOG(sched, ERROR, "could not lock mutex");
    } else {
        result = leap_time_locked(sched, diff);
        if (notify_ancestors) {
            notify_task_changes_locked(sched);
        } else {
            avs_condvar_notify_all(sched->task_condvar);
        }
        avs_mutex_unlock(sched->mutex);
    }
    return result;
}

int avs_sched_leap_time(avs_sched_t *sched, avs_time_duration_t diff) {
    return sched_leap_time_locking(sched, diff, true);
}

#ifdef AVS_UNIT_TESTING
#include "test/test_sched.c"
#endif
