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
    avs_sched_t *parent;
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

static void nonfailing_mutex_lock(avs_mutex_t *mutex) {
    if (avs_mutex_lock(mutex)) {
        AVS_UNREACHABLE("could not lock mutex");
    }
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

#   define JOB_LOG_ID_EXPLICIT(File, Line, Name) \
        job_log_id_impl(&(char[JOB_LOG_ID_MAX_LENGTH]) { "" }[0], \
                        (File), (Line), (Name))

#   define JOB_LOG_ID(Job) \
        JOB_LOG_ID_EXPLICIT((Job)->log_info.file, (Job)->log_info.line, \
                            (Job)->log_info.name)

#endif // WITH_INTERNAL_LOGS

#ifdef WITH_SCHEDULER_THREAD_SAFE
static int init_globals(void *dummy) {
    (void) dummy;
    return avs_mutex_create(&g_handle_access_mutex);
}
#endif // WITH_SCHEDULER_THREAD_SAFE

void _avs_sched_cleanup_global_state(void);
void _avs_sched_cleanup_global_state(void) {
#ifdef WITH_SCHEDULER_THREAD_SAFE
    avs_mutex_cleanup(&g_handle_access_mutex);
    g_init_handle = NULL;
#endif // WITH_SCHEDULER_THREAD_SAFE
}

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

void avs_sched_cleanup(avs_sched_t **sched_ptr) {
    if (!sched_ptr || !*sched_ptr) {
        return;
    }

    SCHED_LOG(*sched_ptr, DEBUG, "shutting down");
    (*sched_ptr)->shut_down = true;

    AVS_ASSERT(!(*sched_ptr)->children_executed,
               "Attempting to clean up scheduler that is being run");
    while ((*sched_ptr)->children) {
        avs_sched_unregister_child(*sched_ptr, *(*sched_ptr)->children);
    }
    if ((*sched_ptr)->parent) {
        avs_sched_unregister_child((*sched_ptr)->parent, *sched_ptr);
    }

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
    nonfailing_mutex_lock(sched->mutex);
    avs_time_monotonic_t result = sched_time_of_next_locked(sched);
    avs_mutex_unlock(sched->mutex);
    return result;
}

int avs_sched_wait_until_next(avs_sched_t *sched,
                              avs_time_monotonic_t deadline) {
    int result = -1;
    (void) deadline;
#ifdef WITH_SCHEDULER_THREAD_SAFE
    nonfailing_mutex_lock(sched->mutex);
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

static AVS_LIST(avs_sched_job_t) fetch_job(avs_sched_t *sched,
                                           avs_time_monotonic_t deadline) {
    AVS_LIST(avs_sched_job_t) result = NULL;
    nonfailing_mutex_lock(sched->mutex);
    if (sched->jobs
            && avs_time_monotonic_before(sched->jobs->instant,
                                         deadline)) {
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

    SCHED_LOG(sched, TRACE, "executing job%s", JOB_LOG_ID(job));

    job->clb(sched, job->clb_data);
    AVS_LIST_DELETE(&job);
}

static avs_sched_t *fetch_child(avs_sched_t *sched) {
    avs_sched_t *result = NULL;
    nonfailing_mutex_lock(sched->mutex);
    if (sched->children) {
        result = *AVS_LIST_INSERT(&sched->children_executed,
                                  AVS_LIST_DETACH(&sched->children));
    }
    avs_mutex_unlock(sched->mutex);
    return result;
}

static void reorganize_children(avs_sched_t *sched) {
    nonfailing_mutex_lock(sched->mutex);
    // fetch_child_*() loop reverses the order when moving from children
    // to children_executed, so reverse the order once again
    while (sched->children_executed) {
        AVS_LIST_INSERT(&sched->children,
                        AVS_LIST_DETACH(&sched->children_executed));
    }
    avs_mutex_unlock(sched->mutex);
}

void avs_sched_run(avs_sched_t *sched) {
    assert(sched);
    avs_time_monotonic_t now = avs_time_monotonic_now();

    uint64_t tasks_executed = 0;
    AVS_LIST(avs_sched_job_t) job = NULL;
    while ((job = fetch_job(sched, now))) {
        assert(job->sched == sched);
        execute_job(sched, job);
        ++tasks_executed;
    }

    if (tasks_executed) {
        SCHED_LOG(sched, TRACE, "%" PRIu64 " jobs executed", tasks_executed);
    } else {
        bool we_have_children = false;
        avs_sched_t *child = NULL;
        while ((child = fetch_child(sched))) {
            if (!we_have_children) {
                we_have_children = true;
                SCHED_LOG(sched, TRACE, "no local jobs to execute, "
                                        "processing child schedulers");
            }
            avs_sched_run(child);
        }
        if (we_have_children) {
            reorganize_children(sched);
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
                  AVS_TIME_DURATION_AS_STRING(next.since_monotonic_epoch),
                  AVS_TIME_DURATION_AS_STRING(remaining));
    }
#endif // WITH_INTERNAL_TRACE
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
        nonfailing_mutex_lock(g_handle_access_mutex);
        AVS_ASSERT(!*out_handle, "Dangerous non-initialized out_handle");
        *out_handle = job;
        avs_mutex_unlock(g_handle_access_mutex);
    }
    AVS_LIST_INSERT(insert_ptr, job);
#ifdef WITH_INTERNAL_TRACE
    avs_time_duration_t remaining =
            avs_time_monotonic_diff(instant, avs_time_monotonic_now());
    SCHED_LOG(sched, TRACE, "scheduled job%s at %s (+%s)", JOB_LOG_ID(job),
              AVS_TIME_DURATION_AS_STRING(instant.since_monotonic_epoch),
              AVS_TIME_DURATION_AS_STRING(remaining));
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
    nonfailing_mutex_lock(sched->mutex);
    if (!(result = sched_at_locked(sched, out_handle, instant,
                                   log_file, log_line, log_name,
                                   clb, clb_data, clb_data_size))) {
        notify_task_changes_locked(sched);
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

typedef struct {
    avs_sched_handle_t *const handle_ptr;
    avs_sched_job_t *job;
    avs_sched_t *sched;
} handle_ops_init_data_t;

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
#ifndef WITH_SCHEDULER_THREAD_SAFE
        AVS_ASSERT(job_ptr, "dangling handle detected");
#endif // WITH_SCHEDULER_THREAD_SAFE
        // Job might have been removed by another thread, don't do anything
    } else {
        SCHED_LOG(sched, TRACE, "cancelling job%s", JOB_LOG_ID(job));
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
#ifndef WITH_SCHEDULER_THREAD_SAFE
        AVS_ASSERT(job_ptr, "dangling handle detected");
#endif // WITH_SCHEDULER_THREAD_SAFE
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

static AVS_LIST(avs_sched_t *) *
traverse_descendants_locked(avs_sched_t *ancestor,
                            avs_sched_t *maybe_descendant) {
    AVS_LIST(avs_sched_t *) *child_ptr;
    AVS_LIST_FOREACH_PTR(child_ptr, &ancestor->children_executed) {
        if (**child_ptr == maybe_descendant
                || avs_sched_is_descendant(**child_ptr, maybe_descendant)) {
            break;
        }
    }
    AVS_LIST_FOREACH_PTR(child_ptr, &ancestor->children) {
        if (**child_ptr == maybe_descendant
                || avs_sched_is_descendant(**child_ptr, maybe_descendant)) {
            break;
        }
    }
    return child_ptr;
}

bool avs_sched_is_descendant(avs_sched_t *ancestor,
                             avs_sched_t *maybe_descendant) {
    assert(ancestor);
    assert(maybe_descendant);
    nonfailing_mutex_lock(ancestor->mutex);
    bool result = !!*traverse_descendants_locked(ancestor, maybe_descendant);
    avs_mutex_unlock(ancestor->mutex);
    return result;
}

int avs_sched_register_child(avs_sched_t *parent, avs_sched_t *child) {
    assert(parent);
    assert(child);
    AVS_ASSERT(!avs_sched_is_descendant(child, parent),
               "Cycle found in the scheduler family tree");

    nonfailing_mutex_lock(parent->mutex);
    nonfailing_mutex_lock(child->mutex);

    int result = -1;
    if (child->parent) {
        SCHED_LOG(child, ERROR, "already a descendant of some scheduler");
    } else {
        AVS_LIST(avs_sched_t *) *append_ptr =
                traverse_descendants_locked(parent, child);
        AVS_ASSERT(!*append_ptr, "Inconsistent scheduler family tree");
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
#ifdef WITH_SCHEDULER_THREAD_SAFE
            AVS_LIST_DELETE(&ancestor_condvar_entry);
#endif // WITH_SCHEDULER_THREAD_SAFE
        } else {
            *entry = child;
            child->parent = parent;
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
    if (!result) {
        notify_task_changes_locked(parent);
    }
    avs_mutex_unlock(parent->mutex);
    return result;
}

#ifdef WITH_SCHEDULER_THREAD_SAFE
static void remove_ancestor_condvar(avs_sched_t *sched,
                                           avs_condvar_t *ancestor_condvar) {
    assert(sched);
    AVS_LIST(avs_condvar_t *) *element_ptr;
    AVS_LIST_FOREACH_PTR(element_ptr, &sched->ancestor_task_condvars) {
        if (**element_ptr == ancestor_condvar) {
            AVS_LIST_DELETE(element_ptr);
            AVS_LIST(avs_sched_t *) child;
            AVS_LIST_FOREACH(child, sched->children) {
                nonfailing_mutex_lock((*child)->mutex);
                remove_ancestor_condvar(*child, ancestor_condvar);
                avs_mutex_unlock((*child)->mutex);
            }
            break;
        }
    }
}
#else // WITH_SCHEDULER_THREAD_SAFE
#define remove_ancestor_condvar(...) ((void) 0)
#endif // WITH_SCHEDULER_THREAD_SAFE

int avs_sched_unregister_child(avs_sched_t *parent, avs_sched_t *child) {
    assert(parent);
    assert(child);
    nonfailing_mutex_lock(parent->mutex);

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
        nonfailing_mutex_lock(child->mutex);
        AVS_ASSERT(child->parent == parent,
                   "Inconsistent scheduler family tree");
        child->parent = NULL;
        remove_ancestor_condvar(child, parent->task_condvar);
        AVS_LIST_DELETE(child_ptr);
        avs_mutex_unlock(child->mutex);
        result = 0;
    }
    avs_mutex_unlock(parent->mutex);
    return result;
}

static void leap_time_impl(avs_sched_t *sched,
                           avs_time_duration_t diff,
                           bool notify_ancestors) {
    assert(sched);
    nonfailing_mutex_lock(sched->mutex);
    AVS_ASSERT(!sched->children_executed,
               "Called avs_sched_time_of_next() "
               "while children schedulers are executed");

    SCHED_LOG(sched, INFO, "moving all jobs by %s s",
              AVS_TIME_DURATION_AS_STRING(diff));

    AVS_LIST(avs_sched_job_t) job;
    AVS_LIST_FOREACH(job, sched->jobs) {
        job->instant = avs_time_monotonic_add(job->instant, diff);
    }

    AVS_LIST(avs_sched_t *) child;
    AVS_LIST_FOREACH(child, sched->children) {
        leap_time_impl(*child, diff, false);
    }
    if (notify_ancestors) {
        notify_task_changes_locked(sched);
    } else {
        avs_condvar_notify_all(sched->task_condvar);
    }
    avs_mutex_unlock(sched->mutex);
}

int avs_sched_leap_time(avs_sched_t *sched, avs_time_duration_t diff) {
    if (avs_time_duration_valid(diff)) {
        SCHED_LOG(sched, ERROR, "attempted to leap an invalid amount of time");
        return -1;
    }
    leap_time_impl(sched, diff, true);
    return 0;
}

#ifdef AVS_UNIT_TESTING
#include "test/test_sched.c"
#endif
