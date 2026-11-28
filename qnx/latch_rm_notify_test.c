/*
 * latch_rm_notify_test.c -- THE HOST PROOF OF THE RESOURCE MANAGER'S
 * NOTIFICATION-LIST LOCK.
 *
 * WHAT THIS PROVES
 * ----------------
 * `qnx/latch_rm_notify.h` is the header every LATCH resource manager
 * uses to reach the QNX notify library, and it carries the rule that
 * the notify call is made while the notification list's lock is held.
 * The header is QNX-only by default, so without this test the rule
 * could only be READ, never RUN.
 *
 * This test compiles the SHIPPED header against the stub in
 * `qnx/latch_rm_notify_host.h` -- the same wrappers, the same text --
 * and runs them.  For every wrapped notify entry point it asserts:
 *
 *   1. the notify call runs WITH the lock held;
 *   2. if the lock cannot be taken, the notify call does NOT run at
 *      all, and the lock's error is returned (FAIL CLOSED);
 *   3. the lock is released on every path -- including the path where
 *      the notify call itself failed;
 *   4. a notification block that does not exist is refused with EINVAL,
 *      and the notify call does not run;
 *   5. the armed-count CHECK and the trigger that follows it are ONE
 *      critical section: the trigger fires exactly when the check says
 *      the count has been reached, and it fires with the lock held;
 *   6. the lock is REAL mutual exclusion: four threads hammering the
 *      same list never enter it at the same time.
 *
 * The test is deliberately about BEHAVIOUR: it does not look at the
 * source of the header.  A wrapper that took the lock after the call,
 * or that continued when the lock failed, would still LOOK right in the
 * source and would fail here.
 *
 * WHY THE CONCURRENCY CHECK MATTERS
 * ---------------------------------
 * The defect this closes is a RACE, and a race cannot be observed by
 * calling the wrapper once.  The library's own trigger walks the armed
 * list and unlinks the events it fires, while its own remove walks the
 * SAME list and frees the events -- so a trigger that runs while a
 * remove is running walks into freed memory.  The check here is that
 * the number of threads inside the critical section NEVER exceeds one.
 */

/* The feature-test macro has to be set BEFORE any system header, or
 * glibc hides `pthread_mutex_timedlock()` from a strict ISO C build.
 * The regression suite passes it on the command line as well, so this
 * is a no-op there. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#define LATCH_RM_NOTIFY_HOSTED 1

#include "latch_rm_notify.h"

#include <sched.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* The stub's state.                                                   */
/* ------------------------------------------------------------------ */

static int host_calls;            /* notify entry points that ran        */
static int host_calls_locked;     /* ... of which, with the lock held    */
static int host_lock_calls;       /* how many times the lock was taken  */
static int host_unlock_calls;     /* how many times it was released     */
static int host_lock_depth;       /* how many threads hold it RIGHT NOW  */
static int host_max_depth;        /* the most that ever did at once      */
static int host_force_error;      /* non-zero: the lock cannot be taken */
static int host_notify_rc;        /* what iofunc_notify() returns        */
static int host_trigger_calls;    /* iofunc_notify_trigger() calls       */
static int host_trigger_cnt;      /* the count it was called with        */
static int host_trigger_strict_calls;
static int host_remove_calls;

static void host_reset(void)
{
    host_calls = 0;
    host_calls_locked = 0;
    host_lock_calls = 0;
    host_unlock_calls = 0;
    host_lock_depth = 0;
    host_max_depth = 0;
    host_force_error = 0;
    host_notify_rc = 0;
    host_trigger_calls = 0;
    host_trigger_cnt = 0;
    host_trigger_strict_calls = 0;
    host_remove_calls = 0;
}

/* ------------------------------------------------------------------ */
/* The lock seam.  It is a REAL pthread mutex, so the concurrency check */
/* is a check of real mutual exclusion and not of a flag.            */
/*                                                                    */
/* Two details make a BROKEN wrapper fail instead of hanging:        */
/*                                                                    */
/*   - the acquisition is BOUNDED (a bounded spin), so a wrapper that */
/*     never releases the lock cannot wedge the regression suite;    */
/*   - the ownership is TRACKED PER THREAD, so a wrapper that unlocks */
/*     without holding the lock cannot make the fixture unlock a     */
/*     mutex that belongs to ANOTHER thread (which is undefined     */
/*     behaviour, and a test that corrupts its own fixture proves    */
/*     nothing).                                                      */
/* ------------------------------------------------------------------ */

#define HOST_LOCK_SPINS 100000

static _Thread_local int host_tls_held;   /* THIS thread holds the lock */

int latch_rm_notify_lock_impl(pthread_mutex_t *m)
{
    if (host_force_error != 0) {
        return host_force_error;
    }
    int spins = 0;
    for (;;) {
        int rc = pthread_mutex_trylock(m);
        if (rc == 0) {
            break;
        }
        if (rc != EBUSY) {
            return rc;
        }
        if (++spins >= HOST_LOCK_SPINS) {
            return EBUSY;
        }
        (void)sched_yield();
    }
    host_tls_held = 1;
    host_lock_calls++;
    host_lock_depth++;
    if (host_lock_depth > host_max_depth) {
        host_max_depth = host_lock_depth;
    }
    return 0;
}

int latch_rm_notify_unlock_impl(pthread_mutex_t *m)
{
    host_unlock_calls++;
    if (!host_tls_held) {
        /* The caller never held the lock.  Do NOT touch the mutex: an
         * unlock of a mutex this thread does not own is undefined, and a
         * test that corrupts its own fixture proves nothing. */
        return EINVAL;
    }
    host_tls_held = 0;
    host_lock_depth--;
    return pthread_mutex_unlock(m);
}

/* ------------------------------------------------------------------ */
/* The stubbed notify entry points.                                    */
/* ------------------------------------------------------------------ */

static void host_note(void)
{
    host_calls++;
    if (host_lock_depth > 0) {
        host_calls_locked++;
    }
}

int iofunc_notify(resmgr_context_t *ctp, io_notify_t *msg,
                  iofunc_notify_t *nop, int trig,
                  const int *notifycnts, int *armed)
{
    (void)ctp;
    (void)msg;
    (void)trig;
    (void)notifycnts;
    (void)armed;
    host_note();
    /* The library WRITES the armed count when it arms a notification. */
    if (nop != NULL) {
        nop[IOFUNC_NOTIFY_INPUT].cnt = 1;
    }
    return host_notify_rc;
}

void iofunc_notify_trigger(iofunc_notify_t *nop, int cnt, int index)
{
    (void)index;
    host_note();
    host_trigger_calls++;
    host_trigger_cnt = cnt;
    /* The library consumes the armed notification when it fires it. */
    if (nop != NULL) {
        nop[IOFUNC_NOTIFY_INPUT].cnt = 0;
    }
}

void iofunc_notify_trigger_strict(resmgr_context_t *ctp,
                                  iofunc_notify_t *nop, int cnt, int index)
{
    (void)ctp;
    (void)nop;
    (void)cnt;
    (void)index;
    host_note();
    host_trigger_strict_calls++;
}

void iofunc_notify_remove(resmgr_context_t *ctp, iofunc_notify_t *nop)
{
    (void)ctp;
    (void)nop;
    host_note();
    host_remove_calls++;
}

/* ------------------------------------------------------------------ */
/* The test harness.                                                   */
/* ------------------------------------------------------------------ */

static int failures = 0;

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            failures++;                                                     \
            printf("  FAIL: ");                                             \
            printf(__VA_ARGS__);                                            \
            printf("\n");                                                   \
        }                                                                   \
    } while (0)

static latch_rm_notify_t g_block;

static int run_arm(latch_rm_notify_t *n)
{
    resmgr_context_t ctp;
    io_notify_t msg;
    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    return latch_rm_notify_arm(&ctp, &msg, n, 0);
}

static int run_input_fire(latch_rm_notify_t *n, int cnt, int *fired)
{
    return latch_rm_notify_input_fire(n, cnt, fired);
}

static int run_trigger_strict(latch_rm_notify_t *n)
{
    resmgr_context_t ctp;
    memset(&ctp, 0, sizeof(ctp));
    return latch_rm_notify_trigger_strict(&ctp, n, 1, IOFUNC_NOTIFY_INPUT);
}

static int run_remove(latch_rm_notify_t *n)
{
    resmgr_context_t ctp;
    memset(&ctp, 0, sizeof(ctp));
    return latch_rm_notify_remove(&ctp, n);
}

/* ------------------------------------------------------------------ */
/* 1. THE ARM PATH: iofunc_notify().                                   */
/* ------------------------------------------------------------------ */

static void check_arm(void)
{
    int rc;

    printf("=== arm (iofunc_notify) ===\n");

    /* THE HAPPY PATH: the notify call runs WITH the lock held. */
    host_reset();
    rc = run_arm(&g_block);
    CHECK(rc == EOK, "arm: the wrapper returned %d, want EOK (%d)", rc, EOK);
    CHECK(host_calls == 1, "arm: the notify call ran %d time(s), want 1",
          host_calls);
    CHECK(host_calls_locked == 1,
          "arm: the notify call ran %d time(s) WITH the lock held, want 1 "
          "-- iofunc_notify() LINKS a new event into the shared list, so it "
          "must not run outside the notification lock",
          host_calls_locked);
    CHECK(host_lock_calls == 1, "arm: the lock was taken %d time(s), want 1",
          host_lock_calls);
    CHECK(host_unlock_calls == 1,
          "arm: the lock was released %d time(s), want 1", host_unlock_calls);
    CHECK(host_lock_depth == 0,
          "arm: the lock is STILL HELD after the wrapper returned");

    /* THE LOCK CANNOT BE TAKEN: fail closed. */
    host_reset();
    host_force_error = EBUSY;
    rc = run_arm(&g_block);
    CHECK(rc == EBUSY,
          "arm: with the lock unavailable the wrapper returned %d, want the "
          "lock's error (%d)", rc, EBUSY);
    CHECK(host_calls == 0,
          "arm: the notify call ran %d time(s) even though the lock could not "
          "be taken -- the operation must be REFUSED, not performed unlocked",
          host_calls);
    CHECK(host_unlock_calls == 0,
          "arm: the lock was released %d time(s) although it was never taken",
          host_unlock_calls);

    /* THE NOTIFY CALL FAILS: the error comes back AND the lock is
     * released. */
    host_reset();
    host_notify_rc = EACCES;
    rc = run_arm(&g_block);
    CHECK(rc == EACCES,
          "arm: the wrapper returned %d, want the notify call's error (%d)",
          rc, EACCES);
    CHECK(host_calls == 1, "arm: the notify call ran %d time(s), want 1",
          host_calls);
    CHECK(host_calls_locked == 1,
          "arm: the notify call ran %d time(s) WITH the lock held, want 1",
          host_calls_locked);
    CHECK(host_unlock_calls == 1,
          "arm: the lock was released %d time(s) on the error path, want 1 "
          "-- a lock that is not released on the error path deadlocks the "
          "node", host_unlock_calls);
    CHECK(host_lock_depth == 0,
          "arm: the lock is STILL HELD after the notify call failed");

    /* NO BLOCK: refused, and the notify call does not run. */
    host_reset();
    rc = run_arm(NULL);
    CHECK(rc == EINVAL,
          "arm: with no notification block the wrapper returned %d, want "
          "EINVAL (%d)", rc, EINVAL);
    CHECK(host_calls == 0,
          "arm: the notify call ran %d time(s) with no notification block to "
          "lock", host_calls);
}

/* ------------------------------------------------------------------ */
/* 2. THE FIRE PATH: the armed-count CHECK and the trigger.            */
/* ------------------------------------------------------------------ */

static void check_input_fire(void)
{
    int fired = -1;
    int rc;

    printf("=== input_fire (the check and the trigger) ===\n");

    /* ARMED: the count has been reached, so the trigger fires -- and it
     * fires WITH the lock held. */
    host_reset();
    IOFUNC_NOTIFY_INIT(g_block.nop);
    g_block.nop[IOFUNC_NOTIFY_INPUT].cnt = 1;   /* a client armed it */
    rc = run_input_fire(&g_block, 1, &fired);
    CHECK(rc == EOK, "input_fire: the wrapper returned %d, want EOK (%d)",
          rc, EOK);
    CHECK(fired == 1,
          "input_fire: the trigger did NOT fire although the armed count "
          "(1) had been reached (the CHECK and the TRIGGER have to be one "
          "critical section)");
    CHECK(host_trigger_calls == 1,
          "input_fire: the trigger ran %d time(s), want 1",
          host_trigger_calls);
    CHECK(host_trigger_cnt == 1,
          "input_fire: the trigger was called with the count %d, want 1",
          host_trigger_cnt);
    CHECK(host_calls_locked == 1,
          "input_fire: the trigger ran %d time(s) WITH the lock held, want 1 "
          "-- iofunc_notify_trigger() WALKS the shared list and unlinks the "
          "events it fires", host_calls_locked);
    CHECK(host_lock_depth == 0,
          "input_fire: the lock is STILL HELD after the wrapper returned");

    /* NOT ARMED: the count has NOT been reached, so nothing fires. */
    host_reset();
    IOFUNC_NOTIFY_INIT(g_block.nop);   /* cnt = INT_MAX: nothing armed */
    fired = -1;
    rc = run_input_fire(&g_block, 1, &fired);
    CHECK(rc == EOK, "input_fire: the wrapper returned %d, want EOK (%d)",
          rc, EOK);
    CHECK(fired == 0,
          "input_fire: the trigger fired although no client had armed a "
          "notification");
    CHECK(host_trigger_calls == 0,
          "input_fire: the trigger ran %d time(s), want 0",
          host_trigger_calls);

    /* THE LOCK CANNOT BE TAKEN: fail closed, and nothing fires. */
    host_reset();
    IOFUNC_NOTIFY_INIT(g_block.nop);
    g_block.nop[IOFUNC_NOTIFY_INPUT].cnt = 1;
    host_force_error = EBUSY;
    fired = -1;
    rc = run_input_fire(&g_block, 1, &fired);
    CHECK(rc == EBUSY,
          "input_fire: with the lock unavailable the wrapper returned %d, "
          "want the lock's error (%d)", rc, EBUSY);
    CHECK(fired == 0,
          "input_fire: the trigger fired although the lock could not be "
          "taken");
    CHECK(host_trigger_calls == 0,
          "input_fire: the trigger ran %d time(s) even though the lock could "
          "not be taken -- the trigger WALKS the shared list, so it must not "
          "run unlocked", host_trigger_calls);

    /* NO BLOCK: refused. */
    host_reset();
    fired = -1;
    rc = run_input_fire(NULL, 1, &fired);
    CHECK(rc == EINVAL,
          "input_fire: with no notification block the wrapper returned %d, "
          "want EINVAL (%d)", rc, EINVAL);
    CHECK(fired == 0,
          "input_fire: the trigger fired with no notification block at all");
    CHECK(host_trigger_calls == 0,
          "input_fire: the trigger ran %d time(s) with no notification "
          "block", host_trigger_calls);
}

/* ------------------------------------------------------------------ */
/* 3. THE CLOSE PATH: trigger_strict and remove.                       */
/* ------------------------------------------------------------------ */

static void check_close_path(void)
{
    int rc;

    printf("=== trigger_strict (iofunc_notify_trigger_strict) ===\n");

    host_reset();
    rc = run_trigger_strict(&g_block);
    CHECK(rc == EOK,
          "trigger_strict: the wrapper returned %d, want EOK (%d)", rc, EOK);
    CHECK(host_trigger_strict_calls == 1,
          "trigger_strict: the notify call ran %d time(s), want 1",
          host_trigger_strict_calls);
    CHECK(host_calls_locked == 1,
          "trigger_strict: the notify call ran %d time(s) WITH the lock "
          "held, want 1 -- it WALKS the shared list and unlinks the events "
          "it fires", host_calls_locked);
    CHECK(host_lock_depth == 0,
          "trigger_strict: the lock is STILL HELD after the wrapper "
          "returned");

    host_reset();
    host_force_error = EBUSY;
    rc = run_trigger_strict(&g_block);
    CHECK(rc == EBUSY,
          "trigger_strict: with the lock unavailable the wrapper returned "
          "%d, want the lock's error (%d)", rc, EBUSY);
    CHECK(host_trigger_strict_calls == 0,
          "trigger_strict: the notify call ran %d time(s) even though the "
          "lock could not be taken", host_trigger_strict_calls);

    host_reset();
    rc = run_trigger_strict(NULL);
    CHECK(rc == EINVAL,
          "trigger_strict: with no notification block the wrapper returned "
          "%d, want EINVAL (%d)", rc, EINVAL);
    CHECK(host_trigger_strict_calls == 0,
          "trigger_strict: the notify call ran %d time(s) with no "
          "notification block", host_trigger_strict_calls);

    printf("=== remove (iofunc_notify_remove) ===\n");

    host_reset();
    rc = run_remove(&g_block);
    CHECK(rc == EOK, "remove: the wrapper returned %d, want EOK (%d)", rc,
          EOK);
    CHECK(host_remove_calls == 1,
          "remove: the notify call ran %d time(s), want 1",
          host_remove_calls);
    CHECK(host_calls_locked == 1,
          "remove: the notify call ran %d time(s) WITH the lock held, want 1 "
          "-- it WALKS the shared list and FREES the events, so it must not "
          "run while a trigger is walking it", host_calls_locked);
    CHECK(host_lock_depth == 0,
          "remove: the lock is STILL HELD after the wrapper returned");

    host_reset();
    host_force_error = EBUSY;
    rc = run_remove(&g_block);
    CHECK(rc == EBUSY,
          "remove: with the lock unavailable the wrapper returned %d, want "
          "the lock's error (%d)", rc, EBUSY);
    CHECK(host_remove_calls == 0,
          "remove: the notify call ran %d time(s) even though the lock "
          "could not be taken", host_remove_calls);

    host_reset();
    rc = run_remove(NULL);
    CHECK(rc == EINVAL,
          "remove: with no notification block the wrapper returned %d, want "
          "EINVAL (%d)", rc, EINVAL);
    CHECK(host_remove_calls == 0,
          "remove: the notify call ran %d time(s) with no notification "
          "block", host_remove_calls);
}

/* ------------------------------------------------------------------ */
/* 4. THE CONCURRENCY CHECK.                                           */
/* ------------------------------------------------------------------ */

#define CONC_THREADS 4
#define CONC_ITERS   2000

static latch_rm_notify_t g_conc_block;

typedef struct {
    int iters;
} conc_arg_t;

static void *conc_worker(void *arg)
{
    conc_arg_t *a = (conc_arg_t *)arg;
    int i;

    for (i = 0; i < a->iters; ++i) {
        int fired = 0;
        /* The three operations that touch the SAME list in the sink. */
        if (run_arm(&g_conc_block) != EOK) {
            /* The lock could not be taken.  That is the fail-closed path
             * working -- but a BROKEN wrapper that never releases the
             * lock would make this spin for every iteration, so stop
             * here and let the assertions speak. */
            break;
        }
        if (run_input_fire(&g_conc_block, 1, &fired) != EOK) {
            break;
        }
        if (run_remove(&g_conc_block) != EOK) {
            break;
        }
    }
    return NULL;
}

static void check_concurrency(void)
{
    pthread_t tid[CONC_THREADS];
    conc_arg_t arg;
    int i;
    int started = 0;

    printf("=== concurrency (%d threads x %d iterations) ===\n",
           CONC_THREADS, CONC_ITERS);

    host_reset();
    arg.iters = CONC_ITERS;
    for (i = 0; i < CONC_THREADS; ++i) {
        if (pthread_create(&tid[i], NULL, conc_worker, &arg) != 0) {
            CHECK(0, "concurrency: pthread_create failed for thread %d", i);
            break;
        }
        started++;
    }
    for (i = 0; i < started; ++i) {
        (void)pthread_join(tid[i], NULL);
    }

    CHECK(started == CONC_THREADS,
          "concurrency: only %d of %d threads ran", started, CONC_THREADS);
    CHECK(host_max_depth == 1,
          "concurrency: %d threads were inside the notification critical "
          "section AT THE SAME TIME -- the lock is not mutual exclusion, so "
          "the library's trigger can walk a list the library's remove is "
          "freeing", host_max_depth);
    CHECK(host_calls_locked == host_calls,
          "concurrency: %d of %d notify calls ran WITH the lock held",
          host_calls_locked, host_calls);
    CHECK(host_lock_depth == 0,
          "concurrency: the lock is STILL HELD after every thread finished");
}

/* ------------------------------------------------------------------ */

int main(void)
{
    int rc;

    printf("=== latch_rm_notify_test: the resource manager's notification "
           "lock ===\n");

    rc = latch_rm_notify_init(&g_block);
    if (rc != EOK) {
        printf("  FAIL: latch_rm_notify_init() returned %d\n", rc);
        return 1;
    }
    rc = latch_rm_notify_init(&g_conc_block);
    if (rc != EOK) {
        printf("  FAIL: latch_rm_notify_init() returned %d\n", rc);
        return 1;
    }

    check_arm();
    check_input_fire();
    check_close_path();
    check_concurrency();

    if (failures != 0) {
        printf("=== latch_rm_notify_test: %d check(s) FAILED ===\n", failures);
        return 1;
    }
    printf("=== latch_rm_notify_test: all checks PASSED ===\n");
    return 0;
}
