/*
 * qnx/latch_guest_child.h
 *
 * THE GUEST CHILD'S LIFECYCLE: THE DECISIONS, AND WHY THEY FAIL CLOSED
 * =====================================================================
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * `qnx/latch_guestd.c` is the dedicated lifecycle daemon: it spawns the
 * guest hypervisor as a CHILD PROCESS, and it is the only thing that
 * decides when that child is stopped and when its corpse is collected.
 *
 * Three of its decisions are safety properties, and all three of them were
 * defects:
 *
 *   1. THE REAP'S OUTCOME WAS READ WITHOUT ITS `errno`.  The code did
 *
 *          int r = waitpid(g_guest_pid, &status, WNOHANG);
 *          if (r == 0) { return 0; }        // still running
 *          if (r > 0)  { ...; return 1; }   // reaped
 *          ...                              // EVERYTHING ELSE
 *
 *      and the "everything else" branch was reached by BOTH `ECHILD` (no
 *      such child) and **`EINTR`** (the call was interrupted before it did
 *      anything).  The daemon's SIGCHLD handler is installed WITHOUT
 *      `SA_RESTART`, so the `waitpid()` was genuinely interruptible: when
 *      the child died, the signal handler could run *inside* the `waitpid()`
 *      and the call would return `-1` with `errno == EINTR`.  The daemon
 *      then concluded that the child was GONE -- set `g_guest_pid = -1`
 *      and reported "the guest VM stopped" -- **while the guest was still
 *      running**.  A stop that reports success without stopping the guest
 *      is the worst possible answer, because the caller is then free to
 *      start a SECOND guest, and two guests fight over the same
 *      virtio-console endpoint.
 *
 *   2. THE CHILD WAS REAPED BEFORE IT COULD BE KILLED.  The SIGCHLD
 *      handler reaped ANY child with `waitpid(-1, ...)`, so the child's PID
 *      -- the very handle `guest_stop()` used to send `SIGKILL` -- was
 *      released while the daemon still believed the guest was running.
 *      **A child's PID cannot be reused while it is an unreaped zombie**,
 *      so reaping it is exactly what makes the PID reusable, and the
 *      `kill(pid, SIGKILL)` in `guest_stop()` could then land on an
 *      unrelated process.  The fix is the ORDER: the child must be KILLED
 *      BEFORE it is reaped, and the only way to guarantee that against an
 *      asynchronous signal handler is to hold the signal blocked across the
 *      whole "kill, then reap" sequence.
 *
 *   3. THE TERMINATION PATH LEFT THE GUEST RUNNING.  `SIGTERM` (and
 *      `SIGINT`) only cleared the run flag; the daemon then detached and
 *      exited, and the guest hypervisor -- its own CHILD -- kept running
 *      as an orphan.  A lifecycle daemon whose death leaves the thing it
 *      manages running is not a lifecycle daemon.
 *
 * WHY A HEADER
 * ------------
 * The QNX path cannot be exercised off-target in the way that matters:
 * `waitpid()`'s `errno` is what the old code threw away, and the
 * interesting cases (`EINTR` versus `ECHILD`) are the ones a host test
 * CAN produce -- by injecting the `errno` directly.  So the DECISIONS live
 * here, in a header that both the daemon and a host test compile, and the
 * host test walks every row.
 *
 * IT FAILS CLOSED
 * ---------------
 * The ZERO value of each enum is the UNKNOWN one, so a decision variable
 * that was never assigned -- or that was assigned a value this header does
 * not define -- establishes NOTHING.  There is no default, no fallback and
 * no "assume it worked" path.
 */

#ifndef LATCH_GUEST_CHILD_H_
#define LATCH_GUEST_CHILD_H_

#include <errno.h>
#include <stdbool.h>

/*
 * 1. THE REAP ATTEMPT'S OUTCOME.
 *
 * `waitpid()` has FIVE distinguishable results, and the old code had two
 * branches for them.
 */
typedef enum {
    /* The zero value is UNKNOWN: an unassigned outcome establishes
     * NOTHING. */
    LATCH_GUEST_REAP_UNKNOWN     = 0,
    /* `waitpid()` returned the pid: the child was reaped. */
    LATCH_GUEST_REAP_REAPED      = 1,
    /* `waitpid()` returned 0 with `WNOHANG`: the child is still running. */
    LATCH_GUEST_REAP_RUNNING     = 2,
    /* `waitpid()` returned -1 with `ECHILD`: there is no such child to
     * wait for (it was already reaped). */
    LATCH_GUEST_REAP_NO_CHILD    = 3,
    /* `waitpid()` returned -1 with `EINTR`: the call was INTERRUPTED
     * before it established anything.  This is NOT "the child is gone" --
     * it is "ask again". */
    LATCH_GUEST_REAP_INTERRUPTED = 4,
    /* `waitpid()` returned -1 with any other errno: the call failed. */
    LATCH_GUEST_REAP_ERROR       = 5,
} latch_guest_reap_outcome_t;

/*
 * THE REAP DECISION.
 *
 * `wait_rc` is `waitpid()`'s return value and `wait_errno` is the
 * `errno` it left behind.  The two are read TOGETHER, because the return
 * value alone does not distinguish "there is no such child" from "the call
 * was interrupted" -- both are -1.
 */
static inline latch_guest_reap_outcome_t latch_guest_reap_decide(int wait_rc,
                                                                 int wait_errno) {
    if (wait_rc > 0) {
        return LATCH_GUEST_REAP_REAPED;
    }
    if (wait_rc == 0) {
        return LATCH_GUEST_REAP_RUNNING;
    }
    if (wait_errno == EINTR) {
        return LATCH_GUEST_REAP_INTERRUPTED;
    }
    if (wait_errno == ECHILD) {
        return LATCH_GUEST_REAP_NO_CHILD;
    }
    return LATCH_GUEST_REAP_ERROR;
}

/*
 * DOES THIS OUTCOME ESTABLISH THAT THE CHILD IS GONE?
 *
 * Exactly TWO of the five do: the child was reaped, or there is no such
 * child.  The interrupted outcome does NOT -- and that is the whole point
 * of this file.  A daemon that treats "the call was interrupted" as "the
 * child is gone" reports a successful stop for a guest that is still
 * running.
 */
static inline bool latch_guest_reap_gone(latch_guest_reap_outcome_t outcome) {
    return outcome == LATCH_GUEST_REAP_REAPED ||
           outcome == LATCH_GUEST_REAP_NO_CHILD;
}

/* "Ask again" -- the call established nothing and must be retried. */
static inline bool latch_guest_reap_retry(latch_guest_reap_outcome_t outcome) {
    return outcome == LATCH_GUEST_REAP_INTERRUPTED;
}

/*
 * 2. THE STOP SEQUENCE'S OUTCOME.
 *
 * The sequence is, in this order:
 *
 *     1. KILL the child (while its PID is still reserved), then
 *     2. REAP it.
 *
 * and the order is load-bearing, so the combined decision takes the KILL's
 * outcome FIRST and refuses to report a stop when the kill did not
 * succeed.
 */
typedef enum {
    /* The zero value is UNKNOWN. */
    LATCH_GUEST_STOP_UNKNOWN = 0,
    /* The guest is gone: the kill succeeded and the child was reaped (or
     * there was no child to reap). */
    LATCH_GUEST_STOP_STOPPED = 1,
    /* The guest is STILL RUNNING: the reap said so.  This is NOT a stop. */
    LATCH_GUEST_STOP_RUNNING = 2,
    /* The kill failed with an errno other than `ESRCH`: the daemon could
     * not even ask the guest to stop. */
    LATCH_GUEST_STOP_FAILED  = 3,
    /* The reap was interrupted: the sequence established nothing and must
     * be run again. */
    LATCH_GUEST_STOP_RETRY   = 4,
} latch_guest_stop_outcome_t;

/*
 * THE KILL'S OUTCOME, on its own.
 *
 * `ESRCH` means there is no such process: the child is already gone, and
 * that is a SUCCESSFUL stop, not a failure.  Every other errno is a
 * failure -- the daemon could not ask the guest to stop, and it must not
 * report that it did.
 */
static inline latch_guest_stop_outcome_t latch_guest_kill_decide(int kill_rc,
                                                                  int kill_errno) {
    if (kill_rc == 0) {
        return LATCH_GUEST_STOP_STOPPED; /* the kill was delivered */
    }
    if (kill_errno == ESRCH) {
        return LATCH_GUEST_STOP_STOPPED; /* it is already gone */
    }
    return LATCH_GUEST_STOP_FAILED;
}

/*
 * THE COMBINED DECISION.
 *
 * The kill's outcome is examined FIRST: a stop is only "stopped" when the
 * kill was delivered (or was unnecessary) AND the reap established that
 * the child is gone.
 */
static inline latch_guest_stop_outcome_t latch_guest_stop_decide(
        latch_guest_stop_outcome_t kill,
        latch_guest_reap_outcome_t reap) {
    if (kill == LATCH_GUEST_STOP_FAILED) {
        return LATCH_GUEST_STOP_FAILED;
    }
    if (kill == LATCH_GUEST_STOP_UNKNOWN) {
        return LATCH_GUEST_STOP_UNKNOWN;
    }
    if (latch_guest_reap_retry(reap)) {
        return LATCH_GUEST_STOP_RETRY;
    }
    if (reap == LATCH_GUEST_REAP_RUNNING) {
        return LATCH_GUEST_STOP_RUNNING;
    }
    if (!latch_guest_reap_gone(reap)) {
        /* An unknown or failed reap establishes nothing. */
        return LATCH_GUEST_STOP_RETRY;
    }
    return LATCH_GUEST_STOP_STOPPED;
}

/* True only for a completed stop. */
static inline bool latch_guest_stop_complete(latch_guest_stop_outcome_t outcome) {
    return outcome == LATCH_GUEST_STOP_STOPPED;
}

/*
 * THE ERRNO A REFUSAL CARRIES.
 *
 * `EINVAL` for a malformed decision, `EPERM` for a failed kill (the daemon
 * could not do what it was asked to do) and `EAGAIN` for a retry.  The
 * success value is spelled 0 rather than `EOK`, because `EOK` is a QNX-only
 * name and this header is also compiled by a POSIX host test -- and 0 IS
 * what `EOK` is on QNX.
 */
#define LATCH_GUEST_CHILD_OK 0

static inline int latch_guest_stop_errno(latch_guest_stop_outcome_t outcome) {
    switch (outcome) {
    case LATCH_GUEST_STOP_STOPPED:
        return LATCH_GUEST_CHILD_OK;
    case LATCH_GUEST_STOP_RUNNING:
        return EBUSY;
    case LATCH_GUEST_STOP_RETRY:
        return EAGAIN;
    case LATCH_GUEST_STOP_FAILED:
        return EPERM;
    case LATCH_GUEST_STOP_UNKNOWN:
    default:
        return EINVAL;
    }
}

/* -------------------------------------------------------------------------
 * 4. THE SEQUENCE ITSELF, IN A PORTABLE FORM
 * -------------------------------------------------------------------------
 *
 * WHY THE SEQUENCE LIVES HERE AND NOT IN THE DAEMON
 * --------------------------------------------------
 * A host test that exercises a COPY of the daemon's logic proves that the
 * COPY works, which says nothing about the daemon.  So the sequence
 * itself -- the masked kill, then the masked reap, with the decisions
 * above -- is a SHIPPED function, and the daemon CALLS it.  The host test
 * then runs the very same code against a REAL child process.
 *
 * The function is portable POSIX (`sigprocmask`, `kill`, `waitpid`,
 * `nanosleep`), so it compiles for QNX and for the host alike.
 */
#include <signal.h>
#include <stdint.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * HOW LONG THE DAEMON WAITS FOR THE CORPSE, AND HOW OFTEN IT LOOKS.
 *
 * 200 polls of 10 ms is a two-second bound.  The bound exists because an
 * UNBOUNDED wait is a hang, and a daemon that hangs in its stop path
 * cannot report the failure that the hang represents.
 */
#define LATCH_GUEST_REAP_TRIES  200u
#define LATCH_GUEST_REAP_SLEEP_NS 10000000L /* 10 ms */

/*
 * BLOCK SIGCHLD, AND RETURN THE PREVIOUS MASK.
 *
 * The mask is what makes the sequence race-free, and it is taken ONCE, at
 * the top of the sequence, so that the kill and every poll of the reap
 * happen inside ONE region with no window between them.
 *
 * A signal generated while it is blocked is not LOST: it stays PENDING and
 * is delivered when the mask is restored.
 */
static inline bool latch_guest_block_sigchld(sigset_t *saved) {
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    return sigprocmask(SIG_BLOCK, &block, saved) == 0;
}

/* RESTORE THE PREVIOUS MASK. */
static inline void latch_guest_restore_mask(const sigset_t *saved) {
    (void)sigprocmask(SIG_SETMASK, saved, NULL);
}

/* WHAT TO STOP, AND HOW PATIENTLY. */
typedef struct {
    /* The child to stop.  A pid of 0 or less means "there is nothing to
     * stop", which is a SUCCESSFUL stop (the daemon is idempotent). */
    pid_t        pid;
    /* How many times to poll for the corpse before giving up. */
    unsigned int tries;
    /* How long to wait between polls, in nanoseconds. */
    long         sleep_ns;
} latch_guest_stop_request_t;

/* WHAT THE SEQUENCE ESTABLISHED. */
typedef struct {
    /* The combined outcome: stopped, running, failed or retry. */
    latch_guest_stop_outcome_t outcome;
    /* The reap's own outcome, for the diagnosis. */
    latch_guest_reap_outcome_t reap;
    /* The wait status, when the child was reaped. */
    uint32_t                   status;
    /* The errno the kill left behind (0 when it was delivered). */
    int                        kill_errno;
    /* The errno the LAST waitpid() left behind. */
    int                        wait_errno;
} latch_guest_stop_result_t;

/* -------------------------------------------------------------------------
 * 4a. THE SINGLE REAP
 * -------------------------------------------------------------------------
 *
 * The daemon asks "has the child exited?" on several paths, and the
 * question has to be asked under the mask for the same reason the stop
 * sequence is: so the handler cannot reap the child in the middle of the
 * question.
 *
 * The `errno` is READ HERE and carried in the result, because that is the
 * whole defect: `waitpid()` returning -1 does not say WHETHER the call
 * was interrupted or whether there was no such child, and only the errno
 * tells the two apart.
 */
typedef struct {
    latch_guest_reap_outcome_t outcome;
    /* The wait status, when the child was reaped. */
    uint32_t                   status;
    /* The errno the waitpid() left behind. */
    int                        wait_errno;
} latch_guest_reap_result_t;

static inline latch_guest_reap_result_t latch_guest_reap_once(pid_t pid) {
    latch_guest_reap_result_t res;
    res.outcome    = LATCH_GUEST_REAP_UNKNOWN;
    res.status     = 0u;
    res.wait_errno = 0;

    if (pid <= 0) {
        res.outcome = LATCH_GUEST_REAP_NO_CHILD;
        return res;
    }

    sigset_t saved;
    if (!latch_guest_block_sigchld(&saved)) {
        res.outcome    = LATCH_GUEST_REAP_ERROR;
        res.wait_errno = errno;
        return res;
    }

    int status = 0;
    errno = 0;
    pid_t r = waitpid(pid, &status, WNOHANG);
    res.wait_errno = errno;
    latch_guest_restore_mask(&saved);

    res.outcome = latch_guest_reap_decide((int)r, res.wait_errno);
    if (res.outcome == LATCH_GUEST_REAP_REAPED) {
        res.status = (uint32_t)status;
    }
    return res;
}

/*
 * THE STOP SEQUENCE.
 *
 * The order is the whole point: the child is KILLED before it is REAPED,
 * because a child's PID cannot be reused while it is an unreaped zombie
 * -- so reaping it first is exactly what makes the PID reusable, and the
 * `kill()` could then land on an unrelated process.
 *
 * And the outcome is DECIDED, never assumed: a reap that was INTERRUPTED
 * establishes nothing and the sequence asks to be retried, and a child
 * the reap says is STILL RUNNING is never reported as "stopped".
 */
static inline latch_guest_stop_result_t latch_guest_stop_sequence(
        const latch_guest_stop_request_t *req) {
    latch_guest_stop_result_t res;
    res.outcome    = LATCH_GUEST_STOP_UNKNOWN;
    res.reap       = LATCH_GUEST_REAP_UNKNOWN;
    res.status     = 0u;
    res.kill_errno = 0;
    res.wait_errno = 0;

    if (req == NULL || req->pid <= 0) {
        /* Nothing to stop: the daemon is idempotent, and this is a
         * SUCCESSFUL stop, not a failure. */
        res.outcome = LATCH_GUEST_STOP_STOPPED;
        res.reap    = LATCH_GUEST_REAP_NO_CHILD;
        return res;
    }

    sigset_t saved;
    if (!latch_guest_block_sigchld(&saved)) {
        res.outcome    = LATCH_GUEST_STOP_FAILED;
        res.kill_errno = errno;
        return res;
    }

    /* THE KILL COMES FIRST.  `ESRCH` means the child is already gone, and
     * that is a SUCCESSFUL stop; every other errno is a failure, and the
     * daemon must not report a stop it did not perform. */
    latch_guest_stop_outcome_t kill_outcome;
    if (kill(req->pid, SIGKILL) != 0) {
        res.kill_errno = errno;
        kill_outcome = latch_guest_kill_decide(-1, res.kill_errno);
    } else {
        kill_outcome = latch_guest_kill_decide(0, 0);
    }
    if (kill_outcome == LATCH_GUEST_STOP_FAILED) {
        latch_guest_restore_mask(&saved);
        res.outcome = LATCH_GUEST_STOP_FAILED;
        return res;
    }

    const unsigned int tries = (req->tries > 0u) ? req->tries : 1u;
    for (unsigned int i = 0u; i < tries; ++i) {
        int status = 0;
        errno = 0;
        pid_t r = waitpid(req->pid, &status, WNOHANG);
        res.wait_errno = errno;

        latch_guest_reap_outcome_t reap = latch_guest_reap_decide((int)r, res.wait_errno);
        latch_guest_stop_outcome_t outcome = latch_guest_stop_decide(kill_outcome, reap);

        if (reap == LATCH_GUEST_REAP_REAPED) {
            res.status = (uint32_t)status;
        }
        if (latch_guest_stop_complete(outcome)) {
            latch_guest_restore_mask(&saved);
            res.outcome = outcome;
            res.reap    = reap;
            return res;
        }
        /* Not complete yet.  The last failure is what the result carries:
         * the caller can distinguish "still running" from "the call was
         * interrupted". */
        res.outcome = outcome;
        res.reap    = reap;

        if (i + 1u < tries) {
            struct timespec ts;
            ts.tv_sec  = 0;
            ts.tv_nsec = req->sleep_ns;
            (void)nanosleep(&ts, NULL);
        }
    }

    latch_guest_restore_mask(&saved);
    return res;
}

#endif /* LATCH_GUEST_CHILD_H_ */
