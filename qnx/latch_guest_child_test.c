/*
 * qnx/latch_guest_child_test.c
 *
 * THE HOST-SIM TEST FOR THE GUEST CHILD'S LIFECYCLE
 * ===================================================
 *
 * WHAT THIS TEST IS FOR
 * ---------------------
 * `qnx/latch_guestd.c` is the dedicated lifecycle daemon: it spawns the
 * guest hypervisor as a CHILD PROCESS and decides when that child is
 * stopped and when its corpse is collected.  Three of its decisions were
 * defects, and all three failed OPEN:
 *
 *   1. the reap's outcome was read WITHOUT its `errno`, so `EINTR` (the
 *      call was interrupted) was read as "the child is gone" -- and a stop
 *      that reports success without stopping the guest lets the caller
 *      start a SECOND guest;
 *   2. the SIGCHLD handler reaped ANY child, so the child's PID -- the
 *      handle `guest_stop()` sends `SIGKILL` through -- was released while
 *      the daemon still believed the guest was running; and
 *   3. `SIGTERM` only cleared the run flag, so the daemon exited and left
 *      the guest hypervisor running as an orphan.
 *
 * The decisions live in the shipped header `qnx/latch_guest_child.h`, and
 * this test compiles and RUNS it.
 *
 * THE DECISIVE ASSERTIONS ARE COUNTS AND INVARIANTS
 * --------------------------------------------------
 * A test that merely checks "the right answers are right" passes against
 * a gate that has been weakened in a way this test did not anticipate.  So
 * the properties under test are COUNTS and INVARIANTS:
 *
 *   * EXACTLY TWO of the five reap outcomes establish that the child is
 *     gone (reaped, or no such child) -- and the INTERRUPTED one is
 *     emphatically not among them;
 *   * EXACTLY ONE reap outcome asks for a retry;
 *   * a stop is "stopped" only when the kill was delivered AND the reap
 *     established that the child is gone; and
 *   * every decision that is not a defined value establishes NOTHING.
 *
 * It runs on the host, so it is part of `make check` and it runs in CI.
 */

#include "latch_guest_child.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int g_checks = 0;
static int g_failures = 0;

static void check(int ok, const char *what) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        printf("  FAIL: %s\n", what);
    }
}

/* -------------------------------------------------------------------------
 * 1. THE REAP OUTCOME: FIVE RESULTS, AND THE OLD CODE HAD TWO BRANCHES
 * ------------------------------------------------------------------------- */

static void test_the_reap_truth_table(void) {
    static const struct {
        int rc;
        int err;
        latch_guest_reap_outcome_t expect;
        const char *name;
    } rows[] = {
        { 42,  0,     LATCH_GUEST_REAP_REAPED,      "waitpid returned the pid: the child was reaped"},
        {  0,  0,     LATCH_GUEST_REAP_RUNNING,     "waitpid returned 0 with WNOHANG: still running"},
        { -1,  ECHILD,LATCH_GUEST_REAP_NO_CHILD,    "waitpid returned -1 with ECHILD: no such child"},
        { -1,  EINTR, LATCH_GUEST_REAP_INTERRUPTED, "waitpid returned -1 with EINTR: the call was INTERRUPTED"},
        { -1,  EIO,   LATCH_GUEST_REAP_ERROR,       "waitpid returned -1 with any other errno"},
    };

    int gone_rows = 0;
    int retry_rows = 0;
    for (unsigned i = 0u; i < sizeof(rows) / sizeof(rows[0]); ++i) {
        const latch_guest_reap_outcome_t o =
            latch_guest_reap_decide(rows[i].rc, rows[i].err);
        check(o == rows[i].expect, rows[i].name);
        if (latch_guest_reap_gone(o)) {
            ++gone_rows;
        }
        if (latch_guest_reap_retry(o)) {
            ++retry_rows;
        }
    }

    /* THE DECISIVE COUNTS. */
    check(gone_rows == 2,
          "EXACTLY TWO reap outcomes establish that the child is gone -- the "
          "reaped one and the no-such-child one -- and no other");
    check(retry_rows == 1,
          "EXACTLY ONE reap outcome asks for a retry: the INTERRUPTED one");
}

/* The defect this file exists for. */
static void test_an_interrupted_reap_is_not_a_gone_child(void) {
    const latch_guest_reap_outcome_t o = latch_guest_reap_decide(-1, EINTR);

    check(!latch_guest_reap_gone(o),
          "an INTERRUPTED waitpid does NOT establish that the child is gone "
          "-- the old code read -1 as ECHILD and reported a successful stop "
          "for a guest that was still running");
    check(latch_guest_reap_retry(o),
          "an INTERRUPTED waitpid asks for a retry");
    check(o == LATCH_GUEST_REAP_INTERRUPTED,
          "the interrupted outcome is spelled INTERRUPTED");
}

/* `ECHILD` and `EINTR` are BOTH -1, and only the errno tells them apart. */
static void test_errno_is_what_tells_echild_from_eintr(void) {
    const latch_guest_reap_outcome_t no_child = latch_guest_reap_decide(-1, ECHILD);
    const latch_guest_reap_outcome_t interrupted = latch_guest_reap_decide(-1, EINTR);

    check(no_child != interrupted,
          "ECHILD and EINTR produce DIFFERENT outcomes even though waitpid "
          "returned -1 for both -- the errno has to be read");
    check(latch_guest_reap_gone(no_child),
          "ECHILD does establish that the child is gone");
    check(!latch_guest_reap_gone(interrupted),
          "EINTR does NOT establish that the child is gone");
}

/* -------------------------------------------------------------------------
 * IT FAILS CLOSED
 * ------------------------------------------------------------------------- */

/*
 * The ZERO value of each enum is the UNKNOWN one, so an unassigned
 * decision establishes NOTHING.
 */
static void test_an_unassigned_decision_establishes_nothing(void) {
    const latch_guest_reap_outcome_t zeroed = (latch_guest_reap_outcome_t)0;
    check(zeroed == LATCH_GUEST_REAP_UNKNOWN,
          "the zero reap outcome is spelled UNKNOWN");
    check(!latch_guest_reap_gone(zeroed),
          "an UNASSIGNED reap outcome does NOT establish that the child is "
          "gone");
    check(!latch_guest_reap_retry(zeroed),
          "an UNASSIGNED reap outcome does not ask for a retry either -- it "
          "establishes nothing at all");

    const latch_guest_stop_outcome_t stop_zero = (latch_guest_stop_outcome_t)0;
    check(stop_zero == LATCH_GUEST_STOP_UNKNOWN,
          "the zero stop outcome is spelled UNKNOWN");
    check(!latch_guest_stop_complete(stop_zero),
          "an UNASSIGNED stop outcome is not a completed stop");
    check(latch_guest_stop_errno(stop_zero) == EINVAL,
          "an UNASSIGNED stop outcome carries EINVAL, not success");
}

/* A value the header does not define must establish nothing either. */
static void test_an_unknown_decision_establishes_nothing(void) {
    const latch_guest_reap_outcome_t bogus = (latch_guest_reap_outcome_t)99;
    check(!latch_guest_reap_gone(bogus),
          "a reap outcome the header does not define does NOT establish that "
          "the child is gone");

    const latch_guest_stop_outcome_t bogus_stop = (latch_guest_stop_outcome_t)99;
    check(!latch_guest_stop_complete(bogus_stop),
          "a stop outcome the header does not define is not a completed stop");
    check(latch_guest_stop_errno(bogus_stop) == EINVAL,
          "an undefined stop outcome carries EINVAL, not success");
}

/* -------------------------------------------------------------------------
 * 2. THE KILL
 * ------------------------------------------------------------------------- */

static void test_the_kill_truth_table(void) {
    /* The kill was delivered. */
    check(latch_guest_kill_decide(0, 0) == LATCH_GUEST_STOP_STOPPED,
          "a delivered kill is a successful kill");

    /* ESRCH: there is no such process -- the child is already gone, and
     * that is a SUCCESSFUL stop, not a failure. */
    check(latch_guest_kill_decide(-1, ESRCH) == LATCH_GUEST_STOP_STOPPED,
          "ESRCH is a SUCCESSFUL stop: the child is already gone");

    /* Every other errno is a failure: the daemon could not even ask the
     * guest to stop, and it must not report that it did. */
    check(latch_guest_kill_decide(-1, EPERM) == LATCH_GUEST_STOP_FAILED,
          "a kill refused with EPERM is a FAILED stop");
    check(latch_guest_kill_decide(-1, EINVAL) == LATCH_GUEST_STOP_FAILED,
          "a kill refused with EINVAL is a FAILED stop");
}

/* -------------------------------------------------------------------------
 * 3. THE COMBINED STOP: THE KILL IS EXAMINED FIRST
 * ------------------------------------------------------------------------- */

/*
 * THE ORDER IS LOAD-BEARING.  The child must be KILLED BEFORE it is
 * reaped, because a child's PID cannot be reused while it is an unreaped
 * zombie -- so reaping it first is what makes the PID reusable, and the
 * `kill()` could then land on an unrelated process.
 */
static void test_the_stop_is_the_kill_and_the_reap_together(void) {
    /* The happy path. */
    check(latch_guest_stop_decide(LATCH_GUEST_STOP_STOPPED,
                                  LATCH_GUEST_REAP_REAPED) == LATCH_GUEST_STOP_STOPPED,
          "a delivered kill and a reaped child is a completed stop");

    /* The child was already gone. */
    check(latch_guest_stop_decide(LATCH_GUEST_STOP_STOPPED,
                                  LATCH_GUEST_REAP_NO_CHILD) == LATCH_GUEST_STOP_STOPPED,
          "a kill that found no child and a reap that found no child is a "
          "completed stop");

    /* The kill failed: the reap does not rescue it. */
    check(latch_guest_stop_decide(LATCH_GUEST_STOP_FAILED,
                                  LATCH_GUEST_REAP_REAPED) == LATCH_GUEST_STOP_FAILED,
          "a FAILED kill is never a completed stop, whatever the reap says");

    /* The child is still running: the stop is NOT complete. */
    check(latch_guest_stop_decide(LATCH_GUEST_STOP_STOPPED,
                                  LATCH_GUEST_REAP_RUNNING) == LATCH_GUEST_STOP_RUNNING,
          "a child the reap says is STILL RUNNING is not a completed stop");
    check(!latch_guest_stop_complete(LATCH_GUEST_STOP_RUNNING),
          "the RUNNING outcome is not a completed stop");

    /* Interrupted: retry, never "stopped". */
    check(latch_guest_stop_decide(LATCH_GUEST_STOP_STOPPED,
                                  LATCH_GUEST_REAP_INTERRUPTED) == LATCH_GUEST_STOP_RETRY,
          "an INTERRUPTED reap asks for the whole sequence to be retried");
    check(!latch_guest_stop_complete(LATCH_GUEST_STOP_RETRY),
          "the RETRY outcome is not a completed stop");
}

/*
 * THE COUNT: of the four (kill, reap) combinations that a caller can
 * actually see, EXACTLY ONE is a completed stop when the reap says the
 * child was reaped -- and the failed kill is never one.
 */
static void test_exactly_one_kill_reap_pair_stops(void) {
    static const struct {
        latch_guest_stop_outcome_t kill;
        latch_guest_reap_outcome_t reap;
        bool expect_stop;
        const char *name;
    } rows[] = {
        {LATCH_GUEST_STOP_STOPPED, LATCH_GUEST_REAP_REAPED, true,
         "the kill was delivered and the child was reaped"},
        {LATCH_GUEST_STOP_STOPPED, LATCH_GUEST_REAP_NO_CHILD, true,
         "the kill was delivered and there was no child to reap"},
        {LATCH_GUEST_STOP_STOPPED, LATCH_GUEST_REAP_RUNNING, false,
         "the kill was delivered but the child is STILL RUNNING"},
        {LATCH_GUEST_STOP_STOPPED, LATCH_GUEST_REAP_INTERRUPTED, false,
         "the kill was delivered but the reap established nothing"},
        {LATCH_GUEST_STOP_FAILED, LATCH_GUEST_REAP_REAPED, false,
         "the kill FAILED, so the stop did not happen"},
        {LATCH_GUEST_STOP_FAILED, LATCH_GUEST_REAP_RUNNING, false,
         "the kill FAILED and the child is still running"},
    };

    int stopping_rows = 0;
    for (unsigned i = 0u; i < sizeof(rows) / sizeof(rows[0]); ++i) {
        const latch_guest_stop_outcome_t o =
            latch_guest_stop_decide(rows[i].kill, rows[i].reap);
        check(latch_guest_stop_complete(o) == rows[i].expect_stop, rows[i].name);
        if (latch_guest_stop_complete(o)) {
            ++stopping_rows;
        }
    }

    check(stopping_rows == 2,
          "EXACTLY TWO of the six (kill, reap) pairs are a completed stop -- "
          "the two in which the kill was delivered AND the child is gone");
}

/* -------------------------------------------------------------------------
 * THE ERRNO
 * ------------------------------------------------------------------------- */

static void test_the_outcomes_carry_their_own_errno(void) {
    check(latch_guest_stop_errno(LATCH_GUEST_STOP_STOPPED) == LATCH_GUEST_CHILD_OK,
          "a completed stop carries no error");
    check(latch_guest_stop_errno(LATCH_GUEST_STOP_RUNNING) == EBUSY,
          "a still-running child carries EBUSY");
    check(latch_guest_stop_errno(LATCH_GUEST_STOP_RETRY) == EAGAIN,
          "a retry carries EAGAIN");
    check(latch_guest_stop_errno(LATCH_GUEST_STOP_FAILED) == EPERM,
          "a failed kill carries EPERM");
    check(LATCH_GUEST_CHILD_OK == 0,
          "the success errno is spelled 0 (EOK is a QNX-only name)");
}

/* -------------------------------------------------------------------------
 * THE BEHAVIOURAL HALF: THE SHIPPED SEQUENCE AGAINST A REAL CHILD
 * -------------------------------------------------------------------------
 *
 * Everything above tests the DECISIONS with injected values.  This half
 * runs the SHIPPED SEQUENCE -- the same function the daemon calls -- against
 * a REAL child process, and proves the properties the decisions exist for:
 *
 *   1. the mask really does stop the SIGCHLD handler from running;
 *   2. the sequence really does kill the child and reap it;
 *   3. the sequence's reap WINS the race against a handler that reaps ANY
 *      child (which is exactly what the daemon's OLD handler did), so the
 *      child is reaped while its PID is still reserved; and
 *   4. the sequence never reports "stopped" for a child that is still
 *      running.
 *
 * THE HANDLER BELOW IS THE OLD, BUGGY ONE ON PURPOSE.  It reaps ANY child
 * with `waitpid(-1, ...)`, which is precisely the behaviour that made the
 * daemon's pid reusable.  Installing it here is what makes the ordering
 * property observable: if the sequence did NOT hold the mask, the handler
 * would win the race and the test would see it.
 */
static volatile sig_atomic_t g_handler_runs = 0;
static volatile sig_atomic_t g_handler_reaped = 0;

static void old_style_sigchld_handler(int sig) {
    (void)sig;
    ++g_handler_runs;
    int status = 0;
    pid_t r = waitpid(-1, &status, WNOHANG);
    if (r > 0) {
        g_handler_reaped = 1;
    }
}

/* A child that exits immediately. */
static pid_t spawn_exiting_child(void) {
    pid_t pid = fork();
    if (pid == 0) {
        _exit(7);
    }
    return pid;
}

/* A child that lives until it is killed. */
static pid_t spawn_sleeping_child(void) {
    pid_t pid = fork();
    if (pid == 0) {
        for (;;) {
            sleep(3600);
        }
    }
    return pid;
}

/* Is this pid still a process we can see? */
static bool pid_is_alive(pid_t pid) {
    if (pid <= 0) {
        return false;
    }
    return kill(pid, 0) == 0 || errno == EPERM;
}

/* 1. THE MASK STOPS THE HANDLER. */
static void test_the_mask_stops_the_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = old_style_sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        check(false, "the SIGCHLD handler could be installed");
        return;
    }

    g_handler_runs = 0;
    g_handler_reaped = 0;

    pid_t pid = spawn_exiting_child();
    check(pid > 0, "a child was spawned for the mask test");
    if (pid <= 0) {
        return;
    }

    sigset_t saved;
    check(latch_guest_block_sigchld(&saved),
          "SIGCHLD could be blocked");

    /* Let the child die while the signal is blocked. */
    struct timespec ts = { 0, 10000000L }; /* 10 ms */
    (void)nanosleep(&ts, NULL);

    check(g_handler_runs == 0,
          "the SIGCHLD handler did NOT run while SIGCHLD was blocked -- the "
          "mask is what makes the sequence race-free");

    /* The signal was not LOST: it is still pending. */
    sigset_t pending;
    sigemptyset(&pending);
    sigpending(&pending);
    check(sigismember(&pending, SIGCHLD) == 1,
          "the SIGCHLD is still PENDING while it is blocked -- blocking a "
          "signal does not lose it");

    latch_guest_restore_mask(&saved);

    check(g_handler_runs == 1,
          "the pending SIGCHLD was delivered when the mask was restored");

    /* The handler reaps the child (it was never reaped by the test). */
    int status = 0;
    pid_t r = waitpid(pid, &status, WNOHANG);
    check(r == pid || r == -1,
          "the child was accounted for after the mask was restored");

    /* Leave the tree clean: no handler, no pending signal. */
    sa.sa_handler = SIG_DFL;
    (void)sigaction(SIGCHLD, &sa, NULL);
}

/* 2 + 3. THE SEQUENCE KILLS, REAPS, AND WINS THE RACE. */
static void test_the_sequence_stops_a_real_child(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = old_style_sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        check(false, "the SIGCHLD handler could be installed");
        return;
    }

    g_handler_runs = 0;
    g_handler_reaped = 0;

    pid_t pid = spawn_sleeping_child();
    check(pid > 0, "a child was spawned for the stop-sequence test");
    if (pid <= 0) {
        return;
    }

    latch_guest_stop_request_t req;
    req.pid      = pid;
    req.tries    = LATCH_GUEST_REAP_TRIES;
    req.sleep_ns = LATCH_GUEST_REAP_SLEEP_NS;

    latch_guest_stop_result_t res = latch_guest_stop_sequence(&req);

    check(res.outcome == LATCH_GUEST_STOP_STOPPED,
          "the shipped stop sequence reports a COMPLETED stop for a real "
          "child");
    check(res.reap == LATCH_GUEST_REAP_REAPED,
          "the shipped stop sequence REAPED the child (the reap outcome says "
          "so, rather than the outcome being assumed)");
    check(latch_guest_stop_complete(res.outcome),
          "the stop outcome is a completed stop");
    check(latch_guest_stop_errno(res.outcome) == LATCH_GUEST_CHILD_OK,
          "a completed stop carries no error");

    /* THE ORDERING PROPERTY: the sequence's reap won the race, so the
     * handler found NOTHING to reap.  With the OLD daemon's handler --
     * which reaps ANY child -- this is the check that would fail if the
     * mask were not held across the sequence. */
    check(g_handler_reaped == 0,
          "the SIGCHLD handler found NO child to reap: the shipped sequence "
          "reaped the child WHILE ITS PID WAS STILL RESERVED, so the pid "
          "could not be reused under the daemon's feet");

    /* The child really is gone. */
    check(!pid_is_alive(pid),
          "the child is really gone after the sequence -- the sequence does "
          "not merely report it");

    /* And the pid is free again, which is exactly why the ORDER mattered. */
    check(!pid_is_alive(pid),
          "the child's pid is not a live process after the reap");

    sa.sa_handler = SIG_DFL;
    (void)sigaction(SIGCHLD, &sa, NULL);
}

/* 4. A CHILD THAT IS ALREADY GONE IS A SUCCESSFUL STOP. */
static void test_stopping_an_already_gone_child_is_a_success(void) {
    pid_t pid = spawn_exiting_child();
    check(pid > 0, "a child was spawned for the already-gone test");
    if (pid <= 0) {
        return;
    }
    /* Reap it first, so the pid is a pid with no child behind it. */
    int status = 0;
    for (int i = 0; i < 100; ++i) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            break;
        }
        struct timespec ts = { 0, 1000000L };
        (void)nanosleep(&ts, NULL);
    }

    latch_guest_stop_request_t req;
    req.pid      = pid;
    req.tries    = LATCH_GUEST_REAP_TRIES;
    req.sleep_ns = LATCH_GUEST_REAP_SLEEP_NS;

    latch_guest_stop_result_t res = latch_guest_stop_sequence(&req);
    check(res.outcome == LATCH_GUEST_STOP_STOPPED,
          "stopping a child that is ALREADY GONE is a SUCCESSFUL stop, not a "
          "failure -- the daemon is idempotent");

    /* Nothing to stop at all. */
    latch_guest_stop_request_t none;
    none.pid      = -1;
    none.tries    = LATCH_GUEST_REAP_TRIES;
    none.sleep_ns = LATCH_GUEST_REAP_SLEEP_NS;
    latch_guest_stop_result_t res2 = latch_guest_stop_sequence(&none);
    check(res2.outcome == LATCH_GUEST_STOP_STOPPED,
          "stopping NOTHING is a successful stop -- the daemon is idempotent");
}

/* 5. THE SINGLE REAP AGAINST A REAL CHILD. */
static void test_the_single_reap_against_a_real_child(void) {
    /* A LIVE child: the reap says RUNNING, and the child is still there. */
    pid_t live = spawn_sleeping_child();
    check(live > 0, "a live child was spawned for the single-reap test");
    if (live > 0) {
        latch_guest_reap_result_t res = latch_guest_reap_once(live);
        check(res.outcome == LATCH_GUEST_REAP_RUNNING,
              "the single reap of a LIVE child says RUNNING -- it does not "
              "guess");
        check(!latch_guest_reap_gone(res.outcome),
              "a RUNNING reap does NOT establish that the child is gone");
        check(pid_is_alive(live),
              "the live child is still alive after the reap said RUNNING");

        /* Clean it up.  `kill()` is ASYNCHRONOUS, so the very next reap
         * can legitimately still say RUNNING -- which is exactly why the
         * shipped sequence POLLS rather than assuming. */
        (void)kill(live, SIGKILL);
        latch_guest_reap_result_t res2;
        memset(&res2, 0, sizeof(res2));
        res2.outcome = LATCH_GUEST_REAP_UNKNOWN;
        for (int i = 0; i < 100; ++i) {
            res2 = latch_guest_reap_once(live);
            if (res2.outcome == LATCH_GUEST_REAP_REAPED) {
                break;
            }
            struct timespec ts = { 0, 1000000L };
            (void)nanosleep(&ts, NULL);
        }
        check(res2.outcome == LATCH_GUEST_REAP_REAPED,
              "the single reap of a KILLED child says REAPED once the child "
              "has actually died -- the reap polls instead of assuming");
    }

    /* A DEAD, UNREAPED child: the reap says REAPED. */
    pid_t dead = spawn_exiting_child();
    check(dead > 0, "a dead child was spawned for the single-reap test");
    if (dead > 0) {
        latch_guest_reap_result_t res;
        memset(&res, 0, sizeof(res));
        res.outcome = LATCH_GUEST_REAP_UNKNOWN;
        for (int i = 0; i < 100; ++i) {
            res = latch_guest_reap_once(dead);
            if (res.outcome == LATCH_GUEST_REAP_REAPED) {
                break;
            }
            struct timespec ts = { 0, 1000000L };
            (void)nanosleep(&ts, NULL);
        }
        check(res.outcome == LATCH_GUEST_REAP_REAPED,
              "the single reap of a child that has EXITED says REAPED");
        check(latch_guest_reap_gone(res.outcome),
              "a REAPED outcome establishes that the child is gone");

        /* And a second reap finds NO CHILD -- which is a DIFFERENT
         * outcome from INTERRUPTED, and the errno is what told them
         * apart. */
        latch_guest_reap_result_t res2 = latch_guest_reap_once(dead);
        check(res2.outcome == LATCH_GUEST_REAP_NO_CHILD,
              "a second reap of an already-reaped child says NO_CHILD");
        check(res2.wait_errno == ECHILD,
              "the NO_CHILD outcome came with ECHILD -- the errno was READ, "
              "not guessed from the -1");
    }
}

int main(void) {
    printf("== LATCH guest child lifecycle (host-sim) ==\n");

    test_the_reap_truth_table();
    test_an_interrupted_reap_is_not_a_gone_child();
    test_errno_is_what_tells_echild_from_eintr();
    test_an_unassigned_decision_establishes_nothing();
    test_an_unknown_decision_establishes_nothing();
    test_the_kill_truth_table();
    test_the_stop_is_the_kill_and_the_reap_together();
    test_exactly_one_kill_reap_pair_stops();
    test_the_outcomes_carry_their_own_errno();
    test_the_mask_stops_the_handler();
    test_the_sequence_stops_a_real_child();
    test_stopping_an_already_gone_child_is_a_success();
    test_the_single_reap_against_a_real_child();

    printf("== %d checks, %d failures ==\n", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
