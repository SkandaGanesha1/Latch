/*
 * qnx/latch_guestd.c
 *
 * LATCH — Guest Lifecycle Supervisor (QNX SDP 8.0)
 *
 * WHAT THIS PROCESS IS
 * --------------------
 * A narrowly-typed resource manager that OWNS the guest VM process and
 * exposes exactly two mutating operations on a dedicated channel:
 *
 *     /dev/latch/guestctl   (channel type `guest_ctl_t`)
 *
 *   DCMD_LATCH_GUEST_STOP  (0x48)  kill the guest VM child and wait for it
 *   DCMD_LATCH_GUEST_START (0x49)  spawn a new guest VM child
 *   DCMD_LATCH_GET_GUEST_STATUS (0x4A)  read-only state
 *
 * WHY IT EXISTS (measured on the QEMU AArch64 target, 2026-11-25)
 * --------------------------------------------------------------
 *   - `slay -9 qvm` from the operator shell WORKS, and the writer-session
 *     handoff is observable (the ingest sees EOF, exits, and the supervisor
 *     reports `Writer Held : 0`).
 *   - `on -T qvm_host_t ... qvm @qvmconf` is REFUSED with
 *     `on: Operation not permitted`, because `operator_shell_t` holds no
 *     `settypeid` and no `spawn`.
 *
 * So the operator shell can stop the guest but not start it.  Granting the
 * operator shell `settypeid:qvm_host_t` would fix that and would also
 * destroy the "the operator shell is deliberately unprivileged" property
 * that the EPERM demonstration depends on.  This process keeps the
 * hypervisor-spawning privilege in ONE typed domain (`latch_guestd_t`)
 * that holds NO actuator ability, NO proposal-write right, and NO ability
 * to connect to the supervisor's own channels.
 *
 * WHY STOP AND START ARE SEPARATE
 * -------------------------------
 * A server-side "restart" that killed the guest and immediately respawned it
 * would RACE the writer handoff: the new guest's ingest opens the proposal
 * node, and if the old ingest has not yet released the exclusive writer
 * OCB, that open is refused with EBUSY and the guest silently never streams
 * again.  A handoff must be OBSERVED, never timed.  The client therefore
 * performs STOP -> observe the supervisor's session status -> START, and
 * refuses to START if the handoff was not observed.  There is deliberately
 * NO single-shot server-side "restart" that skips that observation.
 *
 * FAIL CLOSED
 * -----------
 * Every failure path here reports a status and leaves the system in the
 * safe state:
 *
 *   - If the guest binary or configuration is missing, latch_guestd does
 *     NOT silently run without a guest: it refuses to start, says why, and
 *     exits non-zero.  The supervisor then degrades to LATCH on its own.
 *   - If the type transition is refused by the security policy, the child
 *     is NOT spawned with a weaker type.  The spawn fails and is reported.
 *   - If the guest child cannot be reaped after SIGKILL, the daemon
 *     reports the failure instead of spawning a second guest alongside the
 *     first.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/iomsg.h>
#include <sys/neutrino.h>
#include <sys/procmgr.h>
#include <sys/resmgr.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <secpol/secpol.h>

#include "latch_protocol.h"

/* THE GUEST-CONTROL GATE (C-7).
 *
 * The decision -- "may this open mutate the guest's state?" -- lives in
 * this SHIPPED header, so the resource manager and the host test exercise
 * the same code.  The two checks it makes are INDEPENDENT: the open must
 * carry `_IO_FLAG_WR`, and the client must hold the dedicated
 * `latch/guestctl` ability. */
#include "latch_guestctl_guard.h"
#include "latch_guest_child.h"

/* THE RESOURCE MANAGER'S ATTRIBUTE LOCK.  Every iofunc entry point this
 * resource manager calls goes through the wrappers in this header, so
 * the iofunc call is made while the device's SHARED attribute (the
 * file-use count, the reader and writer counts) is locked.  The iofunc
 * library updates those counters with a NON-ATOMIC 16-bit
 * read-modify-write, so two concurrent opens of the same node can lose
 * an increment -- and the dispatch channel is created with
 * `DISPATCH_FLAG_NOLOCK`, which is exactly what allows two messages to
 * be in flight at the same time. */
#include "latch_rm_attr.h"

/* The QNX type the guest VM is spawned into.  The child inherits the
 * hypervisor abilities it needs (hyp, mem_phys, io, interrupt, ...) from
 * the policy, exactly as it did when the boot script started it directly. */
#define LATCH_GUEST_TYPE_NAME "qvm_host_t"

/* How long to wait for a SIGKILLed guest child to be reaped.  A process
 * that cannot be reaped within this bound is reported as a failure; the
 * daemon never spawns a second guest while the first may still exist.
 *
 * THE TWO CONSTANTS LIVE IN THE SHIPPED HEADER (NEW-3), because the
 * shipped stop sequence uses them and the host test has to use the SAME
 * ones -- a test with a different bound proves a different thing. */

/* -------------------------------------------------------------------------
 * Device attributes
 * ------------------------------------------------------------------------- */
typedef struct latch_guest_attr {
    iofunc_attr_t attr;
} latch_guest_attr_t;

static latch_guest_attr_t g_guest_attr;

/* -------------------------------------------------------------------------
 * Daemon state
 * ------------------------------------------------------------------------- */
/*
 * THE CHILD'S PID IS SHARED WITH THE SIGNAL HANDLER, SO IT IS A
 * `volatile sig_atomic_t` (NEW-3).
 *
 * The SIGCHLD handler WRITES this variable (`g_guest_pid = -1` when it
 * reaps the child), and the control path READS it -- in the status
 * report, in the spawn check and in the stop sequence.  POSIX says the
 * only objects a signal handler may touch are `sig_atomic_t` ones, and
 * `volatile` keeps the compiler from caching the value in a register
 * across the read.
 *
 * On QNX `sig_atomic_t` is `int` and `pid_t` is an `int`-sized type, so
 * the pid fits.  The access is a SINGLE aligned store or load, which is
 * atomic on AArch64; and the windows in which the CONTROL path touches
 * the pid are masked against the handler anyway, so the handler cannot
 * observe a half-published child.
 */
static volatile sig_atomic_t g_guest_pid = -1;
static uint32_t    g_generation    = 0u;
/*
 * THE LAST EXIT STATUS IS SHARED WITH THE SIGNAL HANDLER TOO, SO IT IS
 * A `volatile sig_atomic_t` AS WELL (NEW-3).
 *
 * POSIX says a signal handler may refer to NO object other than a
 * `volatile sig_atomic_t` one (and `errno`, and only if it restores it).
 * The handler WRITES this variable, so a plain `uint32_t` is undefined
 * behaviour by the letter of the standard -- and the standard is the
 * right thing to obey even where the hardware would get away with it.
 *
 * The value is a `waitpid()` status word, which is 16 bits wide on both
 * QNX and Linux, so it fits in an `int`-sized `sig_atomic_t` without
 * loss.  The bit pattern is preserved on the way back out to the
 * protocol's `uint32_t` field.
 */
static volatile sig_atomic_t g_last_exit = 0;
static char        g_qvm_path[256] = {0};
static char        g_conf_path[256] = {0};
static char        g_conf_arg[272] = {0};
static volatile sig_atomic_t g_running = 1;

/*
 * THE TERMINATION FLAG (NEW-3).
 *
 * `SIGTERM` and `SIGINT` used to clear `g_running` and nothing else, so
 * the daemon detached and exited -- and the guest hypervisor, which is the
 * daemon's own CHILD, kept running as an ORPHAN.  A lifecycle daemon
 * whose death leaves the thing it manages running is not a lifecycle
 * daemon.
 *
 * The handler cannot do the stop work itself: `guest_stop()` prints,
 * sleeps and calls `waitpid()`, none of which is async-signal-safe.  So
 * the handler sets a FLAG and the MAIN path performs the stop, after the
 * dispatch loop has ended.  This is the same shape the guest-control gate
 * uses: the signal says WHAT happened, and the ordinary code decides what
 * to do about it.
 */
static volatile sig_atomic_t g_terminate = 0;

/* The dedicated `latch/guestctl` ability (C-7).  It is created by the
 * daemon at start-up with flags 0 -- neither root nor non-root receives it
 * by default -- so the ONLY way to hold it is to be granted it by name in
 * the security policy.  That is what makes it a grant rather than a
 * default: a type that can CONNECT to the guest-control channel does not
 * thereby gain the power to stop the guest. */
static int         g_ability_guestctl_id = -1;

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

/*
 * THE SIGCHLD MASK (NEW-3).
 *
 * This is the mechanism that makes the child's lifecycle race-free, and
 * it is the whole fix in one function.
 *
 * THE PROBLEM.  The daemon's SIGCHLD handler runs asynchronously, and it
 * used to reap ANY child with `waitpid(-1, ...)`.  Two consequences
 * followed:
 *
 *   * the handler could run INSIDE the control path's own `waitpid()` --
 *     the handler is installed WITHOUT `SA_RESTART`, so the interrupted
 *     call returned `-1` with `errno == EINTR`, and the old code read that
 *     as "there is no such child", concluded the guest was GONE, and
 *     reported a successful stop for a guest that was still running; and
 *
 *   * the handler could reap the child BETWEEN the control path's read of
 *     `g_guest_pid` and its `kill()`.  **A child's PID cannot be reused
 *     while it is an unreaped zombie**, so reaping it is exactly what
 *     makes the PID reusable -- and the `kill()` could then land on an
 *     unrelated process.
 *
 * THE FIX.  Hold SIGCHLD blocked across every window in which the child's
 * PID is touched: the spawn window, the kill, and every `waitpid()`.  The
 * handler then cannot run inside any of them, so:
 *
 *   * the `waitpid()` cannot be interrupted by SIGCHLD (the `EINTR` case
 *     disappears at the source, and the code reads `errno` anyway);
 *   * the handler and the control path can never reap the same child; and
 *   * the ORDER is enforceable -- the child is KILLED before it is
 *     reaped, so its PID is still reserved when the `kill()` goes out.
 *
 * The daemon has exactly ONE thread that can receive a signal (the
 * dispatch loop), so blocking the signal in that thread also blocks the
 * handler.  The handler's own `waitpid()` tolerates `ECHILD` as well, so
 * even a second reaper would be harmless.
 *
 * THE MASK ITSELF LIVES IN THE SHIPPED HEADER (NEW-3), because the host
 * test has to be able to exercise it against a REAL child process:
 * `latch_guest_block_sigchld()` / `latch_guest_restore_mask()` out of
 * `qnx/latch_guest_child.h`.  There is ONE implementation of the mask in
 * the tree, and the daemon calls it.
 */
static void guest_sig_handler(int sig) {
    (void)sig;
    g_running = 0;
    g_terminate = 1;
}

/*
 * Reap the guest child as soon as it dies.
 *
 * Without this, an operator's `slay -9 qvm` would leave a ZOMBIE guest in
 * the process table until the next control request arrived -- and a
 * transcript that claims "the guest VM is completely purged from memory"
 * while a defunct entry is still listed is not a transcript anyone should
 * trust.
 *
 * The handler is async-signal-safe: `waitpid()` is, and every variable it
 * touches is either a `sig_atomic_t` or a value whose update is a single
 * aligned store.
 *
 * IT REAPS THE GUEST CHILD AND NOTHING ELSE (NEW-3).  The old code reaped
 * ANY child with `waitpid(-1, ...)`, which needed a whole "pending"
 * side-channel to carry a reap that arrived before the spawn site could
 * record the pid -- a SINGLE slot, which could lose a reap and could match
 * a REUSED pid.  The mask removes that window (the pid is recorded under
 * the mask), so the side-channel is not needed and the handler no longer
 * touches children that are not the guest's.
 */
static void guest_sigchld_handler(int sig) {
    (void)sig;
    /* A handler that calls a function which can set `errno` MUST save and
     * restore it: the interrupted code may be about to read it.  The
     * QNX 8.0 C Library Reference lists `waitpid()` as setting `errno`,
     * so this handler saves it around its own call. */
    int saved_errno = errno;

    pid_t pid = g_guest_pid;
    if (pid <= 0) {
        errno = saved_errno;
        return;                 /* nothing of ours to reap */
    }
    int status = 0;
    pid_t r = waitpid(pid, &status, WNOHANG);
    if (r == pid) {
        g_last_exit = (sig_atomic_t)status;
        g_guest_pid = -1;
    }
    /* `r == 0` -> still running.  `r == -1` -> nothing to reap (the
     * control path got there first) or the call failed; either way the
     * next control request reaps it. */
    errno = saved_errno;
}

/*
 * Reap the guest child if it has exited.
 *
 * Returns 1 if a child was reaped (and updates g_last_exit), 0 if the child
 * is still alive -- or if the attempt established NOTHING -- and -1 if there
 * is no child at all.
 *
 * THE OUTCOME IS DECIDED BY THE SHIPPED HEADER (NEW-3).  `waitpid()`'s
 * return value alone does not distinguish "there is no such child"
 * (`ECHILD`) from "the call was interrupted" (`EINTR`) -- both are -1 --
 * and the old code read BOTH as "the child is gone".  A stop that reports
 * success without stopping the guest lets the caller start a SECOND guest,
 * and two guests fight over the same virtio-console endpoint.
 */
static int guest_reap_if_exited(void) {
    pid_t pid = g_guest_pid;
    if (pid <= 0) {
        return -1;
    }

    /* THE REAP IS THE SHIPPED ONE (NEW-3): the mask, the `waitpid()` and
     * the reading of the `errno` are all in
     * `qnx/latch_guest_child.h`, so the host test exercises the very same
     * code the daemon runs. */
    latch_guest_reap_result_t res = latch_guest_reap_once(pid);

    switch (res.outcome) {
    case LATCH_GUEST_REAP_REAPED:
        g_last_exit = (sig_atomic_t)res.status;
        g_guest_pid = -1;
        return 1;
    case LATCH_GUEST_REAP_NO_CHILD:
        g_guest_pid = -1;
        return 1;
    case LATCH_GUEST_REAP_RUNNING:
        return 0;
    case LATCH_GUEST_REAP_INTERRUPTED:
        /* The call established NOTHING: ask again.  It is emphatically not
         * "the child is gone". */
        return 0;
    case LATCH_GUEST_REAP_ERROR:
    default:
        fprintf(stderr, "latch_guestd: waitpid(%d) failed: %s\n",
                (int)pid, strerror(res.wait_errno));
        return 0;
    }
}

/*
 * Spawn the guest VM.
 *
 * The child is given the `qvm_host_t` security type through the documented
 * libsecpol spawn-attribute API.  If the policy refuses the transition, the
 * spawn FAILS: the daemon does not fall back to running the hypervisor in
 * its own (weaker) type, and it does not run the guest untyped.
 */
static int guest_spawn(void) {
    /*
     * THE WHOLE SPAWN WINDOW IS ONE MASKED REGION (NEW-3).
     *
     * The old code had a whole side-channel for the window between
     * `posix_spawn()` returning the pid and the daemon recording it: the
     * SIGCHLD handler could fire in that window, reap the child, and park
     * the pid in a "pending" slot -- a SINGLE slot, which could lose a
     * reap and could match a REUSED pid.  With SIGCHLD blocked across the
     * window, the handler cannot run until the pid has been recorded, and
     * the side-channel is not needed at all.
     *
     * The signal is not LOST by the mask: a signal generated while it is
     * blocked stays PENDING and is delivered when the mask is restored.
     *
     * The mask is taken HERE, before the "a guest is already running"
     * check, so that the whole region -- the check, the spawn and the
     * recording of the pid -- is ONE region with no window in it.  The
     * check itself is the first thing the function does, because it is the
     * check that prevents TWO guests from fighting over the same
     * virtio-console endpoint.
     */
    sigset_t saved;
    if (!latch_guest_block_sigchld(&saved)) {
        fprintf(stderr, "latch_guestd: sigprocmask(SIG_BLOCK, SIGCHLD) failed: %s\n",
                strerror(errno));
        return errno;
    }

    if (g_guest_pid > 0) {
        /* The reap runs under the mask we already hold. */
        (void)guest_reap_if_exited();
        if (g_guest_pid > 0) {
            fprintf(stderr, "latch_guestd: a guest VM is already running (pid %d)\n",
                    (int)g_guest_pid);
            latch_guest_restore_mask(&saved);
            return EBUSY;
        }
    }

    if (access(g_qvm_path, X_OK) != 0) {
        fprintf(stderr, "latch_guestd: guest binary '%s' is missing or not executable: %s\n",
                g_qvm_path, strerror(errno));
        latch_guest_restore_mask(&saved);
        return ENOENT;
    }
    if (access(g_conf_path, R_OK) != 0) {
        fprintf(stderr, "latch_guestd: guest configuration '%s' is missing: %s\n",
                g_conf_path, strerror(errno));
        latch_guest_restore_mask(&saved);
        return ENOENT;
    }

    posix_spawnattr_t attr;
    int rc = posix_spawnattr_init(&attr);
    if (rc != 0) {
        fprintf(stderr, "latch_guestd: posix_spawnattr_init: %s\n", strerror(rc));
        latch_guest_restore_mask(&saved);
        return rc;
    }

    /*
     * Set the child's security type.  `SECPOL_TYPE_NAME` selects the type by
     * its literal name instead of deriving it.  If no policy is in force
     * this call is a no-op and the child simply inherits our type, which is
     * the correct behaviour for an un-enforced development image.
     */
    rc = secpol_posix_spawnattr_settypeid(NULL, &attr, LATCH_GUEST_TYPE_NAME,
                                           SECPOL_TYPE_NAME);
    if (rc != 0) {
        /*
         * FAIL LOUDLY.  A refused type transition means the policy does not
         * permit this daemon to start the hypervisor; running the guest
         * anyway would run it in the WRONG domain.  The daemon refuses and
         * the supervisor degrades to LATCH on its own.
         */
        fprintf(stderr, "latch_guestd: cannot set the child's security type to '%s': %s\n",
                LATCH_GUEST_TYPE_NAME, strerror(errno));
        posix_spawnattr_destroy(&attr);
        latch_guest_restore_mask(&saved);
        return EPERM;
    }

    char *argv[3];
    argv[0] = g_qvm_path;
    argv[1] = g_conf_arg;
    argv[2] = NULL;

    pid_t pid = -1;
    rc = posix_spawn(&pid, g_qvm_path, NULL, &attr, argv, environ);
    if (rc == 0) {
        /* The pid is RECORDED UNDER THE SAME MASK, so the handler cannot
         * observe a half-published child. */
        g_guest_pid = pid;
    }
    latch_guest_restore_mask(&saved);

    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        fprintf(stderr, "latch_guestd: posix_spawn('%s'): %s\n", g_qvm_path, strerror(rc));
        return rc;
    }

    g_generation++;

    /*
     * THE CHILD MAY HAVE DIED ALREADY (NEW-3).
     *
     * The old code detected this through the "pending" side-channel: if
     * the SIGCHLD handler had already reaped THIS pid by the time the
     * spawn site got here, the daemon recorded the exit status, reported
     * the failure and left the guest DOWN -- so the caller failed closed
     * instead of believing it started a guest that was not there.
     *
     * The side-channel is gone, and the MASK makes it unnecessary: a
     * signal generated while SIGCHLD was blocked stays PENDING, so the
     * moment the mask is restored the child -- if it died -- is either
     * already accounted for by the handler or is about to be.  So the
     * question is asked AFTER the mask is restored, with the SHIPPED
     * reap: has the child already gone?
     *
     * There are two ways the answer can be "yes", and both of them are
     * covered:
     *
     *   * the handler ran when the mask was restored and reaped the
     *     child, so `g_guest_pid` is already -1; or
     *   * the handler has not run yet, and the shipped reap finds the
     *     corpse itself (`waitpid()` returns the pid).
     *
     * Either way the daemon must NOT keep pointing at a dead child, and
     * it must NOT report a start it cannot vouch for.  A guest that
     * exits immediately -- because the hypervisor could not be exec'd,
     * or because the configuration was refused -- is exactly the case
     * this check exists for, and the client's "start" must fail.
     *
     * An INTERRUPTED reap establishes NOTHING (that is the whole point
     * of the shipped decision), so it is not treated as "the child is
     * gone": the start is reported and the truth is established by the
     * next status report.  The only case in which the daemon refuses is
     * the case in which the child's corpse has actually been seen.
     */
    if (guest_reap_if_exited() != 0) {
        fprintf(stderr, "latch_guestd: guest VM (pid %d) exited immediately "
                        "(status 0x%X); the guest is NOT running.\n",
                (int)pid, (unsigned int)g_last_exit);
        return ECHILD;
    }

    printf("latch_guestd: guest VM started (pid %d, generation %u) argv: '%s' '%s'\n",
           (int)pid, (unsigned int)g_generation, g_qvm_path, g_conf_arg);
    fflush(stdout);
    return EOK;
}

/*
 * Stop the guest VM and wait for it to actually be gone.
 *
 * The wait is bounded.  If the child cannot be reaped within the bound the
 * daemon reports the failure and does NOT start another guest, because two
 * live guests would fight over the same virtio-console endpoint.
 *
 * THE KILL AND THE REAP ARE ONE MASKED SEQUENCE (NEW-3).
 *
 * The ORDER is load-bearing: the child must be KILLED BEFORE it is
 * reaped, because a child's PID cannot be reused while it is an unreaped
 * zombie -- so reaping it first is exactly what makes the PID reusable,
 * and the `kill()` could then land on an unrelated process.  Holding
 * SIGCHLD blocked across the whole sequence is what enforces that order
 * against the asynchronous handler.
 *
 * And the outcome is DECIDED, not assumed: a reap that was INTERRUPTED
 * establishes nothing and the sequence is retried, and a child the reap
 * says is STILL RUNNING is never reported as "stopped".
 *
 * THE SEQUENCE ITSELF IS THE SHIPPED ONE (NEW-3).  The daemon does not
 * re-implement it: it calls `latch_guest_stop_sequence()` out of
 * `qnx/latch_guest_child.h`, which is the same function the host test
 * runs against a REAL child process.  A daemon whose stop path could
 * drift from the tested logic would make the test a proof of nothing.
 */
static int guest_stop(void) {
    latch_guest_stop_request_t req;
    req.pid      = g_guest_pid;
    req.tries    = LATCH_GUEST_REAP_TRIES;
    req.sleep_ns = LATCH_GUEST_REAP_SLEEP_NS;

    latch_guest_stop_result_t res = latch_guest_stop_sequence(&req);

    if (res.outcome == LATCH_GUEST_STOP_STOPPED) {
        if (res.reap == LATCH_GUEST_REAP_REAPED) {
            g_last_exit = (sig_atomic_t)res.status;
        }
        g_guest_pid = -1;
        printf("latch_guestd: guest VM stopped (pid %d, status 0x%X)\n",
               (int)req.pid, (unsigned int)g_last_exit);
        fflush(stdout);
        return EOK;
    }

    if (res.outcome == LATCH_GUEST_STOP_FAILED) {
        fprintf(stderr, "latch_guestd: kill(%d): %s\n",
                (int)req.pid, strerror(res.kill_errno));
    } else if (res.outcome == LATCH_GUEST_STOP_RUNNING) {
        fprintf(stderr, "latch_guestd: guest VM (pid %d) did not exit within "
                        "the reap bound\n", (int)req.pid);
    } else {
        /* The sequence established NOTHING -- e.g. the reap was
         * INTERRUPTED.  It is emphatically not a stop, and the daemon says
         * so rather than reporting a success it did not earn. */
        fprintf(stderr, "latch_guestd: the stop of the guest VM (pid %d) "
                        "established nothing (reap outcome %d, wait errno %s); "
                        "it may still be running.\n",
                (int)req.pid, (int)res.reap,
                res.wait_errno ? strerror(res.wait_errno) : "none");
    }
    return latch_guest_stop_errno(res.outcome);
}

static void guest_fill_status(latch_guest_status_t *st) {
    memset(st, 0, sizeof(*st));
    st->struct_size = (uint32_t)sizeof(*st);
    (void)guest_reap_if_exited();
    /* ONE read of the shared pid, so the two uses below cannot disagree
     * with each other: `running` and `pid` must describe the SAME
     * instant.  (NEW-3) */
    int32_t pid = (g_guest_pid > 0) ? (int32_t)g_guest_pid : -1;
    st->running = (pid > 0) ? 1u : 0u;
    st->generation = g_generation;
    st->last_exit_status = (uint32_t)g_last_exit;
    st->pid = pid;
}

/* -------------------------------------------------------------------------
 * Resource manager
 * ------------------------------------------------------------------------- */

/*
 * THE MUTATION AUTHORITY CHECK (C-7).
 *
 * Two INDEPENDENT checks, and the decision lives in the shipped header
 * `qnx/latch_guestctl_guard.h` so that the host test exercises the same
 * code the resource manager runs:
 *
 *   1. THE WRITE FLAG.  The open that carries this devctl must have been
 *      opened for writing (`_IO_FLAG_WR`).  This is what separates MUTATE
 *      from OBSERVE: a read-only open can read the guest's status and can
 *      do nothing else.  It is checked on the OCB's ioflag, so it cannot
 *      be spoofed by the message.
 *
 *   2. THE ABILITY.  The client must hold the dedicated `latch/guestctl`
 *      ability.  This is what separates a NAMED, REVOCABLE GRANT from an
 *      IMPLICIT CONNECT: the channel-connect rule says who may talk to
 *      the daemon, and the ability says who may change the guest.
 *
 * NEITHER CHECK IMPLIES THE OTHER, and there are four combinations of
 * them, of which exactly ONE allows the mutation.  `latchctl` therefore
 * opens the node `O_WRONLY` for the mutating verbs and `O_RDONLY` for the
 * read-only one.
 *
 * IT FAILS CLOSED: if the ability cannot be established, the request is
 * REFUSED -- exactly like a client that demonstrably lacks it.
 */
static int guest_require_mutation_authority(resmgr_context_t *ctp,
                                             iofunc_ocb_t *io_ocb) {
    bool has_write_flag = (io_ocb->ioflag & _IO_FLAG_WR) != 0;
    bool has_ability = false;

    struct _client_info *info = NULL;
    struct _client_able  able;
    memset(&able, 0, sizeof(able));
    able.ability = (uint32_t)g_ability_guestctl_id;
    able.flags   = 0u;
    able.range_lo = 0u;
    able.range_hi = 0u;

    /*
     * `iofunc_client_info_able()` returns EOK and sets `_NTO_CI_UNABLE` in
     * `info->flags` when the client does not hold ALL of the listed
     * abilities; it returns an error only when the client information
     * could not be obtained at all.  Both are refusals, and the error is
     * passed through unchanged so the caller can tell the two apart.
     */
    int status = iofunc_client_info_able(ctp, io_ocb->ioflag, &info, 0, &able, 1);
    if (status != EOK) {
        if (info != NULL) {
            iofunc_client_info_ext_free(&info);
        }
        return status;
    }

    has_ability = (info != NULL) && ((info->flags & _NTO_CI_UNABLE) == 0u);
    iofunc_client_info_ext_free(&info);

    latch_guestctl_decision_t decision = latch_guestctl_decide(has_write_flag,
                                                              has_ability);
    if (!latch_guestctl_allowed(decision)) {
        fprintf(stderr,
                "latch_guestd: REFUSED a guest-control mutation (write_flag=%d "
                "ability=%d)\n",
                has_write_flag ? 1 : 0, has_ability ? 1 : 0);
        return latch_guestctl_errno(decision);
    }
    return EOK;
}

static int guest_io_open(resmgr_context_t *ctp,
                         io_open_t *msg,
                         RESMGR_HANDLE_T *handle,
                         void *extra) {
    (void)ctp;
    (void)handle;
    (void)extra;
    /*
     * The channel type (`guest_ctl_t`) limits WHICH TYPES may connect, and
     * the dedicated `latch/guestctl` ability limits WHO MAY MUTATE.  The
     * node itself is not world-accessible any more: it is `0660`, and the
     * mutating verbs additionally require an open that carries
     * `_IO_FLAG_WR` (see `guest_require_mutation_authority()`).
     */
    (void)msg;
    return latch_rm_open_default(ctp, msg, handle, extra);
}

static int guest_io_devctl(resmgr_context_t *ctp,
                           io_devctl_t *msg,
                           RESMGR_OCB_T *ocb) {
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;

    int status = latch_rm_devctl_default(ctp, msg, io_ocb);
    if (status != _RESMGR_DEFAULT) {
        return status;
    }

    if (ctp->size < sizeof(msg->i)) {
        return EBADMSG;
    }

    void *data_ptr = _IO_OUTPUT_PAYLOAD(msg);
    size_t nbytes_out = 0u;

    switch ((unsigned int)msg->i.dcmd) {
        case (unsigned int)DCMD_LATCH_GUEST_STOP: {
            /*
             * THE AUTHORITY CHECK COMES FIRST, before anything is touched:
             * a client without the write flag or without the ability is
             * refused before the daemon looks at the request at all.
             */
            int auth = guest_require_mutation_authority(ctp, io_ocb);
            if (auth != EOK) {
                return auth;
            }
            if (msg->i.nbytes < sizeof(latch_guest_status_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_guest_status_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_guest_status_t)) {
                return EBADMSG;
            }
            int rc = guest_stop();
            if (rc != EOK) {
                return rc;
            }
            latch_guest_status_t rep;
            guest_fill_status(&rep);
            memcpy(data_ptr, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        case (unsigned int)DCMD_LATCH_GUEST_START: {
            /* THE AUTHORITY CHECK COMES FIRST, exactly as it does for the
             * STOP verb: no request without the write flag and the
             * `latch/guestctl` ability reaches the spawn path. */
            int auth = guest_require_mutation_authority(ctp, io_ocb);
            if (auth != EOK) {
                return auth;
            }
            if (msg->i.nbytes < sizeof(latch_guest_status_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_guest_status_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_guest_status_t)) {
                return EBADMSG;
            }
            int rc = guest_spawn();
            if (rc != EOK) {
                return rc;
            }
            latch_guest_status_t rep;
            guest_fill_status(&rep);
            memcpy(data_ptr, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        case (unsigned int)DCMD_LATCH_GET_GUEST_STATUS: {
            /*
             * THE READ-ONLY VERB.  It deliberately does NOT call
             * `guest_require_mutation_authority()`: observing the guest's
             * state is not a mutation, and the whole point of the
             * mutate-vs-observe separation is that a read-only open is
             * enough to read.  What a read-only open is NOT enough for is
             * the STOP and START verbs above.
             */
            if (msg->i.nbytes < sizeof(latch_guest_status_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_guest_status_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_guest_status_t)) {
                return EBADMSG;
            }
            latch_guest_status_t rep;
            guest_fill_status(&rep);
            memcpy(data_ptr, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        default:
            return ENOTTY;
    }

    if (nbytes_out > 0u) {
        memset(&msg->o, 0, sizeof(msg->o));
        msg->o.ret_val = EOK;
        msg->o.nbytes = (uint32_t)nbytes_out;
        return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + nbytes_out);
    }
    memset(&msg->o, 0, sizeof(msg->o));
    msg->o.ret_val = EOK;
    msg->o.nbytes = 0u;
    return EOK;
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s -q <qvm-binary> -c <qvmconf>\n\n"
            "  -q <path>  guest VM hypervisor binary (default /proc/boot/qvm)\n"
            "  -c <path>  guest VM configuration file.  qvm reads it as an\n"
            "             ARGUMENT FILE, so the daemon passes it with the QNX\n"
            "             '@' sigil (an explicit '@' in the path is accepted\n"
            "             and not doubled).\n",
            prog);
}

int main(int argc, char *argv[]) {
    snprintf(g_qvm_path, sizeof(g_qvm_path), "%s", "/proc/boot/qvm");

    int opt;
    while ((opt = getopt(argc, argv, "q:c:h")) != -1) {
        switch (opt) {
            case 'q':
                snprintf(g_qvm_path, sizeof(g_qvm_path), "%s", optarg);
                break;
            case 'c':
                snprintf(g_conf_path, sizeof(g_conf_path), "%s", optarg);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    if (g_conf_path[0] == '\0') {
        fprintf(stderr, "latch_guestd: no guest configuration given (-c)\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /*
     * qvm takes its configuration as an ARGUMENT FILE: the QNX `@file`
     * sigil means "read the command-line arguments from this file".  This
     * is not cosmetic -- measured on the QEMU AArch64 target on
     * 2026-11-25, passing the path WITHOUT the sigil makes qvm reject it:
     *
     *     Unknown option '/proc/boot/latch_qemu_governor.qvmconf'
     *
     * and the hypervisor exits immediately with status 65 (0x41), which
     * is why the guest never streams.  The original boot-script form
     * (`on -T qvm_host_t /proc/boot/qvm @/proc/boot/...qvmconf`) is the
     * one that works, so the daemon reproduces it exactly.  An explicit
     * leading '@' in the -c argument is accepted and not doubled.
     */
    if (g_conf_path[0] == '@') {
        snprintf(g_conf_arg, sizeof(g_conf_arg), "%s", g_conf_path);
        /* g_conf_path is also used for the existence check below, so
         * strip the sigil for that purpose. */
        memmove(g_conf_path, g_conf_path + 1, strlen(g_conf_path));
    } else {
        snprintf(g_conf_arg, sizeof(g_conf_arg), "@%s", g_conf_path);
    }

    /*
     * THE TERMINATION SIGNALS ARE INSTALLED WITH `sigaction()` (NEW-3).
     *
     * Two reasons, and both of them are about the platform rather than
     * about style.
     *
     * 1. `SA_RESTART` DOES NOT EXIST IN SDP 8.0.  The installed
     *    `<signal.h>` carries the line
     *
     *        #define SA_RESTART      0x0040 (not supported yet)
     *
     *    commented out, so there is no way to ask for a restart, and none
     *    is ever granted: a blocking call that is interrupted by a signal
     *    returns `EINTR`.  The QNX 8.0 C Library Reference says so for
     *    `MsgReceive()` -- which is what `dispatch_block()` waits on --
     *    under `EINTR`: "The call was interrupted by a signal."  So the
     *    dispatch loop DOES come back when a signal arrives, and the
     *    termination flag below is read on the next turn of the loop.
     *
     * 2. `sigaction()` is the mechanism the QNX 8.0 C Library Reference
     *    points new applications at ("The sigaction() function provides a
     *    more comprehensive and reliable mechanism for controlling
     *    signals; new applications should use it instead of signal()").
     *    It also makes the handler's lifetime EXPLICIT: the handler stays
     *    installed, so a second `SIGTERM` does the same thing as the
     *    first instead of reverting to the default action.
     *
     * The handler itself does the LEAST it can: it sets two flags and
     * returns.  It cannot do the stop work itself -- `guest_stop()`
     * prints, sleeps and calls `waitpid()`, none of which is
     * async-signal-safe -- so the ordinary code performs the stop after
     * the dispatch loop has ended.  This is the same shape the
     * guest-control gate uses: the signal says WHAT happened; the
     * ordinary code decides what to do about it.
     */
    struct sigaction term_sa;
    memset(&term_sa, 0, sizeof(term_sa));
    term_sa.sa_handler = guest_sig_handler;
    sigemptyset(&term_sa.sa_mask);
    term_sa.sa_flags = 0;       /* no SA_RESTART: SDP 8.0 has none */
    if (sigaction(SIGTERM, &term_sa, NULL) != 0) {
        perror("latch_guestd: sigaction(SIGTERM)");
        return EXIT_FAILURE;
    }
    if (sigaction(SIGINT, &term_sa, NULL) != 0) {
        perror("latch_guestd: sigaction(SIGINT)");
        return EXIT_FAILURE;
    }
    signal(SIGPIPE, SIG_IGN);

    /*
     * Reap the guest child as soon as it dies, so an operator's
     * `slay -9 qvm` does not leave a ZOMBIE entry in the process table
     * until the next control request arrives.
     */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = guest_sigchld_handler;
    sigemptyset(&sa.sa_mask);
    /*
     * No SA_RESTART: QNX's <signal.h> does not define it (its signal()
     * is the BSD-style one that already restarts interrupted calls), and
     * every loop in this file tolerates EINTR -- the dispatch loop
     * continues on EINTR, and the reap loop simply polls again.
     */
    sa.sa_flags = 0;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        perror("latch_guestd: sigaction(SIGCHLD)");
        return EXIT_FAILURE;
    }

    dispatch_t *dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);
    if (dpp == NULL) {
        perror("latch_guestd: dispatch_create_channel");
        return EXIT_FAILURE;
    }

    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t      io_funcs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs,
                     _RESMGR_IO_NFUNCS, &io_funcs);
    connect_funcs.open = guest_io_open;
    io_funcs.devctl    = guest_io_devctl;

    /*
     * Create the dedicated `latch/guestctl` ability (C-7).
     *
     * flags 0 means NEITHER root nor non-root receives it by default, so
     * the only way to hold it is to be granted it by name in the security
     * policy.  Creating it needs the `able_create` ability, which the
     * policy grants to `latch_guestd_t` and to no other type in this
     * daemon's neighbourhood.
     *
     * Re-creating an ability that already exists is NOT an error: the
     * QNX 8.0 reference says that a subsequent call whose flags do not
     * omit a privilege domain included at creation returns the ability id
     * without changing the permissions.  flags 0 includes no domain, so a
     * restart of the daemon finds the same ability.
     */
    g_ability_guestctl_id = procmgr_ability_create(LATCH_GUESTCTL_ABILITY_NAME, 0);
    if (g_ability_guestctl_id < 0) {
        fprintf(stderr, "latch_guestd: procmgr_ability_create(%s) failed: %s\n",
                LATCH_GUESTCTL_ABILITY_NAME, strerror(errno));
        return EXIT_FAILURE;
    }

    /*
     * The node is NOT world-accessible any more: it is `0660` (C-7).
     * Access is still governed by the channel type -- the policy grants
     * `channel connect` on `guest_ctl_t` only to `latchctl_t` and
     * `operator_shell_t` -- and, on top of that, the mutating verbs
     * require an open that carries `_IO_FLAG_WR` AND a client that holds
     * the `latch/guestctl` ability.
     */
    iofunc_attr_init(&g_guest_attr.attr, S_IFCHR | 0660, NULL, NULL);

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max   = 1;
    rattr.msg_max_size = 1024u;

    int id = resmgr_attach(dpp, &rattr, LATCH_DEV_GUESTCTL,
                            _FTYPE_ANY, 0, &connect_funcs,
                            &io_funcs, &g_guest_attr.attr);
    if (id == -1) {
        perror("latch_guestd: resmgr_attach");
        return EXIT_FAILURE;
    }

    /* Start the guest.  If this fails, the daemon says so and exits
     * non-zero: the supervisor then degrades to LATCH on its own, which is
     * the safe direction. */
    int rc = guest_spawn();
    if (rc != EOK) {
        fprintf(stderr, "latch_guestd: could not start the guest VM (%s); "
                        "the supervisor will fail closed.\n", strerror(rc));
        resmgr_detach(dpp, id, _RESMGR_DETACH_ALL);
        return EXIT_FAILURE;
    }

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    while (g_running) {
        if (dispatch_block(ctp) == NULL) {
            if (errno == EINTR) {
                /* A signal interrupted the wait.  `g_running` is re-read
                 * at the top of the loop, so a termination request is
                 * noticed HERE -- on the next turn -- and not inside the
                 * signal handler, which is where the stop work cannot
                 * safely be done. */
                continue;
            }
            break;
        }
        (void)dispatch_handler(ctp);
    }

    /*
     * THE TERMINATION PATH (NEW-3).
     *
     * The daemon used to detach and exit with the guest hypervisor -- its
     * own CHILD -- still running, as an ORPHAN.  A lifecycle daemon whose
     * death leaves the thing it manages running is not a lifecycle daemon.
     *
     * The invariant is one sentence: **THE DAEMON NEVER EXITS WHILE ITS
     * GUEST IS RUNNING.**  It is enforced here, on EVERY exit from the
     * dispatch loop -- not only on the `SIGTERM` path, because an orphan
     * is an orphan however the daemon came to leave.
     *
     * AND THE STOP MUST COMPLETE BEFORE THE DAEMON EXITS.  If the stop
     * fails, the daemon says so LOUDLY and exits NON-ZERO: it must not
     * exit successfully while reporting that it left the guest running.
     * A non-zero exit is the honest answer, and the supervisor degrades to
     * LATCH on its own, which is the safe direction.
     */
    int exit_status = EXIT_SUCCESS;
    if (g_guest_pid > 0) {
        fprintf(stderr, "latch_guestd: stopping the guest VM (%s).\n",
                g_terminate ? "termination" : "dispatch-loop exit");
        int stop_rc = guest_stop();
        if (stop_rc != EOK) {
            fprintf(stderr, "latch_guestd: the guest VM could NOT be stopped "
                            "(%s); it may still be running.\n", strerror(stop_rc));
            exit_status = EXIT_FAILURE;
        }
    } else if (g_terminate) {
        fprintf(stderr, "latch_guestd: termination; the guest VM was already gone.\n");
    }

    dispatch_context_free(ctp);
    resmgr_detach(dpp, id, _RESMGR_DETACH_ALL);
    return exit_status;
}
