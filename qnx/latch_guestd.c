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
#include <sys/resmgr.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <secpol/secpol.h>

#include "latch_protocol.h"

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
 * daemon never spawns a second guest while the first may still exist. */
#define LATCH_GUEST_REAP_TRIES  200u
#define LATCH_GUEST_REAP_SLEEP_NS 10000000L /* 10 ms */

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
static pid_t       g_guest_pid     = -1;
static uint32_t    g_generation    = 0u;
static uint32_t    g_last_exit     = 0u;
static char        g_qvm_path[256] = {0};
static char        g_conf_path[256] = {0};
static char        g_conf_arg[272] = {0};
static volatile sig_atomic_t g_running = 1;

/*
 * A child that has been reaped by the SIGCHLD handler but whose pid was
 * not yet recorded (the window between posix_spawn() returning and the
 * spawn site storing the pid) is parked here, so its exit status is not
 * lost and the daemon does not end up pointing at a dead, already-reaped
 * pid.
 */
static volatile sig_atomic_t g_pending_reaped = 0;
static pid_t       g_pending_pid    = -1;
static uint32_t    g_pending_status = 0u;

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static void guest_sig_handler(int sig) {
    (void)sig;
    g_running = 0;
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
 * The handler is async-signal-safe: waitpid() is, and every variable it
 * touches is either a sig_atomic_t or a value whose update is a single
 * aligned store.
 */
static void guest_sigchld_handler(int sig) {
    (void)sig;
    int status = 0;
    pid_t r;
    while ((r = waitpid(-1, &status, WNOHANG)) > 0) {
        if (g_guest_pid > 0 && r == g_guest_pid) {
            g_last_exit = (uint32_t)status;
            g_guest_pid = -1;
        } else {
            /* Reaped before the spawn site could record the pid. */
            g_pending_pid = r;
            g_pending_status = (uint32_t)status;
            g_pending_reaped = 1;
        }
    }
}

/*
 * Reap the guest child if it has exited.
 *
 * Returns 1 if a child was reaped (and updates g_last_exit), 0 if the child
 * is still alive, and -1 if there is no child at all.
 */
static int guest_reap_if_exited(void) {
    if (g_guest_pid <= 0) {
        return -1;
    }
    int status = 0;
    pid_t r = waitpid(g_guest_pid, &status, WNOHANG);
    if (r == 0) {
        return 0;               /* still running */
    }
    if (r > 0) {
        g_last_exit = (uint32_t)status;
        g_guest_pid = -1;
        return 1;
    }
    /*
     * ECHILD: the SIGCHLD handler already reaped this child.  Recover the
     * exit status from the pending slot if the handler parked it there
     * (it parks a reap whose pid was not yet recorded); otherwise the
     * handler already folded the status into g_last_exit.
     */
    if (g_pending_reaped && g_pending_pid == g_guest_pid) {
        g_last_exit = g_pending_status;
        g_pending_reaped = 0;
        g_pending_pid = -1;
    }
    g_guest_pid = -1;
    return 1;
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
    if (g_guest_pid > 0) {
        guest_reap_if_exited();
        if (g_guest_pid > 0) {
            fprintf(stderr, "latch_guestd: a guest VM is already running (pid %d)\n",
                    (int)g_guest_pid);
            return EBUSY;
        }
    }

    if (access(g_qvm_path, X_OK) != 0) {
        fprintf(stderr, "latch_guestd: guest binary '%s' is missing or not executable: %s\n",
                g_qvm_path, strerror(errno));
        return ENOENT;
    }
    if (access(g_conf_path, R_OK) != 0) {
        fprintf(stderr, "latch_guestd: guest configuration '%s' is missing: %s\n",
                g_conf_path, strerror(errno));
        return ENOENT;
    }

    posix_spawnattr_t attr;
    int rc = posix_spawnattr_init(&attr);
    if (rc != 0) {
        fprintf(stderr, "latch_guestd: posix_spawnattr_init: %s\n", strerror(rc));
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
        return EPERM;
    }

    char *argv[3];
    argv[0] = g_qvm_path;
    argv[1] = g_conf_arg;
    argv[2] = NULL;

    pid_t pid = -1;
    rc = posix_spawn(&pid, g_qvm_path, NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        fprintf(stderr, "latch_guestd: posix_spawn('%s'): %s\n", g_qvm_path, strerror(rc));
        return rc;
    }

    /*
     * The child may have died -- and been reaped by the SIGCHLD handler --
     * before this point, e.g. if the qvm binary could not be exec'd.  If
     * the handler already reaped THIS pid, the daemon must not keep
     * pointing at a dead child: it records the exit status, reports the
     * failure and leaves the guest DOWN.  The caller (the client that
     * asked for a start, or the daemon's own startup) then fails closed.
     */
    if (g_pending_reaped && g_pending_pid == pid) {
        g_last_exit = g_pending_status;
        g_pending_reaped = 0;
        g_pending_pid = -1;
        g_generation++;
        fprintf(stderr, "latch_guestd: guest VM (pid %d) exited immediately "
                        "(status 0x%X); the guest is NOT running.\n",
                (int)pid, (unsigned int)g_last_exit);
        return ECHILD;
    }
    /* Any pending reap belongs to an older child: discard it. */
    g_pending_reaped = 0;
    g_pending_pid = -1;

    g_guest_pid = pid;
    g_generation++;
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
 */
static int guest_stop(void) {
    if (g_guest_pid <= 0) {
        guest_reap_if_exited();
        if (g_guest_pid <= 0) {
            /* Already stopped.  Idempotent: report success with running=0. */
            return EOK;
        }
    }

    pid_t pid = g_guest_pid;
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        fprintf(stderr, "latch_guestd: kill(%d): %s\n", (int)pid, strerror(errno));
        return errno;
    }

    for (uint32_t i = 0u; i < LATCH_GUEST_REAP_TRIES; ++i) {
        /*
         * Use the SAME reaping path as everywhere else, so the SIGCHLD
         * handler and this loop cannot both try to reap the child.  A
         * non-zero return means the child is gone: either this loop reaped
         * it, or the handler had already done so.
         */
        int r = guest_reap_if_exited();
        if (r != 0) {
            printf("latch_guestd: guest VM stopped (pid %d, status 0x%X)\n",
                   (int)pid, (unsigned int)g_last_exit);
            fflush(stdout);
            return EOK;
        }
        struct timespec ts = { 0, LATCH_GUEST_REAP_SLEEP_NS };
        (void)nanosleep(&ts, NULL);
    }

    fprintf(stderr, "latch_guestd: guest VM (pid %d) did not exit within the reap bound\n",
            (int)pid);
    return ETIMEDOUT;
}

static void guest_fill_status(latch_guest_status_t *st) {
    memset(st, 0, sizeof(*st));
    st->struct_size = (uint32_t)sizeof(*st);
    (void)guest_reap_if_exited();
    st->running = (g_guest_pid > 0) ? 1u : 0u;
    st->generation = g_generation;
    st->last_exit_status = g_last_exit;
    st->pid = (g_guest_pid > 0) ? (int32_t)g_guest_pid : -1;
}

/* -------------------------------------------------------------------------
 * Resource manager
 * ------------------------------------------------------------------------- */

static int guest_io_open(resmgr_context_t *ctp,
                         io_open_t *msg,
                         RESMGR_HANDLE_T *handle,
                         void *extra) {
    (void)ctp;
    (void)handle;
    (void)extra;
    /*
     * The channel type (`guest_ctl_t`) is what actually gates access: the
     * security policy allows only `latchctl_t` and `operator_shell_t` to
     * connect to a channel of that type.  The node itself is opened
     * read-only by default; the mutating devctls are the only way to
     * change the guest's state.
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

    signal(SIGINT, guest_sig_handler);
    signal(SIGTERM, guest_sig_handler);
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
     * The node is world-readable so that the OPERATOR's `latchctl` can open
     * it.  Access is still governed by the channel type: the policy grants
     * `channel connect` on `guest_ctl_t` only to `latchctl_t` and
     * `operator_shell_t`, so an unrelated process cannot even open it.
     */
    iofunc_attr_init(&g_guest_attr.attr, S_IFCHR | 0666, NULL, NULL);

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
                continue;
            }
            break;
        }
        (void)dispatch_handler(ctp);
    }

    dispatch_context_free(ctp);
    resmgr_detach(dpp, id, _RESMGR_DETACH_ALL);
    return EXIT_SUCCESS;
}
