#ifndef LATCH_FEEDBACK_PUB_H_
#define LATCH_FEEDBACK_PUB_H_

/*
 * THE HOST-SIDE FEEDBACK PUBLISHER  (W5)
 * ======================================
 *
 * WHAT THIS IS
 * ------------
 * The trusted supervisor (`latchd`) publishes ONE LFBK verdict per guest
 * proposal: "I accepted it" or "I rejected it, and here is why".  This
 * module is the thing that carries that verdict to the transport.
 *
 * WHY IT IS A SEPARATE MODULE AND NOT A CALL INSIDE THE TICK
 * ----------------------------------------------------------
 * The supervisor's tick is the SAFETY CORE.  It runs at SCHED_FIFO 63, it
 * is the thing whose deadline is the signed WCET budget, and it must never
 * be delayed by anything advisory.  A verdict is advisory by construction:
 * the guest can only use it to STOP proposing, and the supervisor's own
 * dead-man already fails closed when the guest goes quiet.
 *
 * So the tick's publish call is a MEMCPY and a SIGNAL -- nothing else.  The
 * write to the resource manager (a message-passing round trip through
 * QNX's io-char layer) happens on a DEDICATED WRITER THREAD at a priority
 * BELOW the safety core.  A wedged, slow or absent feedback sink therefore
 * costs the supervisor nothing but a stale advisory channel, and the
 * channel's own contract ("loss is safe, silence is fatal") is enforced on
 * the guest side, not here.
 *
 * THE SLOT IS ONE VERDICT DEEP
 * -----------------------------
 * The transport keeps the LATEST verdict (the verdict file holds one
 * frame).  A publisher that queued every verdict would build a backlog
 * that the transport cannot drain, and the backlog would deliver STALE
 * verdicts after the fact -- which is worse than dropping them.  So the
 * mailbox holds ONE frame: a newer verdict overwrites an older one that
 * has not been written yet, and the overwrite is COUNTED rather than
 * hidden.
 *
 * A dropped verdict is SAFE.  The guest correlates a verdict with the
 * proposal it answers by BOTH sequence number and session epoch, so a
 * dropped verdict is seen by the guest as "no answer for this proposal",
 * which the guest's feedback timeout turns into "stop proposing", which
 * the supervisor's dead-man turns into a fail-closed LATCH.  Loss is safe;
 * silence is fatal; both directions close.
 *
 * THE PRIMITIVES LIVE FOR THE PROCESS LIFETIME
 * ---------------------------------------------
 * The publisher's mutex and condvar are STATIC objects with static
 * storage duration.  They are initialised EXACTLY ONCE (by
 * `pthread_once`) and they are NEVER destroyed.
 *
 * `latch_feedback_pub_stop()` stops the writer thread and joins it.  It
 * does NOT tear the primitives down, because every public entry point
 * uses them -- including the ones that run BEFORE the publisher was
 * started and the ones that run AFTER it was stopped:
 *
 *   - `latch_feedback_pub_publish()` before a start takes the lock to
 *     discover that the publisher is not running (and refuses the
 *     frame);
 *   - `latch_feedback_pub_publish()` after a stop takes the lock to
 *     refuse the frame the same way;
 *   - `latch_feedback_pub_get_status()` after a stop takes the lock to
 *     hand the operator a final snapshot;
 *   - `latch_feedback_pub_start()` after a stop RE-USES the very same
 *     mutex and condvar for the new writer thread.
 *
 * POSIX leaves the behaviour UNDEFINED after `pthread_mutex_destroy()` /
 * `pthread_cond_destroy()`, so all four of those would be a use of a
 * destroyed object.  The publisher is therefore restartable, and every
 * one of those paths is exercised by `qnx/latch_feedback_pub_test.c`.
 */

#include "latch_feedback.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The publisher node the feedback resource manager serves.  It is the
 * ONE-SIDED WRITE side: the resource manager refuses a read access on it
 * in code, so a publisher cannot read the channel back. */
#define LATCH_FEEDBACK_PUB_PATH_DEFAULT "/dev/latch/feedback_pub"

/*
 * The counters.  Every one of them is a FACT about the run, and a fact an
 * operator cannot see is a fact that cannot be acted on.
 */
typedef struct {
    uint64_t offered;    /* frames the caller handed to the publisher        */
    uint64_t written;    /* frames the writer thread wrote to the node       */
    uint64_t dropped;    /* frames overwritten in the slot before being written */
    uint64_t errors;     /* write() failures and failed opens                */
    uint64_t opens;      /* successful opens of the publisher node           */
    uint64_t reconnects; /* the node had to be reopened after a failure      */
    uint64_t retries;    /* EAGAIN retries (the node was momentarily full)   */
    int      running;    /* the writer thread is alive                       */
} latch_feedback_pub_status_t;

/*
 * Start the publisher.
 *
 * `path` may be NULL, in which case LATCH_FEEDBACK_PUB_PATH_DEFAULT is
 * used.  Returns 0 on success and -1 on failure (the thread could not be
 * created).  A failure is NOT FATAL: the supervisor runs perfectly well
 * without an advisory channel, and it says so on the console.
 */
int latch_feedback_pub_start(const char *path);

/*
 * Publish one already-encoded frame.
 *
 * Returns 0 when the frame was accepted into the slot, -EPERM when the
 * publisher is not running, and -EINVAL for a NULL frame.  It NEVER blocks
 * on I/O: the call is a memcpy and a condvar signal.
 */
int latch_feedback_pub_publish(const latch_feedback_t *frame);

/* Stop the publisher and join the writer thread.  Safe to call twice.
 *
 * The mutex and the condvar are NOT destroyed: they live for the
 * process lifetime, so a later `publish()`, `get_status()` or `start()`
 * uses live primitives.  See the lifetime note above. */
void latch_feedback_pub_stop(void);

/* A consistent snapshot of the counters. */
void latch_feedback_pub_get_status(latch_feedback_pub_status_t *out);

/* Is the publisher running?  (0 = no.) */
int latch_feedback_pub_is_running(void);

#ifdef __cplusplus
}
#endif

#endif /* LATCH_FEEDBACK_PUB_H_ */
