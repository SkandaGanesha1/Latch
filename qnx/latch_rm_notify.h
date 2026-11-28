/*
 * latch_rm_notify.h -- THE RESOURCE MANAGER'S NOTIFICATION-LIST LOCK.
 *
 * WHAT THIS IS
 * ------------
 * The QNX iofunc library lets a resource manager tell a client "your
 * condition is met" with a PULSE.  The machinery is an
 * `iofunc_notify_t`: a three-element array (one element per condition
 * class: INPUT, OUTPUT and OUT-OF-BAND), and each element holds
 *
 *     struct _iofunc_notify {
 *         int                         cnt;   -- the armed trigger count
 *         struct _iofunc_notify_event *list; -- the armed events
 *     };
 *
 * The `list` is a SINGLY-LINKED list of `iofunc_notify_event_t` -- one
 * node per armed client notification -- and it is owned by the resource
 * manager.  Three library entry points walk and change it:
 *
 *   - `iofunc_notify()` ALLOCATES an event and LINKS it into
 *     `nop[index].list`, and writes `nop[index].cnt`;
 *   - `iofunc_notify_trigger()` (and its `_strict` sibling) walks
 *     `nop[index].list`, delivers a pulse for each event whose count has
 *     been reached, and UNLINKS the events it fires;
 *   - `iofunc_notify_remove()` (and its `_strict` sibling) walks the
 *     list and `free()`s the events.
 *
 * WHY THE LIST NEEDS A LOCK
 * -------------------------
 * MEASURED on the installed QNX SDP 8.0 library
 * (`target/qnx/aarch64le/lib/libc.so.6`, disassembled):
 *
 *   - `iofunc_notify_trigger_strict()` loads the list head with
 *     `ldr x19, [x23, #8]` (the `list` member at offset 8), follows it
 *     with `ldr x19, [x19]` (the event's `next` at offset 0), delivers
 *     the pulse with `MsgDeliverEvent()`, and UNLINKS the event by
 *     writing the successor back through the predecessor's `next`.
 *
 *   - `iofunc_notify_remove_strict()` loads the same list head, follows
 *     the same `next` chain, and calls `free()` on each event.
 *
 *   - `iofunc_notify()` links a freshly allocated event into the same
 *     list and updates the element's `cnt`.
 *
 *   - NONE of the five notify entry points takes a mutex.  MEASURED:
 *     the disassembly of `iofunc_notify`, `iofunc_notify_remove`,
 *     `iofunc_notify_remove_strict`, `iofunc_notify_trigger` and
 *     `iofunc_notify_trigger_strict` contains NO call to
 *     `pthread_mutex_lock`, `pthread_mutex_unlock` or `SyncMutexLock_r`.
 *     The library provides no lock of its own here; the resource
 *     manager has to.
 *
 * So two threads that walk the same list at the same time can corrupt
 * it, and the corruption is not a benign count:
 *
 *   - the trigger walks into an event that the remove has just
 *     `free()`d -- a USE-AFTER-FREE, and the pulse is delivered with
 *     the freed event's contents;
 *   - the trigger's unlink and the remove's unlink both write the
 *     predecessor's `next`, so a node can be lost, duplicated, or made
 *     to point at itself.
 *
 * IS THE RACE LIVE IN LATCH?
 * --------------------------
 * YES, in `latch_fb_sink.c`.  The feedback sink creates its dispatch
 * channel with `DISPATCH_FLAG_NOLOCK` and runs TWO dispatch threads on
 * it, so two messages really can be in flight at the same time.  The
 * READ node's notification list is reachable from three of them:
 *
 *   - the publisher's WRITE handler calls `iofunc_notify_trigger()`
 *     when a frame is queued;
 *   - the reader's `io_notify()` handler calls `iofunc_notify()` to arm
 *     a notification;
 *   - the reader's close handler calls `iofunc_notify_remove()`.
 *
 * The WRITE handler and the read/close handlers run on DIFFERENT
 * dispatch threads, so the trigger and the remove -- which both walk
 * and unlink the SAME list -- can be in flight simultaneously.
 *
 * THE RULE
 * --------
 * **Every access to a notification list is made while that list's lock
 * is held.**
 *
 * The rule is implemented by the wrappers below, and the wrappers are
 * the ONLY way a LATCH resource manager is allowed to reach the notify
 * library: the consistency checker fails the build if a resource
 * manager calls a raw notify entry point or uses a raw `IOFUNC_NOTIFY_*`
 * macro, so a new notification path cannot be added without a lock.
 *
 * FAIL CLOSED
 * -----------
 * If the notification lock cannot be taken, the operation is REFUSED.
 * It is never performed without the lock.  A notification that is
 * delivered without the lock can be delivered from freed memory; a
 * notification that is refused is a client that waits for the next
 * trigger, which is the safe direction.
 *
 * WHY THE NOTIFY LOCK IS NEVER NESTED WITH THE ATTRIBUTE LOCK
 * -----------------------------------------------------------
 * The attribute lock (`latch_rm_attr.h`) and this lock protect different
 * state, and a resource manager must never hold both at once -- two
 * locks held in two different orders are a deadlock.
 *
 * That is guaranteed by construction, and the consistency checker
 * proves it structurally:
 *
 *   - no wrapper in this header calls another wrapper in this header,
 *     so a wrapper cannot re-enter the lock it already holds (which on
 *     a non-recursive mutex would be a self-deadlock);
 *   - this header does not mention the attribute lock, and
 *     `latch_rm_attr.h` does not mention this lock, so neither family
 *     can be reached from inside the other's critical section;
 *   - each wrapper takes exactly one lock and releases it before it
 *     returns.
 *
 * The measured facts agree: NONE of the notify entry points reaches
 * `iofunc_attr_lock`, so the library itself never nests the two.
 *
 * THE HOST TEST
 * -------------
 * This header is QNX-only by default (it includes <sys/iofunc.h>).
 * `qnx/latch_rm_notify_test.c` compiles the SAME header against a small
 * stub of the notify interface (`qnx/latch_rm_notify_host.h`, a test
 * fixture that is never on the include path of anything that ships) and
 * RUNS it, so the lock discipline is proved BEHAVIOURALLY and not
 * merely read out of the source.  The stub records, for every notify
 * entry point, whether the notification lock was HELD while the entry
 * point ran.  The test then asserts that:
 *
 *   1. the notify call runs WITH the lock held;
 *   2. if the lock cannot be taken, the notify call does NOT run at
 *      all (fail closed);
 *   3. the lock is released on every path, including the error path;
 *   4. the armed-count CHECK and the trigger that follows it are ONE
 *      critical section;
 *   5. four threads hammering the same list NEVER enter it at the same
 *      time (the lock really is mutual exclusion).
 */

#ifndef LATCH_RM_NOTIFY_H
#define LATCH_RM_NOTIFY_H

/*
 * The notify interface.  On the target it is QNX's <sys/iofunc.h>; the
 * host test substitutes its own declarations so that the wrappers below
 * -- the code that ships -- can be compiled and run off-target.
 */
#ifdef LATCH_RM_NOTIFY_HOSTED
#include "latch_rm_notify_host.h"
#else
#include <sys/iofunc.h>
#endif

#include <errno.h>
#include <pthread.h>
#include <stddef.h>   /* NULL */

/*
 * The notification block: QNX's three lists AND the lock that guards
 * them.  The lock lives INSIDE the block on purpose -- a list and its
 * lock cannot be separated, so a resource manager cannot lock one
 * block's list while reading another block's.
 */
typedef struct latch_rm_notify_s {
    iofunc_notify_t nop[3];   /* INPUT, OUTPUT and OUT-OF-BAND */
    pthread_mutex_t lock;     /* THIS block's lock              */
} latch_rm_notify_t;

/*
 * The lock primitives.  On the target they are the POSIX mutex calls.
 * The host test substitutes its own so that the FAIL-CLOSED path can be
 * driven; the wrappers below are the SAME text in both builds.
 */
#ifdef LATCH_RM_NOTIFY_HOSTED
extern int latch_rm_notify_lock_impl(pthread_mutex_t *m);
extern int latch_rm_notify_unlock_impl(pthread_mutex_t *m);
#else
static inline int latch_rm_notify_lock_impl(pthread_mutex_t *m)
{
    return pthread_mutex_lock(m);
}

static inline int latch_rm_notify_unlock_impl(pthread_mutex_t *m)
{
    return pthread_mutex_unlock(m);
}
#endif

/*
 * Take the notification list's lock.
 *
 * Returns EOK on success, or the lock's error (EDEADLK, EBUSY or
 * EINVAL) on failure.  A NULL block is EINVAL: there is no lock to
 * take, so the caller must refuse the operation.
 */
static inline int latch_rm_notify_lock(latch_rm_notify_t *n)
{
    if (n == NULL) {
        return EINVAL;
    }
    int rc = latch_rm_notify_lock_impl(&n->lock);
    if (rc != EOK) {
        return rc;
    }
    return EOK;
}

/*
 * Release the notification list's lock.
 *
 * Returns EOK on success, or the unlock's error.  A NULL block is
 * EINVAL.
 */
static inline int latch_rm_notify_unlock(latch_rm_notify_t *n)
{
    if (n == NULL) {
        return EINVAL;
    }
    return latch_rm_notify_unlock_impl(&n->lock);
}

/*
 * Initialise a notification block: the mutex and the three lists.
 *
 * The lists are initialised with QNX's own `IOFUNC_NOTIFY_INIT()`, so
 * the state a client sees is exactly the state it saw before this
 * header existed.
 */
static inline int latch_rm_notify_init(latch_rm_notify_t *n)
{
    if (n == NULL) {
        return EINVAL;
    }
    int rc = pthread_mutex_init(&n->lock, NULL);
    if (rc != EOK) {
        return rc;
    }
    IOFUNC_NOTIFY_INIT(n->nop);
    return EOK;
}

/*
 * The wrappers.  Each one is the ONLY sanctioned way for a LATCH
 * resource manager to reach the corresponding notify entry point.
 *
 * The shape of every wrapper is the same:
 *
 *   1. take the notification lock -- and if it cannot be taken, RETURN
 *      the error WITHOUT calling the notify function (fail closed);
 *   2. make the notify call;
 *   3. release the notification lock -- on BOTH paths, including the
 *      error path;
 *   4. return the notify function's status, or the unlock's error.
 *
 * NO WRAPPER CALLS ANOTHER WRAPPER.  That is what makes the lock
 * non-reentrant-safe: a wrapper that re-entered its own lock would
 * deadlock on a non-recursive mutex.
 */

/* The io_notify() handler: arm a notification for the client. */
static inline int latch_rm_notify_arm(resmgr_context_t *ctp,
                                      io_notify_t *msg,
                                      latch_rm_notify_t *n,
                                      int trig)
{
    if (n == NULL) {
        return EINVAL;
    }
    int rc = latch_rm_notify_lock(n);
    if (rc != EOK) {
        return rc;
    }
    int status = iofunc_notify(ctp, msg, n->nop, trig, NULL, NULL);
    int urc = latch_rm_notify_unlock(n);
    return (status != EOK) ? status : urc;
}

/*
 * Fire the INPUT notification if the armed trigger count has been
 * reached.
 *
 * The CHECK and the TRIGGER are ONE critical section.  The check reads
 * the element's `cnt` and the trigger walks the element's `list`; if
 * they were two critical sections, a notification could be armed
 * between them and the count the trigger used would not be the count
 * the check compared against.
 *
 * `*fired` is set to 1 when a trigger was attempted and to 0 otherwise.
 * The return value is EOK, or the lock's error (fail closed: no
 * trigger is attempted at all).
 */
static inline int latch_rm_notify_input_fire(latch_rm_notify_t *n,
                                             int cnt,
                                             int *fired)
{
    if (fired != NULL) {
        *fired = 0;
    }
    if (n == NULL) {
        return EINVAL;
    }
    int rc = latch_rm_notify_lock(n);
    if (rc != EOK) {
        return rc;
    }
    if (IOFUNC_NOTIFY_INPUT_CHECK(n->nop, cnt, 0)) {
        iofunc_notify_trigger(n->nop, cnt, IOFUNC_NOTIFY_INPUT);
        if (fired != NULL) {
            *fired = 1;
        }
    }
    int urc = latch_rm_notify_unlock(n);
    return urc;
}

/* Fire every armed notification of one class (the close path). */
static inline int latch_rm_notify_trigger_strict(resmgr_context_t *ctp,
                                                 latch_rm_notify_t *n,
                                                 int cnt,
                                                 int index)
{
    if (n == NULL) {
        return EINVAL;
    }
    int rc = latch_rm_notify_lock(n);
    if (rc != EOK) {
        return rc;
    }
    iofunc_notify_trigger_strict(ctp, n->nop, cnt, index);
    int urc = latch_rm_notify_unlock(n);
    return urc;
}

/* Drop every armed notification of the block (the close path). */
static inline int latch_rm_notify_remove(resmgr_context_t *ctp,
                                         latch_rm_notify_t *n)
{
    if (n == NULL) {
        return EINVAL;
    }
    int rc = latch_rm_notify_lock(n);
    if (rc != EOK) {
        return rc;
    }
    iofunc_notify_remove(ctp, n->nop);
    int urc = latch_rm_notify_unlock(n);
    return urc;
}

#endif /* LATCH_RM_NOTIFY_H */
