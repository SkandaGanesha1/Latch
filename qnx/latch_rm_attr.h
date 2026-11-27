/*
 * latch_rm_attr.h -- THE RESOURCE MANAGER'S ATTRIBUTE LOCK.
 *
 * WHAT THIS IS
 * ------------
 * Every LATCH resource manager (the supervisor `latchd`, the feedback
 * sink `latch_fb_sink` and the guest lifecycle daemon `latch_guestd`)
 * is a QNX resource manager built on the iofunc library.  The iofunc
 * library keeps a block of PER-DEVICE state in an `iofunc_attr_t`: the
 * file-use count, the reader and writer counts, the lock counts, the
 * dirty flags, the mode and the timestamps.  That block is SHARED by
 * every client of the node.
 *
 * WHY THE SHARED STATE NEEDS A LOCK
 * ---------------------------------
 * MEASURED on the installed QNX SDP 8.0 library
 * (`target/qnx/aarch64le/lib/libc.so.6`, disassembled):
 *
 *   - `iofunc_ocb_attach()` -- reached by `iofunc_open_default()` --
 *     updates `attr->count` (offset 44), `attr->rcount` (46),
 *     `attr->wcount` (48), `attr->rlocks` (50) and `attr->wlocks` (52)
 *     with a NON-ATOMIC 16-bit read-modify-write: a `ldrh` followed by
 *     a `strh` of the incremented value.
 *
 *   - `iofunc_ocb_detach()` -- reached by `iofunc_close_ocb_default()` --
 *     updates the same five counters the same way.
 *
 *   - `iofunc_write_verify()` stores to `attr->flags` (40) and
 *     `attr->mode` (104).
 *
 *   The offsets are confirmed by `iofunc_attr_init_sized()`, which
 *   memsets the structure and then stores the dirty-flag word at
 *   offset 40 and the mode at offset 104 -- exactly the layout in
 *   <sys/iofunc.h>.
 *
 * A read-modify-write of a shared 16-bit counter is NOT atomic, so two
 * threads that attach an OCB at the same time can LOSE an increment:
 * both read `count == 0`, both write `count == 1`, and the device
 * believes it has one user when it has two.  The same shape of race
 * exists on the close path, where a lost decrement can drive the count
 * below zero and wrap it to 65535.
 *
 * LATCH's resource managers create their dispatch channel with
 * `DISPATCH_FLAG_NOLOCK` and run MORE THAN ONE dispatch thread on it
 * (`latch_fb_sink` runs two), so two messages really can be in flight
 * at the same time on the same node.  The iofunc library does not take
 * the attribute lock around its own entry points -- verified by
 * disassembly: none of `iofunc_open_default`,
 * `iofunc_close_ocb_default`, `iofunc_close_dup_default`,
 * `iofunc_read_verify`, `iofunc_write_verify` or `iofunc_devctl_default`
 * reaches `iofunc_attr_lock()` -- so the resource manager has to do it.
 *
 * THE RULE
 * --------
 * **Every iofunc entry point a LATCH resource manager calls is made
 * while that device's attribute lock is held.**
 *
 * The rule is implemented by the wrappers below, and the wrappers are
 * the ONLY way a LATCH resource manager is allowed to reach the iofunc
 * library: the consistency checker fails the build if a resource
 * manager calls a raw iofunc entry point.  That way a new iofunc call
 * cannot be added without a lock -- it would have to be a new wrapper,
 * and a new wrapper has to pass the same gate.
 *
 * FAIL CLOSED
 * -----------
 * If the attribute lock cannot be taken, the operation is REFUSED.  It
 * is never performed without the lock.  A resource manager that mutates
 * shared device state without the lock is worse than one that refuses
 * the request.
 *
 * WHY IT CANNOT SELF-DEADLOCK
 * ---------------------------
 *  - The mutex inside the attribute is created by
 *    `iofunc_attr_init()`, which memsets the whole structure to zero
 *    (measured: `iofunc_attr_init_sized()` calls `memset()` and then
 *    stores the dirty-flag word at offset 40 and the mode at offset
 *    104; it never writes the mutex at offset 32).  On QNX a zeroed
 *    `pthread_mutex_t` is EXACTLY the state that `_mutex_init()`
 *    produces (`__count == {0U}`, `__owner == _NTO_SYNC_MUTEX_FREE`),
 *    so it is a valid mutex -- and a RECURSIVE one, because the
 *    non-recursive flag `_NTO_SYNC_NONRECURSIVE` (bit 31) is clear in
 *    a zeroed mutex and set in `PTHREAD_MUTEX_INITIALIZER`.
 *
 *  - The QNX SDP 8.0 documentation for `iofunc_attr_lock()` says the
 *    lock is a COUNTING mechanism: "a given thread can lock the
 *    attributes structure multiple times; it must then unlock the
 *    attributes structure a corresponding number of times."  So a
 *    re-entrant acquisition succeeds and returns EOK rather than
 *    deadlocking -- which matters, because a resource manager may
 *    legitimately reach a second wrapper from inside the first.
 *
 *  - None of the wrapped iofunc entry points takes the attribute lock
 *    itself.  PROVEN by disassembling the installed SDP 8.0 library
 *    and walking the FULL transitive call closure of each wrapper with
 *    the PLT resolved: 350 functions, and `iofunc_attr_lock` is in
 *    NONE of them.  The library's own `iofunc_attr_lock()` is
 *    `pthread_mutex_lock(&attr->lock)` and its `iofunc_attr_unlock()`
 *    is `pthread_mutex_unlock(&attr->lock)` -- both of which are
 *    leaves.  So there is no lock-ordering cycle between the attribute
 *    lock and the library.
 *
 *  - A resource manager never holds the attribute lock while it holds
 *    one of its own mutexes.  The wrappers take the lock, make the one
 *    iofunc call and release it; the caller's own state is never
 *    touched inside the region.
 *
 * THE HOST TEST
 * -------------
 * This header is QNX-only by default (it includes <sys/iofunc.h>).
 * `qnx/latch_rm_attr_test.c` compiles the SAME header against a small
 * stub of the iofunc interface (`qnx/latch_rm_attr_host.h`) and RUNS
 * it, so the lock discipline is proved BEHAVIOURALLY and not merely
 * read out of the source.  The stub is a test fixture: it is never on
 * the include path of anything that ships.
 */

#ifndef LATCH_RM_ATTR_H
#define LATCH_RM_ATTR_H

/*
 * The iofunc interface.  On the target it is QNX's <sys/iofunc.h>; the
 * host test substitutes its own declarations so that the wrappers below
 * -- the code that ships -- can be compiled and run off-target.
 */
#ifdef LATCH_RM_ATTR_HOSTED
#include "latch_rm_attr_host.h"
#else
#include <sys/iofunc.h>
#endif

#include <errno.h>
#include <stddef.h>   /* NULL */

/*
 * Take the device's attribute lock.
 *
 * Returns EOK on success, or the lock's error (EDEADLK, EBUSY or
 * EINVAL) on failure.  A NULL attribute is EINVAL: there is no lock to
 * take, so the caller must refuse the operation.
 */
static inline int latch_rm_attr_lock(iofunc_attr_t *attr)
{
    if (attr == NULL) {
        return EINVAL;
    }
    int rc = iofunc_attr_lock(attr);
    if (rc != EOK) {
        return rc;
    }
    return EOK;
}

/*
 * Release the device's attribute lock.
 *
 * Returns EOK on success, or the unlock's error.  A NULL attribute is
 * EINVAL.
 */
static inline int latch_rm_attr_unlock(iofunc_attr_t *attr)
{
    if (attr == NULL) {
        return EINVAL;
    }
    return iofunc_attr_unlock(attr);
}

/*
 * The wrappers.  Each one is the ONLY sanctioned way for a LATCH
 * resource manager to reach the corresponding iofunc entry point.
 *
 * The shape of every wrapper is the same:
 *
 *   1. take the attribute lock -- and if it cannot be taken, RETURN the
 *      error WITHOUT calling the iofunc function (fail closed);
 *   2. make the iofunc call;
 *   3. release the attribute lock -- on BOTH paths, including the
 *      error path;
 *   4. return the iofunc function's status, or the unlock's error.
 */

/* The OPEN path.  `handle` IS the device's iofunc_attr_t: the
 * resource manager hands `&attr` to `resmgr_attach()` and the library
 * hands the same pointer back as the open handler's handle. */
static inline int latch_rm_open_default(resmgr_context_t *ctp,
                                        io_open_t *msg,
                                        RESMGR_HANDLE_T *handle,
                                        void *extra)
{
    iofunc_attr_t *attr = (iofunc_attr_t *)handle;
    int rc = latch_rm_attr_lock(attr);
    if (rc != EOK) {
        return rc;
    }
    int status = iofunc_open_default(ctp, msg, attr, extra);
    int urc = latch_rm_attr_unlock(attr);
    return (status != EOK) ? status : urc;
}

/* The CLOSE path (an OCB is being detached). */
static inline int latch_rm_close_ocb_default(resmgr_context_t *ctp,
                                             void *reserved,
                                             RESMGR_OCB_T *ocb)
{
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    iofunc_attr_t *attr = (io_ocb != NULL) ? io_ocb->attr : NULL;
    int rc = latch_rm_attr_lock(attr);
    if (rc != EOK) {
        return rc;
    }
    int status = iofunc_close_ocb_default(ctp, reserved, io_ocb);
    int urc = latch_rm_attr_unlock(attr);
    return (status != EOK) ? status : urc;
}

/* The DUPLICATE-CLOSE path. */
static inline int latch_rm_close_dup_default(resmgr_context_t *ctp,
                                              io_close_t *msg,
                                              RESMGR_OCB_T *ocb)
{
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    iofunc_attr_t *attr = (io_ocb != NULL) ? io_ocb->attr : NULL;
    int rc = latch_rm_attr_lock(attr);
    if (rc != EOK) {
        return rc;
    }
    int status = iofunc_close_dup_default(ctp, msg, io_ocb);
    int urc = latch_rm_attr_unlock(attr);
    return (status != EOK) ? status : urc;
}

/* The READ path. */
static inline int latch_rm_read_verify(resmgr_context_t *ctp,
                                       io_read_t *msg,
                                       RESMGR_OCB_T *ocb,
                                       int *nonblock)
{
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    iofunc_attr_t *attr = (io_ocb != NULL) ? io_ocb->attr : NULL;
    int rc = latch_rm_attr_lock(attr);
    if (rc != EOK) {
        return rc;
    }
    int status = iofunc_read_verify(ctp, msg, io_ocb, nonblock);
    int urc = latch_rm_attr_unlock(attr);
    return (status != EOK) ? status : urc;
}

/* The WRITE path. */
static inline int latch_rm_write_verify(resmgr_context_t *ctp,
                                        io_write_t *msg,
                                        RESMGR_OCB_T *ocb,
                                        int *nonblock)
{
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    iofunc_attr_t *attr = (io_ocb != NULL) ? io_ocb->attr : NULL;
    int rc = latch_rm_attr_lock(attr);
    if (rc != EOK) {
        return rc;
    }
    int status = iofunc_write_verify(ctp, msg, io_ocb, nonblock);
    int urc = latch_rm_attr_unlock(attr);
    return (status != EOK) ? status : urc;
}

/* The DEVCTL path. */
static inline int latch_rm_devctl_default(resmgr_context_t *ctp,
                                          io_devctl_t *msg,
                                          RESMGR_OCB_T *ocb)
{
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    iofunc_attr_t *attr = (io_ocb != NULL) ? io_ocb->attr : NULL;
    int rc = latch_rm_attr_lock(attr);
    if (rc != EOK) {
        return rc;
    }
    int status = iofunc_devctl_default(ctp, msg, io_ocb);
    int urc = latch_rm_attr_unlock(attr);
    return (status != EOK) ? status : urc;
}

#endif /* LATCH_RM_ATTR_H */
