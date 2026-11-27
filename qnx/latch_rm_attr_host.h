/*
 * latch_rm_attr_host.h -- THE HOST-TEST STUB for <sys/iofunc.h>.
 *
 * THIS IS A TEST FIXTURE.  IT IS NEVER ON THE INCLUDE PATH OF ANYTHING
 * THAT SHIPS.
 *
 * WHY IT EXISTS
 * -------------
 * `qnx/latch_rm_attr.h` is the header that carries the resource
 * managers' attribute-lock discipline, and it is QNX-only by default:
 * it includes <sys/iofunc.h>.  A lock discipline that can only be READ
 * and never RUN is a discipline nobody has proved, and this repository
 * does not accept that.
 *
 * So the host test compiles the SHIPPED header against this stub -- the
 * same wrappers, the same text -- and RUNS it.  The stub records, for
 * every iofunc entry point, whether the attribute lock was HELD while
 * the entry point ran.  The test then asserts the three properties
 * that matter:
 *
 *   1. the iofunc call runs WITH the lock held;
 *   2. if the lock cannot be taken, the iofunc call does NOT run at
 *      all (fail closed);
 *   3. the lock is released on every path, including the error path.
 *
 * The stub's `iofunc_attr_t` is a TEST DOUBLE, not QNX's structure.
 * What it has to get right is the SHAPE the wrappers depend on:
 *
 *   - `resmgr_attach()` hands the open handler a `RESMGR_HANDLE_T *`
 *     that IS the device's `iofunc_attr_t *`;
 *   - an OCB's first member is a pointer to the device's
 *     `iofunc_attr_t`.
 *
 * Both of those are QNX's contract (see <sys/iofunc.h>:
 * `iofunc_open_default()`'s third parameter is `iofunc_attr_t *__attr`,
 * and `iofunc_ocb_t`'s first member is `IOFUNC_ATTR_T *attr`), and both
 * are what the wrappers cast to.
 */

#ifndef LATCH_RM_ATTR_HOST_H
#define LATCH_RM_ATTR_HOST_H

#include <errno.h>
#include <stdint.h>

#ifndef EOK
#define EOK 0
#endif

/* --- the iofunc-shaped types ------------------------------------- */

typedef struct {
    int dummy;
} resmgr_context_t;

typedef struct {
    int dummy;
} io_open_t;

typedef struct {
    int dummy;
} io_read_t;

typedef struct {
    int dummy;
} io_write_t;

typedef struct {
    int dummy;
} io_devctl_t;

typedef struct {
    int dummy;
} io_close_t;

/* QNX: `RESMGR_HANDLE_T` and `RESMGR_OCB_T` are `void`. */
typedef void RESMGR_HANDLE_T;
typedef void RESMGR_OCB_T;

/*
 * The stub's attribute.  It carries the lock's state and the
 * bookkeeping the test asserts on.
 */
typedef struct {
    int lock_held;       /* is the lock held right now?            */
    int lock_calls;      /* how many times the lock was taken      */
    int unlock_calls;    /* how many times the lock was released   */
    int lock_rc;         /* what the lock returns (0 = success)     */
    int unlock_rc;       /* what the unlock returns                 */
    int iofunc_rc;       /* what the iofunc entry points return     */
    int calls;           /* how many times an iofunc entry ran      */
    int calls_locked;    /* ... of which, how many ran WITH the lock */
} iofunc_attr_t;

/*
 * The stub's OCB.  QNX's `iofunc_ocb_t` also starts with a pointer to
 * the device's attribute, and the wrappers rely on that.
 */
typedef struct {
    iofunc_attr_t *attr;
    int32_t        ioflag;
} iofunc_ocb_t;

/* --- the stubbed iofunc entry points ------------------------------ */

extern int iofunc_attr_lock(iofunc_attr_t *attr);
extern int iofunc_attr_unlock(iofunc_attr_t *attr);

extern int iofunc_open_default(resmgr_context_t *ctp, io_open_t *msg,
                                iofunc_attr_t *attr, void *extra);
extern int iofunc_close_ocb_default(resmgr_context_t *ctp, void *reserved,
                                     iofunc_ocb_t *ocb);
extern int iofunc_close_dup_default(resmgr_context_t *ctp, io_close_t *msg,
                                     iofunc_ocb_t *ocb);
extern int iofunc_read_verify(resmgr_context_t *ctp, io_read_t *msg,
                              iofunc_ocb_t *ocb, int *nonblock);
extern int iofunc_write_verify(resmgr_context_t *ctp, io_write_t *msg,
                               iofunc_ocb_t *ocb, int *nonblock);
extern int iofunc_devctl_default(resmgr_context_t *ctp, io_devctl_t *msg,
                                 iofunc_ocb_t *ocb);

#endif /* LATCH_RM_ATTR_HOST_H */
