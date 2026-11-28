/*
 * latch_rm_notify_host.h -- THE HOST-TEST STUB for the iofunc NOTIFY
 * interface.
 *
 * THIS IS A TEST FIXTURE.  IT IS NEVER ON THE INCLUDE PATH OF ANYTHING
 * THAT SHIPS.
 *
 * WHY IT EXISTS
 * -------------
 * `qnx/latch_rm_notify.h` is the header that carries the resource
 * managers' notification-list lock, and it is QNX-only by default: it
 * includes <sys/iofunc.h>.  A lock discipline that can only be READ and
 * never RUN is a discipline nobody has proved, and this repository does
 * not accept that.
 *
 * So the host test compiles the SHIPPED header against this stub -- the
 * same wrappers, the same text -- and RUNS it.  The stub records, for
 * every notify entry point, whether the notification lock was HELD
 * while the entry point ran.  The test then asserts the properties
 * that matter:
 *
 *   1. the notify call runs WITH the lock held;
 *   2. if the lock cannot be taken, the notify call does NOT run at
 *      all (fail closed);
 *   3. the lock is released on every path, including the error path;
 *   4. the armed-count CHECK and the trigger are one critical section;
 *   5. the lock is real mutual exclusion under concurrency.
 *
 * WHAT THE STUB HAS TO GET RIGHT
 * ------------------------------
 * The stub's `iofunc_notify_t` is a TEST DOUBLE, not QNX's structure.
 * What it has to reproduce is the SHAPE the wrappers depend on:
 *
 *   - `iofunc_notify_t` is `{ int cnt; struct _iofunc_notify_event
 *     *list; }` -- a 16-byte element, and the library indexes an array
 *     of them by condition class (INPUT, OUTPUT, OUT-OF-BAND);
 *   - `IOFUNC_NOTIFY_INPUT_CHECK()` reads element 0's `cnt`, and
 *     `IOFUNC_NOTIFY_INIT()` sets all three elements' `cnt` to
 *     `INT_MAX` and their `list` to NULL.
 *
 * Both are QNX's contract (see <sys/iofunc.h>) and both are copied
 * here VERBATIM, because the wrapper's behaviour depends on their exact
 * shape.
 *
 * THE TYPES ARE SHARED WITH THE ATTRIBUTE STUB
 * ---------------------------------------------
 * `resmgr_context_t` is defined by `latch_rm_attr_host.h`, because the
 * iofunc library is ONE library and a test that includes both families
 * must not define the same type twice.
 */

#ifndef LATCH_RM_NOTIFY_HOST_H
#define LATCH_RM_NOTIFY_HOST_H

#include "latch_rm_attr_host.h"

#include <pthread.h>

#ifndef EOK
#define EOK 0
#endif

/* --- the iofunc-shaped types ------------------------------------- */

typedef struct {
    int dummy;
} io_notify_t;

/*
 * QNX: `struct _iofunc_notify_event` is the node of the armed-event
 * list.  Only the `next` member matters to the stub.
 */
typedef struct _iofunc_notify_event {
    struct _iofunc_notify_event *next;
} iofunc_notify_event_t;

/*
 * QNX: `struct _iofunc_notify` is `{ int cnt; struct
 * _iofunc_notify_event *list; }` -- see <sys/iofunc.h>.
 */
typedef struct {
    int                  cnt;
    iofunc_notify_event_t *list;
} iofunc_notify_t;

/* --- the macros, copied from QNX's <sys/iofunc.h> VERBATIM -------- */

/* Indexes to the array of struct _iofunc_notify */
#define IOFUNC_NOTIFY_INPUT  0
#define IOFUNC_NOTIFY_OUTPUT 1
#define IOFUNC_NOTIFY_OBAND  2

/* Macros to be used to see if iofunc_notify_trigger should be called. */
#define IOFUNC_NOTIFY_INPUT_CHECK(__nop, __cnt, __tran)    \
    ((__nop)[IOFUNC_NOTIFY_INPUT].cnt <= (__cnt) && ((__nop)[IOFUNC_NOTIFY_INPUT].cnt || (__tran)))

#define IOFUNC_NOTIFY_INIT(__nop) \
    ((__nop)[0].cnt = (__nop)[1].cnt = (__nop)[2].cnt = (~0u) >> 1, \
     (__nop)[0].list = (__nop)[1].list = (__nop)[2].list = NULL)

/* --- the stubbed notify entry points ----------------------------- */

extern int  iofunc_notify(resmgr_context_t *ctp, io_notify_t *msg,
                           iofunc_notify_t *nop, int trig,
                           const int *notifycnts, int *armed);
extern void iofunc_notify_trigger(iofunc_notify_t *nop, int cnt, int index);
extern void iofunc_notify_trigger_strict(resmgr_context_t *ctp,
                                         iofunc_notify_t *nop, int cnt,
                                         int index);
extern void iofunc_notify_remove(resmgr_context_t *ctp, iofunc_notify_t *nop);

/*
 * The lock seam.  The shipped header's `latch_rm_notify_lock_impl()`
 * and `latch_rm_notify_unlock_impl()` are these functions in the host
 * build and the POSIX mutex calls in the target build.  The wrappers
 * that use them are the SAME text in both.
 */
extern int latch_rm_notify_lock_impl(pthread_mutex_t *m);
extern int latch_rm_notify_unlock_impl(pthread_mutex_t *m);

#endif /* LATCH_RM_NOTIFY_HOST_H */
