/*
 * latch_rm_attr_test.c -- THE HOST PROOF OF THE RESOURCE MANAGER'S
 * ATTRIBUTE LOCK.
 *
 * WHAT THIS PROVES
 * ----------------
 * `qnx/latch_rm_attr.h` is the header every LATCH resource manager uses
 * to reach the QNX iofunc library, and it carries the rule that the
 * iofunc call is made while the device's attribute lock is held.  The
 * header is QNX-only by default, so without this test the rule could
 * only be READ, never RUN.
 *
 * This test compiles the SHIPPED header against the stub in
 * `qnx/latch_rm_attr_host.h` -- the same wrappers, the same text -- and
 * runs them.  For every wrapped iofunc entry point it asserts:
 *
 *   1. the iofunc call runs WITH the lock held;
 *   2. if the lock cannot be taken, the iofunc call does NOT run at
 *      all, and the lock's error is returned (FAIL CLOSED);
 *   3. the lock is released on every path -- including the path where
 *      the iofunc call itself failed;
 *   4. a device with no attribute is refused with EINVAL, and the
 *      iofunc call does not run.
 *
 * The test is deliberately about BEHAVIOUR: it does not look at the
 * source of the header.  A wrapper that took the lock after the call,
 * or that continued when the lock failed, would still LOOK right in the
 * source and would fail here.
 */

#define LATCH_RM_ATTR_HOSTED 1

#include "latch_rm_attr.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* The stub's implementation.                                          */
/* ------------------------------------------------------------------ */

int iofunc_attr_lock(iofunc_attr_t *attr)
{
    attr->lock_calls++;
    if (attr->lock_rc != 0) {
        return attr->lock_rc;
    }
    attr->lock_held = 1;
    return 0;
}

int iofunc_attr_unlock(iofunc_attr_t *attr)
{
    attr->unlock_calls++;
    if (attr->unlock_rc != 0) {
        return attr->unlock_rc;
    }
    attr->lock_held = 0;
    return 0;
}

/* Every stubbed iofunc entry point records whether the lock was held. */
static int host_null_calls = 0;

static void host_note(iofunc_attr_t *attr)
{
    if (attr == NULL) {
        /* A wrapper that reaches the iofunc library with no attribute to
         * lock is a defect, but it must be REPORTED, not crash the
         * test: a crash says nothing about which property broke. */
        host_null_calls++;
        return;
    }
    attr->calls++;
    if (attr->lock_held) {
        attr->calls_locked++;
    }
}

static int host_rc(iofunc_attr_t *attr)
{
    return (attr != NULL) ? attr->iofunc_rc : 0;
}

int iofunc_open_default(resmgr_context_t *ctp, io_open_t *msg,
                        iofunc_attr_t *attr, void *extra)
{
    (void)ctp;
    (void)msg;
    (void)extra;
    host_note(attr);
    return host_rc(attr);
}

int iofunc_close_ocb_default(resmgr_context_t *ctp, void *reserved,
                             iofunc_ocb_t *ocb)
{
    (void)ctp;
    (void)reserved;
    host_note(ocb->attr);
    return host_rc(ocb->attr);
}

int iofunc_close_dup_default(resmgr_context_t *ctp, io_close_t *msg,
                             iofunc_ocb_t *ocb)
{
    (void)ctp;
    (void)msg;
    host_note(ocb->attr);
    return host_rc(ocb->attr);
}

int iofunc_read_verify(resmgr_context_t *ctp, io_read_t *msg,
                       iofunc_ocb_t *ocb, int *nonblock)
{
    (void)ctp;
    (void)msg;
    (void)nonblock;
    host_note(ocb->attr);
    return host_rc(ocb->attr);
}

int iofunc_write_verify(resmgr_context_t *ctp, io_write_t *msg,
                        iofunc_ocb_t *ocb, int *nonblock)
{
    (void)ctp;
    (void)msg;
    (void)nonblock;
    host_note(ocb->attr);
    return host_rc(ocb->attr);
}

int iofunc_devctl_default(resmgr_context_t *ctp, io_devctl_t *msg,
                          iofunc_ocb_t *ocb)
{
    (void)ctp;
    (void)msg;
    host_note(ocb->attr);
    return host_rc(ocb->attr);
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

/* One wrapped iofunc entry point, and how to call it. */
typedef struct {
    const char *name;
    int (*run)(iofunc_attr_t *attr, iofunc_ocb_t *ocb);
} host_case_t;

static int run_open(iofunc_attr_t *attr, iofunc_ocb_t *ocb)
{
    resmgr_context_t ctp;
    io_open_t msg;
    (void)ocb;
    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    return latch_rm_open_default(&ctp, &msg, attr, NULL);
}

static int run_close_ocb(iofunc_attr_t *attr, iofunc_ocb_t *ocb)
{
    resmgr_context_t ctp;
    (void)attr;
    memset(&ctp, 0, sizeof(ctp));
    return latch_rm_close_ocb_default(&ctp, NULL, ocb);
}

static int run_close_dup(iofunc_attr_t *attr, iofunc_ocb_t *ocb)
{
    resmgr_context_t ctp;
    io_close_t msg;
    (void)attr;
    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    return latch_rm_close_dup_default(&ctp, &msg, ocb);
}

static int run_read_verify(iofunc_attr_t *attr, iofunc_ocb_t *ocb)
{
    resmgr_context_t ctp;
    io_read_t msg;
    (void)attr;
    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    return latch_rm_read_verify(&ctp, &msg, ocb, NULL);
}

static int run_write_verify(iofunc_attr_t *attr, iofunc_ocb_t *ocb)
{
    resmgr_context_t ctp;
    io_write_t msg;
    (void)attr;
    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    return latch_rm_write_verify(&ctp, &msg, ocb, NULL);
}

static int run_devctl(iofunc_attr_t *attr, iofunc_ocb_t *ocb)
{
    resmgr_context_t ctp;
    io_devctl_t msg;
    (void)attr;
    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    return latch_rm_devctl_default(&ctp, &msg, ocb);
}

static const host_case_t HOST_CASES[] = {
    { "open_default",       run_open },
    { "close_ocb_default",  run_close_ocb },
    { "close_dup_default",  run_close_dup },
    { "read_verify",        run_read_verify },
    { "write_verify",       run_write_verify },
    { "devctl_default",     run_devctl },
};

static void check_case(const host_case_t *c)
{
    iofunc_attr_t attr;
    iofunc_ocb_t ocb;
    int rc;

    printf("=== %s ===\n", c->name);

    /* 1. THE HAPPY PATH: the iofunc call runs WITH the lock held. */
    memset(&attr, 0, sizeof(attr));
    memset(&ocb, 0, sizeof(ocb));
    ocb.attr = &attr;
    attr.iofunc_rc = 0;
    host_null_calls = 0;
    rc = c->run(&attr, &ocb);
    CHECK(rc == EOK, "%s: the wrapper returned %d, want EOK (%d)",
          c->name, rc, EOK);
    CHECK(attr.calls == 1, "%s: the iofunc call ran %d time(s), want 1",
          c->name, attr.calls);
    CHECK(attr.calls_locked == 1,
          "%s: the iofunc call ran %d time(s) WITH the lock held, want 1 "
          "-- the iofunc entry point updates the SHARED device counters, "
          "so it must not run outside the attribute lock",
          c->name, attr.calls_locked);
    CHECK(attr.lock_calls == 1, "%s: the lock was taken %d time(s), want 1",
          c->name, attr.lock_calls);
    CHECK(attr.unlock_calls == 1,
          "%s: the lock was released %d time(s), want 1",
          c->name, attr.unlock_calls);
    CHECK(attr.lock_held == 0,
          "%s: the lock is STILL HELD after the wrapper returned", c->name);
    CHECK(host_null_calls == 0,
          "%s: the iofunc call ran %d time(s) with no attribute at all",
          c->name, host_null_calls);

    /* 2. THE LOCK CANNOT BE TAKEN: fail closed. */
    memset(&attr, 0, sizeof(attr));
    memset(&ocb, 0, sizeof(ocb));
    ocb.attr = &attr;
    attr.lock_rc = EBUSY;
    host_null_calls = 0;
    rc = c->run(&attr, &ocb);
    CHECK(rc == EBUSY,
          "%s: with the lock unavailable the wrapper returned %d, want the "
          "lock's error (%d)", c->name, rc, EBUSY);
    CHECK(attr.calls == 0,
          "%s: the iofunc call ran %d time(s) even though the lock could "
          "not be taken -- the operation must be REFUSED, not performed "
          "unlocked", c->name, attr.calls);
    CHECK(attr.unlock_calls == 0,
          "%s: the lock was released %d time(s) although it was never "
          "taken", c->name, attr.unlock_calls);

    /* 3. THE IOFUNC CALL FAILS: the error comes back AND the lock is
     *    released. */
    memset(&attr, 0, sizeof(attr));
    memset(&ocb, 0, sizeof(ocb));
    ocb.attr = &attr;
    attr.iofunc_rc = EACCES;
    host_null_calls = 0;
    rc = c->run(&attr, &ocb);
    CHECK(rc == EACCES,
          "%s: the wrapper returned %d, want the iofunc call's error (%d)",
          c->name, rc, EACCES);
    CHECK(attr.calls == 1, "%s: the iofunc call ran %d time(s), want 1",
          c->name, attr.calls);
    CHECK(attr.calls_locked == 1,
          "%s: the iofunc call ran %d time(s) WITH the lock held, want 1",
          c->name, attr.calls_locked);
    CHECK(attr.unlock_calls == 1,
          "%s: the lock was released %d time(s) on the error path, want 1 "
          "-- a lock that is not released on the error path deadlocks the "
          "node", c->name, attr.unlock_calls);
    CHECK(attr.lock_held == 0,
          "%s: the lock is STILL HELD after the iofunc call failed",
          c->name);

    /* 4. NO ATTRIBUTE: refused, and the iofunc call does not run. */
    memset(&attr, 0, sizeof(attr));
    memset(&ocb, 0, sizeof(ocb));
    ocb.attr = NULL;
    host_null_calls = 0;
    rc = c->run(NULL, &ocb);
    CHECK(rc == EINVAL,
          "%s: with no attribute the wrapper returned %d, want EINVAL (%d)",
          c->name, rc, EINVAL);
    CHECK(attr.calls == 0,
          "%s: the iofunc call ran %d time(s) with no attribute to lock",
          c->name, attr.calls);
    CHECK(host_null_calls == 0,
          "%s: the iofunc call ran %d time(s) with no attribute to lock",
          c->name, host_null_calls);
}

int main(void)
{
    size_t i;

    printf("=== latch_rm_attr_test: the resource manager's attribute lock ===\n");
    for (i = 0; i < sizeof(HOST_CASES) / sizeof(HOST_CASES[0]); ++i) {
        check_case(&HOST_CASES[i]);
    }

    if (failures != 0) {
        printf("=== latch_rm_attr_test: %d check(s) FAILED ===\n", failures);
        return 1;
    }
    printf("=== latch_rm_attr_test: all checks PASSED ===\n");
    return 0;
}
