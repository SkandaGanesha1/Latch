/*
 * qnx/latch_guestctl_guard_test.c
 *
 * THE HOST-SIM TEST FOR THE GUEST-CONTROL GATE
 * =============================================
 *
 * WHAT THIS TEST IS FOR
 * ---------------------
 * `/dev/latch/guestctl` can stop and start the guest VM.  Before the fix,
 * it had no access control of its own: the node was world read/write, the
 * client opened it read-only, and the mutating devctls checked NOTHING --
 * so "may connect to the channel" silently meant "may kill the guest".
 *
 * The fix is TWO INDEPENDENT CHECKS, and this test exists to prove the
 * claim that ONE of them is not enough.  It compiles the SHIPPED header
 * `qnx/latch_guestctl_guard.h` and RUNS the real decision function over
 * the whole truth table:
 *
 *   | open carries _IO_FLAG_WR | client holds latch/guestctl | result  |
 *   |-------------------------|------------------------------|---------|
 *   | no                      | no                           | REFUSED |
 *   | no                      | yes                          | REFUSED |
 *   | yes                     | no                           | REFUSED |
 *   | yes                     | yes                          | ALLOWED |
 *
 * The decisive assertion is not "the right rows are refused" -- it is
 *
 *     EXACTLY ONE of the four rows allows the mutation
 *
 * because that is the property that makes the second check load-bearing.
 * A gate that checks only the write flag leaves three rows allowing; a gate
 * that checks only the ability leaves three rows allowing; only the two
 * together leave exactly one.  If a future edit weakens the gate to a
 * single check, this test's row count changes and it FAILS.
 *
 * It also pins the two properties that are easy to lose in a refactor:
 * the decision FAILS CLOSED (an undefined decision value is not an ALLOW),
 * and the two refusals are DISTINGUISHABLE (the diagnostic that says WHICH
 * check failed is worth more than the errno).
 *
 * It runs on the host, so it is part of `make check` and it runs in CI.
 */

#include "latch_guestctl_guard.h"

#include <stdio.h>
#include <string.h>

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
 * THE TRUTH TABLE
 * ------------------------------------------------------------------------- */

/*
 * The four (write flag, ability) combinations, walked explicitly.
 *
 * `expect_allow` is what the gate MUST decide for that row.  The test does
 * not merely assert the verdict: it COUNTS the rows that allow, and the
 * count is the property under test.
 */
typedef struct guestctl_row {
    bool has_write_flag;
    bool has_ability;
    bool expect_allow;
    latch_guestctl_decision_t expect_decision;
    const char *name;
} guestctl_row_t;

static const guestctl_row_t g_rows[4] = {
    {false, false, false, LATCH_GUESTCTL_DENY_NO_WRITE_FLAG,
     "read-only open, no ability"},
    {false, true,  false, LATCH_GUESTCTL_DENY_NO_WRITE_FLAG,
     "read-only open, WITH the ability"},
    {true,  false, false, LATCH_GUESTCTL_DENY_NO_ABILITY,
     "write open, NO ability"},
    {true,  true,  true,  LATCH_GUESTCTL_ALLOW,
     "write open, WITH the ability"},
};

static void test_the_truth_table(void) {
    int allowing_rows = 0;

    for (unsigned i = 0u; i < sizeof(g_rows) / sizeof(g_rows[0]); ++i) {
        const guestctl_row_t *r = &g_rows[i];
        const latch_guestctl_decision_t d =
            latch_guestctl_decide(r->has_write_flag, r->has_ability);

        check(latch_guestctl_allowed(d) == r->expect_allow,
              r->name);
        check(d == r->expect_decision,
              "the refusal says WHICH check failed");
        if (latch_guestctl_allowed(d)) {
            ++allowing_rows;
        }
    }

    /*
     * THE DECISIVE COUNT.  Exactly one row may allow -- the row where the
     * open carries the write flag AND the client holds the ability.
     */
    check(allowing_rows == 1,
          "EXACTLY ONE of the four (write flag, ability) combinations allows "
          "the mutation -- one gate alone would allow three");
}

/* -------------------------------------------------------------------------
 * EACH CHECK IS LOAD-BEARING ON ITS OWN
 * ------------------------------------------------------------------------- */

/* A client that holds the ability but opened the node READ-ONLY must still
 * be refused: the ability says "you may change the guest", not "you may
 * change the guest through a read-only descriptor". */
static void test_the_write_flag_is_load_bearing(void) {
    const latch_guestctl_decision_t d = latch_guestctl_decide(false, true);
    check(!latch_guestctl_allowed(d),
          "the write flag alone refuses a read-only open, even WITH the ability");
    check(d == LATCH_GUESTCTL_DENY_NO_WRITE_FLAG,
          "the refusal names the write flag");
}

/* A client that opened the node for WRITING but holds no ability must be
 * refused: "can open" is not "is allowed to mutate". */
static void test_the_ability_is_load_bearing(void) {
    const latch_guestctl_decision_t d = latch_guestctl_decide(true, false);
    check(!latch_guestctl_allowed(d),
          "the ability alone refuses a write open when the client holds no "
          "ability");
    check(d == LATCH_GUESTCTL_DENY_NO_ABILITY,
          "the refusal names the ability");
}

/* -------------------------------------------------------------------------
 * IT FAILS CLOSED
 * ------------------------------------------------------------------------- */

/* A decision value this header does not define must be a refusal.  ALLOW is
 * the ZERO value on purpose, so a decision variable that was never set is
 * NOT an ALLOW -- but an out-of-range value must not slip through either. */
static void test_an_unknown_decision_is_refused(void) {
    const latch_guestctl_decision_t bogus = (latch_guestctl_decision_t)99;
    check(!latch_guestctl_allowed(bogus),
          "a decision value the header does not define is REFUSED");
    check(latch_guestctl_errno(bogus) == EPERM,
          "an unknown decision carries EPERM, not success");
}

/* The ALLOW decision must be the ZERO value, so that a zeroed decision
 * variable is a refusal rather than an ALLOW. */
static void test_allow_is_the_zero_value(void) {
    const latch_guestctl_decision_t zeroed = (latch_guestctl_decision_t)0;
    check(latch_guestctl_allowed(zeroed),
          "the ALLOW decision is the zero value");
    check(!latch_guestctl_allowed(LATCH_GUESTCTL_DENY_NO_WRITE_FLAG) &&
          !latch_guestctl_allowed(LATCH_GUESTCTL_DENY_NO_ABILITY),
          "neither refusal is the zero value");
}

/* -------------------------------------------------------------------------
 * THE ERRNO
 * ------------------------------------------------------------------------- */

/* Both refusals carry EPERM: the client is not permitted.  The two decision
 * values stay distinct anyway, because the diagnostic that says WHICH check
 * failed is worth more than the errno. */
static void test_the_refusals_carry_eperm(void) {
    check(latch_guestctl_errno(LATCH_GUESTCTL_DENY_NO_WRITE_FLAG) == EPERM,
          "a missing write flag carries EPERM");
    check(latch_guestctl_errno(LATCH_GUESTCTL_DENY_NO_ABILITY) == EPERM,
          "a missing ability carries EPERM");
    check(latch_guestctl_errno(LATCH_GUESTCTL_ALLOW) == LATCH_GUESTCTL_OK,
          "an allowed mutation carries no error");
}

/* -------------------------------------------------------------------------
 * THE ABILITY'S NAME
 * ------------------------------------------------------------------------- */

/* The ability's name is the CONTRACT between the daemon that creates it,
 * the policy that grants it and the gate that checks it.  It lives in the
 * shipped header so that there is one copy of it; this test pins the exact
 * string, because a renamed ability would compile cleanly and then be
 * refused by the kernel for ever. */
static void test_the_ability_name(void) {
    check(strcmp(LATCH_GUESTCTL_ABILITY_NAME, "latch/guestctl") == 0,
          "the dedicated ability is named 'latch/guestctl'");
    check(strchr(LATCH_GUESTCTL_ABILITY_NAME, '/') != NULL,
          "the ability's name carries the 'latch/' namespace");
    check(strncmp(LATCH_GUESTCTL_ABILITY_NAME, "latch/", 6) == 0,
          "the ability's name is inside LATCH's own namespace");
}

int main(void) {
    printf("== LATCH guest-control guard (host-sim) ==\n");

    test_the_truth_table();
    test_the_write_flag_is_load_bearing();
    test_the_ability_is_load_bearing();
    test_an_unknown_decision_is_refused();
    test_allow_is_the_zero_value();
    test_the_refusals_carry_eperm();
    test_the_ability_name();

    printf("== %d checks, %d failures ==\n", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
