/*
 * qnx/latch_ingest_start_test.c
 *
 * THE HOST-SIM TEST FOR THE INGEST'S START-UP CONTRACT
 * =====================================================
 *
 * WHAT THIS TEST IS FOR
 * ---------------------
 * `qnx/latch_ingest.c` is the unprivileged bridge between the guest's
 * byte stream and the supervisor's proposal node.  Three of its start-up
 * decisions were defects, and all three failed OPEN:
 *
 *   1. the `-c` option was parsed and then silently overwritten by the
 *      manifest's value, so the option was a lie;
 *   2. the CPU pin's return value was discarded, so an ingest that could
 *      not be placed started anyway -- UNPINNED, possibly on the
 *      supervisor's own CPU; and
 *   3. a failed `procmgr_ability_lookup()` was ignored, so the bridge
 *      kept HOLDING `latch/actuator` -- the ability to move the plant.
 *
 * The QNX path cannot be exercised off-target (`ThreadCtl()` and
 * `procmgr_ability()` are QNX calls), so the DECISIONS live in the
 * shipped header `qnx/latch_ingest_start.h` and this test compiles and
 * RUNS it.
 *
 * THE DECISIVE ASSERTIONS ARE COUNTS, NOT ROWS
 * ---------------------------------------------
 * A test that merely checks "the right answers are right" passes against
 * a gate that has been weakened in a way this test did not anticipate.
 * So the properties under test are COUNTS and INVARIANTS:
 *
 *   * EXACTLY ONE pin outcome allows the start (only `pin_rc == 0`);
 *   * EXACTLY ONE ability-lookup outcome allows the start (only a
 *     positive id);
 *   * the effective CPU is ALWAYS the SIGNED CPU -- the `-c` option can
 *     never become the CPU the bridge runs on, because it is an
 *     ASSERTION and not an OVERRIDE; and
 *   * every decision that is not an ALLOW -- including the ZERO value
 *     and a value the header does not define -- refuses.
 *
 * It runs on the host, so it is part of `make check` and it runs in CI.
 */

#include "latch_ingest_start.h"

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
 * 1. THE CPU: `-c` IS AN ASSERTION, NOT AN OVERRIDE
 * ------------------------------------------------------------------------- */

/*
 * The three cases, walked explicitly.
 *
 * `expect_allow` is what the decision MUST be for that row.  The test does
 * not merely assert the verdict: it COUNTS the rows that allow and it
 * checks that the EFFECTIVE CPU is the signed one in every usable row.
 */
typedef struct cpu_row {
    bool option_given;
    unsigned int option_cpu;
    unsigned int signed_cpu;
    bool expect_allow;
    bool expect_agrees;
    const char *name;
} cpu_row_t;

static const cpu_row_t g_cpu_rows[3] = {
    {false, 0u,   1u, true,  false, "no -c: the signed CPU is the only authority"},
    {true,  1u,   1u, true,  true,  "-c agrees with the signed contract"},
    {true,  5u,   1u, false, false, "-c CONTRADICTS the signed contract"},
};

static void test_the_cpu_truth_table(void) {
    int allowing_rows = 0;

    for (unsigned i = 0u; i < sizeof(g_cpu_rows) / sizeof(g_cpu_rows[0]); ++i) {
        const cpu_row_t *r = &g_cpu_rows[i];
        const latch_ingest_cpu_choice_t c =
            latch_ingest_cpu_choose(r->option_given, r->option_cpu, r->signed_cpu);

        check(latch_ingest_start_allowed(c.decision) == r->expect_allow, r->name);
        check(c.agrees == r->expect_agrees,
              "the choice says whether -c agreed with the signed contract");
        check(c.asserted == r->option_given,
              "the choice says whether -c was given at all");

        if (latch_ingest_start_allowed(c.decision)) {
            ++allowing_rows;
            /*
             * THE LOAD-BEARING INVARIANT.  The effective CPU is the
             * SIGNED one, always.  A `-c` that agrees changes nothing,
             * and a `-c` that disagrees does not become the CPU the
             * bridge runs on -- it is a REFUSAL.
             */
            check(c.cpu == r->signed_cpu,
                  "the effective CPU is the SIGNED CPU -- -c never overrides it");
        } else {
            check(c.decision == LATCH_INGEST_START_REFUSE_CPU,
                  "the refusal says the CPU contradicted the signed contract");
            check(c.cpu == r->signed_cpu,
                  "even a REFUSED choice reports the SIGNED CPU, never the "
                  "requested one");
        }
    }

    /* Two of the three rows start -- "no -c" and "-c agrees" -- and the
     * third refuses.  The count pins the shape of the table. */
    check(allowing_rows == 2,
          "TWO of the three CPU rows start (no -c, and -c in agreement with "
          "the signed contract) and ONE refuses");
}

/* A `-c` that names a CPU the signed contract does not name must stop the
 * bridge.  This is the whole point: the option used to be a lie, and the
 * lie was resolved in favour of the command line. */
static void test_a_contradiction_refuses(void) {
    const latch_ingest_cpu_choice_t c = latch_ingest_cpu_choose(true, 0u, 1u);
    check(!latch_ingest_start_allowed(c.decision),
          "-c 0 against a signed ingest.cpu of 1 REFUSES to start");
    check(c.decision == LATCH_INGEST_START_REFUSE_CPU,
          "the refusal names the CPU");
    check(c.cpu == 1u,
          "the refused choice still reports the SIGNED CPU (1), not the "
          "requested one (0)");
    check(c.asserted && !c.agrees,
          "the refused choice says -c was given and did not agree");
}

/* The signed CPU is used when the option agrees, so the two paths cannot
 * drift onto different CPUs. */
static void test_agreement_uses_the_signed_cpu(void) {
    const latch_ingest_cpu_choice_t c = latch_ingest_cpu_choose(true, 1u, 1u);
    check(latch_ingest_start_allowed(c.decision),
          "-c in agreement with the signed contract starts");
    check(c.cpu == 1u, "the effective CPU is the signed one");
}

/* -------------------------------------------------------------------------
 * 2. THE PIN: EXACTLY ONE OUTCOME ALLOWS
 * ------------------------------------------------------------------------- */

static void test_the_pin_truth_table(void) {
    /*
     * The pin's own convention: 0 is success, anything else is a
     * negative errno.  EVERY failure must refuse -- the bridge cannot
     * run UNPINNED, because an unpinned bridge can be scheduled onto
     * the supervisor's CPU.
     */
    static const struct {
        int pin_rc;
        bool expect_allow;
        const char *name;
    } rows[] = {
        {0,       true,  "the pin succeeded"},
        {-EACCES, false, "the platform refused the placement"},
        {-ENOMEM, false, "the runmask could not be allocated"},
        {-EINVAL, false, "the signed CPU is not on this platform"},
        {1,       false, "a positive, non-zero result is still not success"},
    };

    int allowing_rows = 0;
    for (unsigned i = 0u; i < sizeof(rows) / sizeof(rows[0]); ++i) {
        const latch_ingest_start_decision_t d =
            latch_ingest_pin_decide(rows[i].pin_rc);
        check(latch_ingest_start_allowed(d) == rows[i].expect_allow, rows[i].name);
        if (rows[i].expect_allow) {
            ++allowing_rows;
        } else {
            check(d == LATCH_INGEST_START_REFUSE_PIN,
                  "the refusal names the PIN");
        }
    }

    /* THE DECISIVE COUNT.  Exactly ONE pin outcome allows the start. */
    check(allowing_rows == 1,
          "EXACTLY ONE pin outcome allows the start -- every failure starts "
          "the bridge UNPINNED otherwise");
}

/* -------------------------------------------------------------------------
 * 3. THE ABILITY LOOKUP: EXACTLY ONE OUTCOME ALLOWS
 * ------------------------------------------------------------------------- */

/*
 * `procmgr_ability_lookup()` returns a POSITIVE id when the ability
 * exists.  Anything else is a FAILED LOOKUP, and a failed lookup means
 * the bridge cannot prove it has surrendered `latch/actuator` -- so it
 * must not run.  The failure mode of getting this wrong is an
 * ESCALATION, not a crash.
 */
static void test_the_ability_truth_table(void) {
    static const struct {
        int lookup_rc;
        bool expect_allow;
        const char *name;
    } rows[] = {
        {1,       true,  "the lookup returned an ability id"},
        {42,      true,  "the lookup returned another ability id"},
        {0,       false, "the lookup returned zero (the ability is absent)"},
        {-1,      false, "the lookup failed"},
        {-EPERM,  false, "the lookup failed with an errno"},
    };

    int allowing_rows = 0;
    for (unsigned i = 0u; i < sizeof(rows) / sizeof(rows[0]); ++i) {
        const latch_ingest_start_decision_t d =
            latch_ingest_ability_decide(rows[i].lookup_rc);
        check(latch_ingest_start_allowed(d) == rows[i].expect_allow, rows[i].name);
        if (rows[i].expect_allow) {
            ++allowing_rows;
        } else {
            check(d == LATCH_INGEST_START_REFUSE_ABILITY,
                  "the refusal names the ABILITY");
        }
    }

    /*
     * THE DECISIVE COUNT.  Exactly the rows that returned a POSITIVE id
     * allow the start -- two of the five -- and every failure refuses.
     * The property is "a positive id and nothing else", so the count is
     * pinned rather than the individual verdicts.
     */
    check(allowing_rows == 2,
          "TWO of the five lookup outcomes allow the start -- the two that "
          "returned a POSITIVE ability id, and no other");
}

/* -------------------------------------------------------------------------
 * IT FAILS CLOSED
 * ------------------------------------------------------------------------- */

/*
 * The ZERO value of the decision enum is a REFUSAL, on purpose.  A
 * decision variable that was never assigned must not start the bridge.
 */
static void test_an_unassigned_decision_is_refused(void) {
    const latch_ingest_start_decision_t zeroed = (latch_ingest_start_decision_t)0;
    check(!latch_ingest_start_allowed(zeroed),
          "the ZERO decision value is a REFUSAL -- an unassigned decision "
          "never starts the bridge");
    check(zeroed == LATCH_INGEST_START_REFUSE_UNKNOWN,
          "the zero value is spelled REFUSE_UNKNOWN");
}

/* A decision value this header does not define must be a refusal too. */
static void test_an_unknown_decision_is_refused(void) {
    const latch_ingest_start_decision_t bogus = (latch_ingest_start_decision_t)99;
    check(!latch_ingest_start_allowed(bogus),
          "a decision value the header does not define is REFUSED");
    check(latch_ingest_start_errno(bogus) == EPERM,
          "an unknown decision carries EPERM, not success");
}

/* The ALLOW decision must NOT be the zero value.  This is the opposite of
 * the convention used by some other gates in this tree, and the reason is
 * worth pinning: a zeroed variable must not be permissive. */
static void test_allow_is_not_the_zero_value(void) {
    check(LATCH_INGEST_START_ALLOW != 0,
          "the ALLOW decision is NOT the zero value -- a zeroed decision "
          "variable must refuse, not start");
    check(latch_ingest_start_allowed(LATCH_INGEST_START_ALLOW),
          "the ALLOW decision allows the start");
}

/* -------------------------------------------------------------------------
 * THE ERRNO
 * ------------------------------------------------------------------------- */

/*
 * The three refusals carry three DIFFERENT errnos, because they are
 * three different operational stories:
 *
 *   EINVAL -- the caller asked for a CPU the signed contract does not
 *             name (a MISCONFIGUREMENT);
 *   EACCES -- the platform refused the placement (a RESOURCE problem);
 *   EPERM  -- the bridge cannot prove it is unprivileged (a PRIVILEGE
 *             problem).
 */
static void test_the_refusals_carry_their_own_errno(void) {
    check(latch_ingest_start_errno(LATCH_INGEST_START_REFUSE_CPU) == EINVAL,
          "a CPU conflict carries EINVAL");
    check(latch_ingest_start_errno(LATCH_INGEST_START_REFUSE_PIN) == EACCES,
          "a failed pin carries EACCES");
    check(latch_ingest_start_errno(LATCH_INGEST_START_REFUSE_ABILITY) == EPERM,
          "a failed ability lookup carries EPERM");
    check(latch_ingest_start_errno(LATCH_INGEST_START_ALLOW) == LATCH_INGEST_START_OK,
          "an allowed start carries no error");
    check(LATCH_INGEST_START_OK == 0,
          "the success errno is spelled 0 (EOK is a QNX-only name)");
}

/* -------------------------------------------------------------------------
 * THE CPU RANGE RULE
 * ------------------------------------------------------------------------- */

/*
 * The pin used to answer "this CPU is not on this platform" by MOVING the
 * bridge -- to CPU 1, or to CPU 0 on a single-CPU platform -- and by
 * reporting SUCCESS.  The fallback is the CPU THE SAFETY SUPERVISOR RUNS
 * ON, so a silent substitution of signed data is a fail-open.
 *
 * The rule is "the CPU must exist here", and it is a property of the
 * shipped header, so it is tested here rather than being a branch nobody
 * can reach off-target.
 */
static void test_the_cpu_range_rule(void) {
    check(latch_ingest_cpu_in_range(0u, 2u),
          "CPU 0 exists on a two-CPU platform");
    check(latch_ingest_cpu_in_range(1u, 2u),
          "CPU 1 exists on a two-CPU platform");
    check(!latch_ingest_cpu_in_range(2u, 2u),
          "CPU 2 does NOT exist on a two-CPU platform");
    check(!latch_ingest_cpu_in_range(5u, 2u),
          "CPU 5 does NOT exist on a two-CPU platform");
    check(!latch_ingest_cpu_in_range(0u, 0u),
          "no CPU exists on a zero-CPU platform, so nothing may be pinned");
    check(latch_ingest_cpu_in_range(0u, 1u) &&
          !latch_ingest_cpu_in_range(1u, 1u),
          "on a SINGLE-CPU platform only CPU 0 exists -- and the signed "
          "contract asks for CPU 1, so the bridge is REFUSED rather than "
          "being moved onto the supervisor's CPU");
}

int main(void) {
    printf("== LATCH ingest start-up contract (host-sim) ==\n");

    test_the_cpu_truth_table();
    test_a_contradiction_refuses();
    test_agreement_uses_the_signed_cpu();
    test_the_cpu_range_rule();
    test_the_pin_truth_table();
    test_the_ability_truth_table();
    test_an_unassigned_decision_is_refused();
    test_an_unknown_decision_is_refused();
    test_allow_is_not_the_zero_value();
    test_the_refusals_carry_their_own_errno();

    printf("== %d checks, %d failures ==\n", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
