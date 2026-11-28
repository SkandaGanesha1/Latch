/*
 * qnx/latch_ingest_start.h
 *
 * THE INGEST'S START-UP CONTRACT: EVERY DECISION FAILS CLOSED
 * ============================================================
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * `qnx/latch_ingest.c` is the UNPRIVILEGED bridge between the guest's
 * byte stream and the supervisor's proposal node.  Three things about its
 * start-up are safety properties, and all three of them were defects:
 *
 *   1. WHICH CPU IT PINS ITSELF TO.  The `-c` option was parsed and then
 *      silently overwritten by the manifest's value, so the option was a
 *      LIE: a caller could ask for a CPU and get a different one, with no
 *      diagnostic.  The pin's return value was then DISCARDED
 *      (`(void)latch_ingest_pin_cpu(...)`), so an ingest that could not
 *      bind itself to its CPU started anyway -- UNPINNED, on whatever CPU
 *      the scheduler chose.  The ingest's whole reason for existing on
 *      `_cpu-1` is that it is not on `_cpu-0`, where the safety supervisor
 *      runs.
 *
 *   2. WHETHER IT ACHIEVED THAT PIN AT ALL.  Covered above: the pin's
 *      result was thrown away, so "the bridge could not be placed" was
 *      indistinguishable from "the bridge was placed".
 *
 *   3. WHETHER IT DROPPED THE CUSTOM ABILITY.  The manifest names the
 *      custom ability the bridge must surrender (`paths.ability` is
 *      `latch/actuator` in every shipped contract).  A FAILED
 *      `procmgr_ability_lookup()` was ignored, so the bridge carried on
 *      HOLDING `latch/actuator` -- the ability to move the plant.  The
 *      least-privilege step silently became a no-op, and the failure mode
 *      was an ESCALATION, not a crash.
 *
 * WHY A HEADER
 * ------------
 * The QNX path cannot be exercised off-target: `procmgr_ability()` and
 * `ThreadCtl()` are QNX calls, and the ingest's host-sim build stubs
 * them out.  So the DECISIONS live here, in a header that both the
 * ingest and a host test compile, and the host test
 * (`qnx/latch_ingest_start_test.c`) walks every row.
 *
 * IT FAILS CLOSED
 * ---------------
 * Every decision has exactly one permissive outcome, and it is NOT the
 * zero value: the ZERO value of the decision enum is a REFUSAL, so a
 * decision variable that was never set -- or that was set to something
 * this header does not define -- refuses to start.  There is no default,
 * no fallback and no "assume it worked" path.
 */

#ifndef LATCH_INGEST_START_H_
#define LATCH_INGEST_START_H_

#include <errno.h>
#include <stdbool.h>

/*
 * 1. THE CPU THE INGEST PINS ITSELF TO.
 *
 * THE SIGNED MANIFEST IS THE AUTHORITY.  Every shipped contract carries
 * `ingest.cpu`, and the ingest's isolation is derived from it: the
 * supervisor runs on `_cpu-0` and the bridge on `_cpu-1`, so the value in
 * the signed contract is what keeps the two apart.
 *
 * The `-c` option is therefore NOT an override.  An override would
 * replace SIGNED data with UNSIGNED data -- the command line of whoever
 * happens to be able to start the process -- and on the target it would
 * also try to move the bridge off the CPU the qvmconf pinned it to
 * (`on -T latch_ingest_t -C 1 ...`).  So `-c` is an ASSERTION: it says
 * "I expect the bridge on CPU N", and a DISAGREEMENT with the signed
 * contract is a REFUSAL, not a silent substitution.
 *
 * That turns the option from a lie into a cross-check, and it is the
 * behaviour that is the same on the target and on the host: a request
 * that contradicts the signed contract stops the bridge everywhere.
 */

/*
 * THE OUTCOMES OF THE START-UP.
 *
 * THE ZERO VALUE IS A REFUSAL, ON PURPOSE.  `LATCH_INGEST_START_ALLOW`
 * is deliberately NOT zero, so a decision variable that was never
 * assigned -- and a value this header does not define -- is a refusal
 * rather than an ALLOW.  (The opposite convention, "ALLOW is zero", is
 * tempting and is wrong here: a zeroed variable would then be an ALLOW,
 * which is the opposite of failing closed.)
 */
typedef enum {
    /* The zero value is a REFUSAL: an unassigned decision never starts
     * the bridge. */
    LATCH_INGEST_START_REFUSE_UNKNOWN = 0,
    /* The start-up may proceed. */
    LATCH_INGEST_START_ALLOW          = 1,
    /* `-c` CONTRADICTS the signed contract's `ingest.cpu`. */
    LATCH_INGEST_START_REFUSE_CPU     = 2,
    /* The CPU pin FAILED: the bridge cannot honour its own placement. */
    LATCH_INGEST_START_REFUSE_PIN     = 3,
    /* The custom-ability LOOKUP FAILED: the bridge cannot establish that
     * it has surrendered `latch/actuator`, so it must not run at all. */
    LATCH_INGEST_START_REFUSE_ABILITY = 4,
} latch_ingest_start_decision_t;

/*
 * THE CPU CHOICE.
 *
 * `asserted` says whether `-c` was given at all, and `agrees` says
 * whether it agreed with the signed contract.  They are kept apart from
 * the decision so the diagnostic can say WHICH case it was -- "no `-c`
 * was given" and "`-c` contradicted the contract" are different
 * operational stories -- while the decision itself stays a single value.
 */
typedef struct {
    /* ALLOW or REFUSE_CPU. */
    latch_ingest_start_decision_t decision;
    /* The CPU the ingest would pin itself to.  Meaningful for ALLOW; for
     * a REFUSAL it is the SIGNED value, because the signed value is the
     * one the ingest would have used.  It is NEVER the option's value:
     * the option is an assertion, not an override. */
    unsigned int cpu;
    /* Was `-c` given at all? */
    bool asserted;
    /* Did it agree with the signed value? */
    bool agrees;
} latch_ingest_cpu_choice_t;

/*
 * THE CPU DECISION.
 *
 * `option_given` is "was `-c` present on the command line"; `option_cpu`
 * is what it said; `signed_cpu` is the manifest's `ingest.cpu`.
 */
static inline latch_ingest_cpu_choice_t latch_ingest_cpu_choose(bool option_given,
                                                                 unsigned int option_cpu,
                                                                 unsigned int signed_cpu) {
    latch_ingest_cpu_choice_t out;
    out.cpu = signed_cpu;
    out.asserted = option_given;
    if (!option_given) {
        out.decision = LATCH_INGEST_START_ALLOW;
        out.agrees = false;
        return out;
    }
    if (option_cpu != signed_cpu) {
        out.decision = LATCH_INGEST_START_REFUSE_CPU;
        out.agrees = false;
        return out;
    }
    out.decision = LATCH_INGEST_START_ALLOW;
    out.cpu = option_cpu;
    out.agrees = true;
    return out;
}

/*
 * 2. AND 3. THE TWO REFUSALS.
 *
 * They are separate decisions because they are separate facts, and the
 * diagnostic that says WHICH one failed is worth more to the next person
 * than the errno is.
 */

/*
 * THE PIN.  `pin_rc` is the ingest's own convention: 0 is success, and
 * anything else is a negative errno.  A pin that did not succeed is
 * fatal -- the bridge starts UNPINNED otherwise, and an unpinned bridge
 * can be scheduled onto the supervisor's CPU.
 */
static inline latch_ingest_start_decision_t latch_ingest_pin_decide(int pin_rc) {
    return (pin_rc == 0) ? LATCH_INGEST_START_ALLOW
                         : LATCH_INGEST_START_REFUSE_PIN;
}

/*
 * THE ABILITY LOOKUP.  `lookup_rc` is the id `procmgr_ability_lookup()`
 * returned: a POSITIVE id means the ability exists and can be dropped;
 * anything else means the lookup FAILED, and the bridge therefore cannot
 * prove it has surrendered the ability.  Continuing would leave the
 * guest's bridge holding `latch/actuator`.
 */
static inline latch_ingest_start_decision_t latch_ingest_ability_decide(int lookup_rc) {
    return (lookup_rc > 0) ? LATCH_INGEST_START_ALLOW
                           : LATCH_INGEST_START_REFUSE_ABILITY;
}

/* True only for the ALLOW decision.  Every other value -- including a
 * value this header does not define -- is a refusal. */
static inline bool latch_ingest_start_allowed(latch_ingest_start_decision_t decision) {
    return decision == LATCH_INGEST_START_ALLOW;
}

/*
 * IS THE SIGNED CPU ON THIS PLATFORM AT ALL?
 *
 * The pin used to answer "no" by MOVING the bridge: an out-of-range CPU
 * was silently replaced by CPU 1 -- or by CPU 0 on a single-CPU platform
 * -- and the pin reported SUCCESS.  That is a compiled-in default
 * substituted for SIGNED data, and the fallback is the CPU THE SAFETY
 * SUPERVISOR RUNS ON.
 *
 * The rule is therefore "the CPU must exist here", and it lives in this
 * header so that it is a host-tested property rather than a branch
 * nobody can reach off-target.  A platform with no CPUs at all is
 * refused too: there is nothing to pin to.
 */
static inline bool latch_ingest_cpu_in_range(unsigned int cpu, unsigned int num_cpu) {
    return (num_cpu > 0u) && (cpu < num_cpu);
}

/*
 * THE ERRNO A REFUSAL CARRIES.
 *
 * `EINVAL` for the CPU conflict (the caller asked for something the
 * signed contract does not say), `EACCES` for the pin (the platform
 * refused the placement) and `EPERM` for the ability (the bridge cannot
 * prove it is unprivileged).  An unrecognised decision is treated as the
 * ability refusal -- the most conservative of the three.
 *
 * The success value is spelled 0 rather than `EOK`, because `EOK` is a
 * QNX name and this header is also compiled by a POSIX host test -- and 0
 * IS what `EOK` is on QNX.
 */
#define LATCH_INGEST_START_OK 0

static inline int latch_ingest_start_errno(latch_ingest_start_decision_t decision) {
    switch (decision) {
    case LATCH_INGEST_START_ALLOW:
        return LATCH_INGEST_START_OK;
    case LATCH_INGEST_START_REFUSE_CPU:
        return EINVAL;
    case LATCH_INGEST_START_REFUSE_PIN:
        return EACCES;
    case LATCH_INGEST_START_REFUSE_ABILITY:
    default:
        return EPERM;
    }
}

#endif /* LATCH_INGEST_START_H_ */
