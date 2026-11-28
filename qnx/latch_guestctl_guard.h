/*
 * qnx/latch_guestctl_guard.h
 *
 * THE GUEST-CONTROL GATE: TWO INDEPENDENT CHECKS, ONE DECISION
 * =============================================================
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * `/dev/latch/guestctl` is the one channel that can STOP and START the guest
 * VM.  Before this file existed, that channel had NO access control of its
 * own at all:
 *
 *   - the node was `S_IFCHR | 0666` (world read/write),
 *   - `latchctl` opened it `O_RDONLY`,
 *   - and the `STOP` / `START` devctls checked NOTHING.
 *
 * The security policy limited *which types may connect* to the channel
 * (`guest_ctl_t`), but "may connect" was silently read as "may mutate":
 * every type that could open the node could also kill and respawn the guest
 * VM that the whole safety envelope is built around.
 *
 * WHY TWO CHECKS AND NOT ONE
 * --------------------------
 * Because ONE of them is not enough, and the truth table below says exactly
 * why.  The two checks are INDEPENDENT -- neither one implies the other --
 * and there are FOUR (open-flag, ability) combinations, of which exactly
 * ONE allows the mutation:
 *
 *   | open carries _IO_FLAG_WR | client holds latch/guestctl | result      |
 *   |-------------------------|------------------------------|-------------|
 *   | no                      | no                           | REFUSED     |
 *   | no                      | yes                          | REFUSED     |
 *   | yes                     | no                           | REFUSED     |
 *   | yes                     | yes                          | ALLOWED     |
 *
 * A gate that checks only the write flag is satisfied by any process that
 * can open the node for writing; a gate that checks only the ability is
 * satisfied by a client that opened the node READ-ONLY and then tried to
 * mutate through it.  `qnx/latch_guestctl_guard_test.c` asserts all four
 * rows and asserts that EXACTLY ONE row allows -- so the "one gate is not
 * enough" claim is a measurement, not an assertion.
 *
 * WHAT THE TWO CHECKS ACTUALLY SEPARATE
 * -------------------------------------
 * The two checks answer two DIFFERENT questions, and it is worth being
 * precise about which is which, because the earlier draft of this work got
 * it wrong:
 *
 *   1. THE WRITE FLAG separates MUTATE from OBSERVE.  A read-only open can
 *      read the guest's status and can do nothing else.  This is the check
 *      that makes "status" and "stop" different operations at the kernel
 *      level, rather than different words in a command parser.
 *
 *   2. THE ABILITY separates a NAMED, REVOCABLE GRANT from an IMPLICIT
 *      CONNECT.  The channel-connect rule says who may *talk to* the
 *      daemon; the `latch/guestctl` ability says who may *change* the
 *      guest's state.  They are separate rules in separate files, so a
 *      type can be added to the connect list without silently acquiring
 *      the power to stop the guest, and the grant can be revoked at
 *      runtime without editing the policy.
 *
 * It is tempting to read the second check as "the operator shell must not
 * be able to stop the guest".  That is NOT what it says, and the plan's
 * first draft said so -- which was wrong, because `latchctl guest-restart`
 * IS the operator's deliberate recovery path (U-1) and
 * `tools/qemu_guest_kill.py` PHASE 9 depends on it.  The operator shell
 * therefore KEEPS `latch/guestctl`; what the gate removes is the
 * "connect implies mutate" implication.
 *
 * IT FAILS CLOSED
 * ---------------
 * A decision is only ALLOW when BOTH checks passed.  There is no default,
 * no fallback and no "assume the ability is there" path: a client whose
 * ability cannot be established is REFUSED, exactly like a client that
 * demonstrably lacks it.
 *
 * It is a header because the property has to be reachable from a host
 * test: `qnx/latch_guestctl_guard_test.c` compiles this file and RUNS it.
 * The QNX path cannot be exercised off-target, because it is a resource
 * manager.
 */

#ifndef LATCH_GUESTCTL_GUARD_H_
#define LATCH_GUESTCTL_GUARD_H_

#include <errno.h>
#include <stdbool.h>

/*
 * THE NAME OF THE DEDICATED ABILITY.
 *
 * The daemon creates it with `procmgr_ability_create(name, 0)` -- flags 0
 * means NEITHER root nor non-root receives it by default, so the only way
 * to hold it is to be granted it by name in the security policy.  The name
 * lives here, in the SHIPPED header, so the daemon, the client-side
 * documentation and `tools/consistency_check.py` all read the same string
 * instead of three copies of it.
 */
#define LATCH_GUESTCTL_ABILITY_NAME "latch/guestctl"

/* The three outcomes of the gate.  ALLOW is the only one that is not a
 * refusal, and it is deliberately the ZERO value: a decision variable that
 * was never set is not an ALLOW. */
typedef enum {
    LATCH_GUESTCTL_ALLOW = 0,
    LATCH_GUESTCTL_DENY_NO_WRITE_FLAG = 1,
    LATCH_GUESTCTL_DENY_NO_ABILITY = 2,
} latch_guestctl_decision_t;

/*
 * THE DECISION.
 *
 * `has_write_flag` is "the open that carries this devctl was opened for
 * writing" (the QNX side computes it from `_IO_FLAG_WR` on the OCB's
 * ioflag).  `has_ability` is "the client holds the `latch/guestctl`
 * ability" (the QNX side computes it from `iofunc_client_info_able()`).
 *
 * Both are booleans rather than QNX types so that the DECISION is
 * host-testable; the platform-specific part -- asking the kernel -- stays
 * in the resource manager, where it belongs.
 */
static inline latch_guestctl_decision_t latch_guestctl_decide(bool has_write_flag,
                                                              bool has_ability) {
    if (!has_write_flag) {
        return LATCH_GUESTCTL_DENY_NO_WRITE_FLAG;
    }
    if (!has_ability) {
        return LATCH_GUESTCTL_DENY_NO_ABILITY;
    }
    return LATCH_GUESTCTL_ALLOW;
}

/* True only for the ALLOW decision.  Every other value -- including a
 * value this header does not define -- is a refusal. */
static inline bool latch_guestctl_allowed(latch_guestctl_decision_t decision) {
    return decision == LATCH_GUESTCTL_ALLOW;
}

/*
 * THE ERRNO A REFUSAL CARRIES.
 *
 * Both refusals are EPERM: the client is not permitted to perform the
 * operation.  The two decision values are kept distinct anyway, because
 * the diagnostic that says WHICH check failed is worth more to the next
 * person than the errno is -- and a gate that collapses them at the source
 * cannot tell them apart later.
 *
 * The success value is spelled 0 rather than `EOK`, because `EOK` is a QNX
 * name and this header is also compiled by a POSIX host test.  0 IS what
 * `EOK` is on QNX.
 */
#define LATCH_GUESTCTL_OK 0

static inline int latch_guestctl_errno(latch_guestctl_decision_t decision) {
    return latch_guestctl_allowed(decision) ? LATCH_GUESTCTL_OK : EPERM;
}

#endif /* LATCH_GUESTCTL_GUARD_H_ */
