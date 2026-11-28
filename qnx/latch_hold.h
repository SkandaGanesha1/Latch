/*
 * qnx/latch_hold.h
 *
 * THE OPERATOR-HOLD COMMAND: ONE ORDER OF OPERATIONS
 * ===================================================
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * `DCMD_LATCH_FORCE_HOLD` is the operator's lever on the safety envelope:
 * `lock_hold = 1` forces the plant into HA-HOLD, `lock_hold = 0` releases
 * it.  Both the QNX resource manager and the host simulation implement it,
 * and -- before this file existed -- each one had its OWN copy of the
 * logic.  That is how the defect below came to exist in TWO places.
 *
 * THE DEFECT: A FAILED COMMAND THAT STILL RELEASED THE HOLD
 * ----------------------------------------------------------
 * The release path needs to know WHICH rung the operator was looking at,
 * so it takes a seqlock SNAPSHOT of the supervisor's own state.  The
 * snapshot can fail -- a torn read -- and when it does, the command
 * returns EBUSY.
 *
 * The old code stored `operator_hold_locked = 0` FIRST and only THEN took
 * the snapshot:
 *
 *     atomic_store_explicit(&g_simplex.operator_hold_locked, 0u, ...);
 *     if (cmd->lock_hold) { ... }
 *     else {
 *         if (!latch_fill_hold_status(&before)) {
 *             return EBUSY;          // <-- the hold is ALREADY released
 *         }
 *         ...
 *     }
 *
 * So an operator who was told "the command failed" had in fact LOST THE
 * HOLD.  That is a fail-open on the error path, and it is the worst kind:
 * the supervisor reported an error and changed the plant's behaviour at the
 * same time.
 *
 * WHY A SHARED HEADER AND NOT A REORDERED COPY
 * ---------------------------------------------
 * Because a reorder in two places is two chances to get it wrong, and one
 * of them is the copy nobody reads.  The ORDER is now INSIDE one function,
 * `latch_hold_command()`, which snapshots FIRST and mutates NOTHING if the
 * snapshot fails.  The order cannot be got wrong by a caller, because the
 * caller does not choose the order.
 *
 * The snapshot is injected as a CALLBACK so that the decision can be
 * driven by a HOST test: a test can hand it a snapshot function that fails
 * on purpose and assert that not one byte of the hold state moved.  That
 * is the behavioural proof of the fix; the QNX path cannot be exercised
 * off-target, because it is a resource manager.
 *
 * IT FAILS CLOSED
 * ---------------
 * A NULL state, a NULL snapshot, a NULL command or a missing member makes
 * the command REFUSE, and a refusal mutates nothing.  There is no path
 * through this function that reports success and leaves the state
 * half-changed.
 *
 * It is a header because the property has to be reachable from a host
 * test: `qnx/latch_hold_test.c` compiles this file and RUNS it.
 */

#ifndef LATCH_HOLD_H_
#define LATCH_HOLD_H_

#include "latch_protocol.h"

#include <stdbool.h>
#include <stdatomic.h>

/*
 * The state a FORCE_HOLD command mutates.
 *
 * The supervisor holds these as separate members of its own state struct,
 * so this header takes POINTERS to them: that keeps the decision in one
 * place, and it lets a host test drive the real function against its own
 * state instead of against a copy of the logic.
 */
typedef struct latch_hold_state {
    _Atomic uint32_t *hold_locked;
    _Atomic uint32_t *release_pending;
    _Atomic uint32_t *release_armed;
    _Atomic uint32_t *release_deferred_ticks;
    _Atomic uint32_t *release_rung;
} latch_hold_state_t;

/*
 * The snapshot the command needs before it may mutate anything.
 *
 * Returns true when the snapshot is CONSISTENT, false when it is torn.
 * A false return means the caller learns nothing and, crucially, that
 * NOTHING may be changed.
 */
typedef bool (*latch_hold_snapshot_fn)(void *ctx, latch_hold_status_t *out);

/*
 * APPLY AN OPERATOR-HOLD COMMAND.
 *
 * Returns true when the command was applied, false when it was REFUSED --
 * and a refusal mutates NOTHING.  `cmd->lock_hold` selects the direction;
 * `before->rung` is the rung the operator was looking at, and it is the
 * rung a release is recorded against (L-5: a release is only effective at
 * LATCH, and a rung that changes afterwards INVALIDATES the request rather
 * than silently applying it to a different state).
 */
static inline bool latch_hold_command(latch_hold_state_t *st,
                                      latch_hold_snapshot_fn snapshot,
                                      void *ctx,
                                      const latch_force_hold_cmd_t *cmd) {
    latch_hold_status_t before;

    /* FAIL CLOSED on anything the command cannot be applied to. */
    if (st == NULL || snapshot == NULL || cmd == NULL) {
        return false;
    }
    if (st->hold_locked == NULL || st->release_pending == NULL ||
        st->release_armed == NULL || st->release_deferred_ticks == NULL ||
        st->release_rung == NULL) {
        return false;
    }

    /*
     * THE SNAPSHOT COMES FIRST.  THIS IS THE WHOLE FIX.
     *
     * If the snapshot is torn, the supervisor's state is not trustworthy,
     * so the command is REFUSED -- and because nothing has been written
     * yet, the operator's hold is exactly what it was.  An operator who is
     * told "the command failed" can trust that nothing changed.
     *
     * The old code wrote the hold FIRST, so a failed snapshot returned
     * EBUSY with the hold already released.
     */
    if (!snapshot(ctx, &before)) {
        return false;
    }

    atomic_store_explicit(st->hold_locked,
                          cmd->lock_hold ? 1u : 0u,
                          memory_order_release);
    if (cmd->lock_hold) {
        /* ENGAGING the hold cancels any pending release authorisation. */
        atomic_store_explicit(st->release_pending, 0u, memory_order_release);
        atomic_store_explicit(st->release_armed, 0u, memory_order_release);
        atomic_store_explicit(st->release_deferred_ticks, 0u, memory_order_release);
    } else {
        /*
         * RELEASING the hold records the rung the operator was looking
         * at.  The release is DEFERRED: it is only armed by the ladder
         * while the rung IS LATCH, so a release issued at another rung is
         * retained rather than thrown away, and it is invalidated if the
         * rung changes before it can take effect.
         */
        atomic_store_explicit(st->release_rung, before.rung, memory_order_release);
        atomic_store_explicit(st->release_pending, 1u, memory_order_release);
        atomic_store_explicit(st->release_deferred_ticks, 0u, memory_order_release);
    }
    return true;
}

#endif /* LATCH_HOLD_H_ */
