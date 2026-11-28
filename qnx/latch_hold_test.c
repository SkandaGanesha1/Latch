/*
 * qnx/latch_hold_test.c
 *
 * THE HOST-SIM TEST FOR THE OPERATOR-HOLD COMMAND'S ORDER OF OPERATIONS
 * ======================================================================
 *
 * WHAT THIS TEST IS FOR
 * ---------------------
 * `DCMD_LATCH_FORCE_HOLD` releases the operator's hold on the plant.  It
 * needs a snapshot of the supervisor's own state (to record WHICH rung the
 * operator was looking at), and the snapshot can fail.
 *
 * The old code released the hold FIRST and took the snapshot SECOND, so a
 * failed snapshot returned EBUSY with the hold ALREADY RELEASED.  An
 * operator who was told "the command failed" had in fact lost the hold --
 * a fail-open on the error path, in which the supervisor reports an error
 * and changes the plant's behaviour at the same time.
 *
 * The order now lives inside `qnx/latch_hold.h`'s `latch_hold_command()`,
 * which snapshots FIRST and mutates NOTHING if the snapshot fails.  This
 * test compiles that SHIPPED header and RUNS it, and the decisive check is
 * the one the defect makes impossible:
 *
 *     a snapshot that FAILS must leave EVERY byte of the hold state alone
 *
 * It runs on the host, so it is part of `make check-governor` and it runs
 * in CI.
 */

#include "latch_hold.h"

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

/* The state under test.  It is the SAME shape as the supervisor's own
 * members; the header takes pointers to them, so the test drives the real
 * function against real atomics. */
static _Atomic uint32_t g_hold_locked;
static _Atomic uint32_t g_release_pending;
static _Atomic uint32_t g_release_armed;
static _Atomic uint32_t g_release_deferred_ticks;
static _Atomic uint32_t g_release_rung;

static latch_hold_state_t g_state;

static void reset_state(uint32_t hold_locked) {
    atomic_store_explicit(&g_hold_locked, hold_locked, memory_order_release);
    atomic_store_explicit(&g_release_pending, 0u, memory_order_release);
    atomic_store_explicit(&g_release_armed, 0u, memory_order_release);
    atomic_store_explicit(&g_release_deferred_ticks, 0u, memory_order_release);
    atomic_store_explicit(&g_release_rung, 0u, memory_order_release);
    g_state.hold_locked = &g_hold_locked;
    g_state.release_pending = &g_release_pending;
    g_state.release_armed = &g_release_armed;
    g_state.release_deferred_ticks = &g_release_deferred_ticks;
    g_state.release_rung = &g_release_rung;
}

static uint32_t load32(_Atomic uint32_t *p) {
    return atomic_load_explicit(p, memory_order_acquire);
}

/* A CONSISTENT snapshot, like the supervisor's own seqlock read. */
static bool snapshot_ok(void *ctx, latch_hold_status_t *out) {
    (void)ctx;
    memset(out, 0, sizeof(*out));
    out->struct_size = (uint32_t)sizeof(*out);
    out->hold_locked = load32(&g_hold_locked);
    out->rung = 4u;                 /* LATCH: the only rung a release acts on */
    return true;
}

/* A TORN snapshot: the supervisor's state cannot be trusted. */
static bool snapshot_torn(void *ctx, latch_hold_status_t *out) {
    (void)ctx;
    memset(out, 0, sizeof(*out));
    out->struct_size = (uint32_t)sizeof(*out);
    out->hold_locked = load32(&g_hold_locked);
    out->rung = 4u;
    return false;
}

/*
 * THE DECISIVE CHECK: A FAILED SNAPSHOT CHANGES NOTHING.
 *
 * The operator's hold is ENGAGED, the command asks for a RELEASE, and the
 * snapshot fails.  The command must REFUSE and every field must still hold
 * its old value -- above all the hold itself, which the old code released
 * before it found out that the snapshot had failed.
 */
static void test_a_failed_snapshot_changes_nothing(void) {
    latch_force_hold_cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.lock_hold = 0u;            /* RELEASE */
    cmd.reason_code = 42u;

    reset_state(1u);               /* the hold is ENGAGED */
    atomic_store_explicit(&g_release_pending, 1u, memory_order_release);
    atomic_store_explicit(&g_release_rung, 3u, memory_order_release);
    atomic_store_explicit(&g_release_deferred_ticks, 7u, memory_order_release);

    const bool applied = latch_hold_command(&g_state, snapshot_torn, NULL, &cmd);

    check(!applied,
          "a command whose snapshot FAILED is REFUSED");
    check(load32(&g_hold_locked) == 1u,
          "the operator's HOLD is still engaged after a failed snapshot -- "
          "the old code released it BEFORE it found out the snapshot was "
          "torn");
    check(load32(&g_release_pending) == 1u,
          "a failed snapshot leaves the release bookkeeping alone");
    check(load32(&g_release_rung) == 3u,
          "a failed snapshot does not overwrite the recorded rung");
    check(load32(&g_release_deferred_ticks) == 7u,
          "a failed snapshot does not reset the deferred-tick counter");
}

/* The same for the ENGAGING direction: a failed snapshot must not engage
 * the hold either, or a refused command would still have changed the
 * plant. */
static void test_a_failed_snapshot_does_not_engage_the_hold(void) {
    latch_force_hold_cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.lock_hold = 1u;            /* ENGAGE */
    cmd.reason_code = 43u;

    reset_state(0u);               /* the hold is NOT engaged */
    atomic_store_explicit(&g_release_pending, 1u, memory_order_release);

    const bool applied = latch_hold_command(&g_state, snapshot_torn, NULL, &cmd);

    check(!applied,
          "an engage command whose snapshot FAILED is REFUSED");
    check(load32(&g_hold_locked) == 0u,
          "a failed snapshot does not engage the hold either");
    check(load32(&g_release_pending) == 1u,
          "a failed snapshot does not cancel the release bookkeeping");
}

/*
 * THE RELEASE, WITH A GOOD SNAPSHOT.
 *
 * The hold is released, the release is RECORDED (deferred, not thrown
 * away), and the rung recorded is the one from the SNAPSHOT -- the rung the
 * operator was looking at when they asked.
 */
static void test_the_release_records_the_snapshot_rung(void) {
    latch_force_hold_cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.lock_hold = 0u;
    cmd.reason_code = 44u;

    reset_state(1u);
    atomic_store_explicit(&g_release_armed, 1u, memory_order_release);
    atomic_store_explicit(&g_release_deferred_ticks, 9u, memory_order_release);

    const bool applied = latch_hold_command(&g_state, snapshot_ok, NULL, &cmd);

    check(applied, "a release with a CONSISTENT snapshot is applied");
    check(load32(&g_hold_locked) == 0u, "the hold is released");
    check(load32(&g_release_pending) == 1u,
          "the release is RECORDED (deferred), not thrown away");
    check(load32(&g_release_rung) == 4u,
          "the release records the rung from the SNAPSHOT -- the rung the "
          "operator was looking at");
    check(load32(&g_release_deferred_ticks) == 0u,
          "the deferred-tick counter is reset for the new request");
}

/*
 * THE ENGAGE, WITH A GOOD SNAPSHOT.
 *
 * Engaging the hold cancels any pending release authorisation: a stale
 * authorisation must never be left in the state to fire later.
 */
static void test_the_engage_cancels_a_pending_release(void) {
    latch_force_hold_cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.lock_hold = 1u;
    cmd.reason_code = 45u;

    reset_state(0u);
    atomic_store_explicit(&g_release_pending, 1u, memory_order_release);
    atomic_store_explicit(&g_release_armed, 1u, memory_order_release);
    atomic_store_explicit(&g_release_deferred_ticks, 9u, memory_order_release);

    const bool applied = latch_hold_command(&g_state, snapshot_ok, NULL, &cmd);

    check(applied, "an engage with a CONSISTENT snapshot is applied");
    check(load32(&g_hold_locked) == 1u, "the hold is engaged");
    check(load32(&g_release_pending) == 0u,
          "engaging the hold CANCELS a pending release authorisation");
    check(load32(&g_release_armed) == 0u,
          "engaging the hold disarms an armed release");
    check(load32(&g_release_deferred_ticks) == 0u,
          "engaging the hold resets the deferred-tick counter");
}

/*
 * IT FAILS CLOSED ON A COMMAND IT CANNOT APPLY.
 *
 * A NULL state, a NULL snapshot, a NULL command or a missing member makes
 * the command REFUSE -- and a refusal mutates nothing.  There is no path
 * through this function that reports success and leaves the state
 * half-changed.
 */
static void test_it_fails_closed(void) {
    latch_force_hold_cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.lock_hold = 0u;

    reset_state(1u);

    check(!latch_hold_command(NULL, snapshot_ok, NULL, &cmd),
          "a NULL state is REFUSED");
    check(!latch_hold_command(&g_state, NULL, NULL, &cmd),
          "a NULL snapshot function is REFUSED");
    check(!latch_hold_command(&g_state, snapshot_ok, NULL, NULL),
          "a NULL command is REFUSED");

    latch_hold_state_t partial = g_state;
    partial.release_rung = NULL;
    check(!latch_hold_command(&partial, snapshot_ok, NULL, &cmd),
          "a state with a missing member is REFUSED");

    check(load32(&g_hold_locked) == 1u,
          "every refused command left the hold exactly as it was");
}

int main(void) {
    printf("[LATCH_HOLD] a refused operator-hold command must change "
           "NOTHING\n");

    test_a_failed_snapshot_changes_nothing();
    test_a_failed_snapshot_does_not_engage_the_hold();
    test_the_release_records_the_snapshot_rung();
    test_the_engage_cancels_a_pending_release();
    test_it_fails_closed();

    if (g_failures == 0) {
        printf("[LATCH_HOLD] PASS: %d checks, 0 failures -- the snapshot is "
               "taken BEFORE anything is written, and a refused command "
               "changes nothing\n", g_checks);
        return 0;
    }
    printf("[LATCH_HOLD] FAIL: %d checks, %d failure(s)\n",
           g_checks, g_failures);
    return 1;
}
