/*
 * guest/latch_soak_pace.h
 *
 * THE DEADLINE PACER'S DECISION, AS A PURE FUNCTION  (U-4)
 * =====================================================
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * The U-4 decision-latency soak paces its 900 Hz proposal stream against a
 * DEADLINE on the guest's own monotonic clock.  The pacer's decision --
 * "when is the next frame due?" -- is the part that can go wrong, and it
 * went wrong on the target on 2026-11-27, so it is written here as a PURE
 * function that the host can test without a guest, a hypervisor or a
 * licence.
 *
 * THE DEFECT THIS FILE EXISTS TO PREVENT
 * --------------------------------------
 * The pacer this replaces advanced its deadline by one period and then, if
 * the guest had been starved past that deadline, sent the next frame
 * IMMEDIATELY and left the deadline BEHIND `now`.  That is a rate limiter
 * that ACCUMULATES CREDIT: every missed period became a frame owed, and the
 * producer paid the whole debt back in one burst.
 *
 * Measured on the QEMU AArch64 `virt` target (2026-11-27): a ~0.5 s host
 * stall left the producer roughly 450 frames behind, and the catch-up burst
 * put 255 frames into the supervisor's 256-frame proposal ring and DROPPED
 * 186 of them.  The stall was the HOST's -- the supervisor's own WCET
 * overrun counter jumped by 99 in the same window, against a background of
 * about 6 -- but the burst was the PRODUCER's own, and it turned a
 * scheduling hiccup into a broken workload.  The measurement is about the
 * supervisor's decision latency under a healthy frame stream, so a
 * producer that breaks the stream is a defect in the workload, not
 * something to measure around.
 *
 * THE RULE
 * --------
 * A rate limiter must do TWO things at once, and the original pacer did
 * only the first:
 *
 *   1. KEEP THE RATE.  The producer's long-run rate is the target rate,
 *      and ordinary scheduling jitter must not eat it.
 *   2. BOUND THE CATCH-UP.  The producer must never owe more than a small
 *      allowance's worth of frames, so a host stall cannot become a burst.
 *
 * The first fix for this file broke the rate in order to get the bound:
 * it dropped the credit on ANY lateness, and the guest's own jitter puts
 * it late about half the time, so every late frame cost a full period.
 * Measured on the same target with the same guest, the rate fell from
 * **901/s to 610/s** -- the workload was no longer the one the plan
 * describes.
 *
 * So the rule, in one sentence:
 *
 *     the producer is never more than the LAG ALLOWANCE behind its own
 *     schedule, and it catches up by keeping its grid.
 *
 * That sentence is the whole contract, and it is checkable:
 *
 *     now - latch_soak_next_deadline(deadline, now, period)
 *         <= LATCH_SOAK_MAX_LAG_PERIODS * period
 *
 * for every input.  The host-side test (qnx/latch_soak_pace_test.c)
 * asserts exactly that, and also asserts the two behavioural consequences
 * -- that the rate survives the jitter, and that a long stall produces a
 * handful of catch-up frames rather than hundreds.
 *
 * WHY A SEPARATE HEADER
 * ---------------------
 * The guest policy is FREESTANDING: it cannot include the QNX tree, so a
 * function that has to be tested on the host has to live somewhere the
 * guest can reach too.  This is the same arrangement the guest-side LFBK
 * decoder uses (guest/latch_fb_decode.h): one copy, included by the guest
 * AND by a host-side test, so the two cannot drift.
 *
 * This header is included ONLY by the LATCH_GOVERNOR_LATENCY_SOAK profile.
 * The legacy, plain GOVERNOR, W4 and W5 guest binaries do not see it, so
 * their SHA-256 witnesses are untouched by this file.
 */

#ifndef LATCH_SOAK_PACE_H_
#define LATCH_SOAK_PACE_H_

#include <stdint.h>

/*
 * THE LAG ALLOWANCE, in periods.
 *
 * The producer may fall this many periods behind its own schedule before
 * the missed deadlines are dropped.  Four is not a magic number: the
 * guest's MEASURED normal lateness on this target is ~1.02 periods (its
 * sleep's WAKE overshoots by more than a whole period under TCG), so four
 * is three times the ordinary jitter and it still bounds the catch-up
 * after a host stall at a handful of frames against a 256-frame ring.
 */
#ifndef LATCH_SOAK_MAX_LAG_PERIODS
#define LATCH_SOAK_MAX_LAG_PERIODS 4
#endif

/*
 * The next deadline, given the current deadline, the present time and the
 * period.  Three cases, and the MIDDLE one is the whole design.
 *
 *   * ON SCHEDULE (now < deadline + period): the deadline advances by
 *     EXACTLY one period.  The achieved rate is the intended rate.
 *
 *   * A LITTLE LATE (the frame is due, but the producer is no more than
 *     LATCH_SOAK_MAX_LAG_PERIODS periods behind): ordinary scheduling
 *     jitter.  The deadline is KEPT -- the grid does not move -- and the
 *     frame that is due goes out immediately.  This is what preserves the
 *     target rate.
 *
 *   * A LONG WAY LATE (more than LATCH_SOAK_MAX_LAG_PERIODS periods
 *     behind): the guest was STARVED -- a host stall.  The missed
 *     deadlines are DROPPED and the deadline resumes from NOW.  The
 *     producer must not pay the whole debt back in one burst.
 *
 * THE INVARIANT, for every input:
 *
 *     now - result <= LATCH_SOAK_MAX_LAG_PERIODS * period_ns
 *
 * i.e. the producer is never more than the ALLOWANCE behind its own
 * schedule, so it can never owe more than the allowance's worth of
 * frames.  That is the BURST BOUND: after a host stall of any length, the
 * catch-up is a handful of frames, not hundreds.
 *
 * WHY THE MIDDLE CASE EXISTS
 * ---------------------------
 * Three pacers were measured on the QEMU AArch64 `virt` target (2026-11-27)
 * against the SAME guest, and each one is wrong in one direction:
 *
 *   * "keep the grid, catch up without limit" -- the original.  It
 *     sustained the target rate (901/s) but a ~0.5 s host stall made it
 *     emit its whole debt at once: 255 frames into the supervisor's
 *     256-frame proposal ring, 186 DROPPED.
 *
 *   * "drop the credit on ANY lateness" -- the first fix.  The burst is
 *     gone (2 frames), but the RATE collapses: the guest's own scheduling
 *     jitter puts it late about half the time, every late frame costs a
 *     full period, and the measured rate fell from 901/s to 610/s.  The
 *     measurement's workload then was not the one the plan describes, and
 *     the archive's "900 Hz" would have contradicted its own numbers.
 *
 *   * THIS ONE.  The grid is kept for ordinary jitter, and the debt is
 *     dropped only when the producer is far behind.
 *
 * A simulation of the guest's measured dynamics (a ~550 us per-frame
 * cost and a ~1.7 ms wake overshoot) gives, for the same guest:
 *
 *     pacer                          rate     catch-up after a 0.5 s stall
 *     keep the grid, no bound       900/s              894 frames
 *     drop the credit always        595/s                1 frame
 *     allowance = 1 period          595/s                1 frame
 *     allowance = 4 periods         900/s                4 frames   <== THIS
 */
static inline uint64_t latch_soak_next_deadline(uint64_t deadline, uint64_t now,
                                                uint64_t period_ns) {
    const uint64_t next = deadline + period_ns;

    if (now < next) {
        return next;           /* on schedule: advance by exactly one period */
    }

    if ((now - next) > ((uint64_t)LATCH_SOAK_MAX_LAG_PERIODS * period_ns)) {
        return now;           /* too far behind: DROP the missed deadlines */
    }

    return next;               /* a little late: keep the grid, one frame now */
}

/*
 * How long the producer must wait, in microseconds, before the next frame.
 * Zero means "send it now" -- which is what a producer that has just been
 * starved must do, exactly ONCE, before the normal rate resumes.
 */
static inline uint64_t latch_soak_sleep_us(uint64_t deadline, uint64_t now) {
    if (deadline <= now) {
        return 0u;
    }
    return (deadline - now + 999ULL) / 1000ULL;
}

#endif /* LATCH_SOAK_PACE_H_ */
